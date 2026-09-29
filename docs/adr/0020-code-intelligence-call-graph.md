# ADR-0020: Code intelligence — symbols, call graph, entrypoint detection

Status: Implemented (2026-09-29, Week 37), in-memory only — Postgres persistence deferred to
Week 38 (its first real consumer). See `docs/v2-week37-verification.md`.

## Context

The plan's §20.2/§20.3 (taint analysis, Week 38) needs to answer "is this sink reachable from an
HTTP entrypoint, and by what path?" That needs three things that don't exist yet: a way to find
functions in source code, a way to know which functions call which, and a way to find the
functions a web framework actually exposes as routes. This week builds all three, general enough
for the taint engine to walk next week, without yet building the taint engine itself.

## Decision

`core/codeintel/`, structured in four pieces:

- **`models.py`**: `Symbol` (one function/method definition), `CallEdge` (one call site, resolved
  to a `Symbol` or not), `Entrypoint` (a route: framework, method, path, the `Symbol` it enters),
  `CodeGraph` (the whole analysis, plus `callers_of`/`calls_from` for the one-hop queries a
  reachability walk needs).
- **One extractor per language** (`python_lang.py`, `js_lang.py`, `go_lang.py`): parses one file
  into raw `Symbol`s and `(caller_id, callee_name, line)` call sites, plus any entrypoints that
  file's own decorators/exports/registrations reveal.
- **`resolve.py`**: turns every file's raw calls into a `CodeGraph`'s resolved edges, intra-file
  first, then by name across the whole repository.
- **`__init__.py`**: `analyze(root)`/`analyze_or_none(root)`, walking the tree once and dispatching
  by extension — the same never-raises contract `core/reachability` already established.

### Python uses `ast`, not `tree-sitter-python`

The plan's own wording says "parse Python... with tree-sitter." This deviates from that, on
purpose: `core/reachability/imports.py` already made the same choice for the same reason — Python
ships a real, maintained parser (`ast`) in the standard library, so there's nothing tree-sitter
would add here except a dependency. JavaScript/TypeScript and Go have no such built-in, so they use
tree-sitter (`tree-sitter-javascript`, `tree-sitter-typescript` — already a dependency;
`tree-sitter-go`, added this week).

### Entrypoint detection is shape-based, not import-based

`@app.get("/path")` is recognized as FastAPI by the *shape* of the decorator (an HTTP-verb method
call with a string first argument), not by confirming `app` really came from `fastapi import
FastAPI`. The same is true of Flask's `@app.route`, Express's `app.get(...)`, and Go's
`http.HandleFunc`. Resolving the real import chain reliably (through aliasing, re-exports,
dependency-injected app objects) is a much larger analysis than decorator/call inspection, and
would still be wrong for a hand-rolled function that merely happens to be named `get`. This is a
documented, deliberate approximation: a false positive is a function that looks like a route but
isn't; a false negative is a route registered through enough indirection that its shape doesn't
match (a factory function building the decorator, for instance).

Next.js is the exception — it uses **file location**, not code shape (`app/**/route.ts` exporting
`GET`/`POST`/etc., or `pages/api/**/*.ts`'s default export), because that is what Next.js's own
routing is actually keyed on; there is no decorator to inspect. The path derived from the file's
location is a close but not exact match to Next.js's own resolution (route groups like `(marketing)`
are not stripped, and `[...slug]` catch-alls are left as literal path segments) — documented in
`js_lang.py`'s own docstring, not silently wrong.

### Call resolution is intra-procedural first, then name-based — and is unsound where the plan says it will be

A call site's name is matched against symbols defined in the *same file* first (so a file that
defines its own `process` resolves to it, even if another, unrelated `process` exists elsewhere).
Failing that, it's matched against every symbol with that name across the whole repository *only*
if there is exactly one — an ambiguous or absent match stays unresolved (`callee_id=None`), the
same "unknown stays unknown, never guessed" principle `core/reachability/index.py` uses for package
reachability. This cannot and does not handle:

- **Dynamic dispatch** (`getattr(obj, name)()`, calling a value stored in a dict/list).
- **Reflection** (`importlib.import_module(computed_name)`).
- **Genuine name collisions** with no local definition to disambiguate — the exact case the plan
  asks to be honest about, not silently resolved to an arbitrary candidate.

An inline callback (an anonymous arrow function passed to `.map()`, `setTimeout`, etc. — everywhere
except the one place an anonymous function needs its own identity, an inline route handler) has its
calls folded into the enclosing named function rather than becoming its own graph node: for the
reachability question this graph exists to answer, a call made from inside a closure is exactly as
reachable as the function that created it, so nothing is lost by not giving every closure literal
its own place in the graph.

### Persistence: deferred, on purpose

The plan says "store the graph in Postgres as an edges table." This week's `CodeGraph` is in-memory
only, not yet written to a database. A Postgres schema (`code_symbols`, `call_graph_edges`,
`entrypoints`, asset-scoped like `issues`, with the same Row-Level Security pattern) is a bounded,
well-understood addition on its own, but it has no real reader yet — Week 38's taint engine is the
first thing that will actually query this data, and its access pattern (does it read whole-graph
per asset? walk edges lazily? cache in memory per scan?) should inform the schema rather than being
guessed at now. Building and RLS-hardening a table nothing reads yet, in the same week as the graph
construction itself, traded a genuine but premature piece of the plan's literal wording for real
risk to a security-sensitive migration with no validating consumer in this session. Deferred
explicitly, not silently dropped.

## Consequences

- Reachability today (`core/reachability`, SCA-only: "is this package imported") is unaffected;
  this is new, separate infrastructure for a different, broader question ("is this code called from
  an entrypoint") that Week 38 will connect to scoring.
- The taint engine's function summaries (plan §20.3) can be built directly on `CodeGraph.symbols`/
  `edges`/`entrypoints` without re-parsing anything.
- Every unresolved edge, every unparsed file, and every entrypoint whose shape didn't match is
  something Week 38 (and any future consumer) must treat as "don't know," not "not reachable" — the
  same discipline `core/reachability/index.py`'s three-valued `Reachability` already established.
