# Week 37 verification — code intelligence: symbols, call graph, entrypoints (plan §20.2)

Honest record of what was built, run, and measured — for Week 37: `core/codeintel/`, a
multi-language symbol table, call graph, and framework entrypoint detector, built as foundation
for Week 38's taint analysis. See `docs/adr/0020-code-intelligence-call-graph.md` for the design
decisions and their reasoning.

## What was built

Four pieces, one package:

- **`models.py`**: `Symbol`, `CallEdge`, `Entrypoint`, and `CodeGraph` (with `callers_of()`/
  `calls_from()` one-hop queries).
- **Per-language extractors** — `python_lang.py` (stdlib `ast`), `js_lang.py`/`ts` (tree-sitter),
  `go_lang.py` (tree-sitter) — each turning one file into raw symbols, `(caller, callee_name,
  line)` call sites, and any entrypoints its own decorators/exports/route registrations reveal.
- **`resolve.py`**: intra-file-first, then repo-wide-if-unique name resolution into a `CodeGraph`,
  leaving ambiguous or absent matches unresolved rather than guessing.
- **`__init__.py`**: `analyze(root)`/`analyze_or_none(root)`, the same never-raises directory-walk
  contract `core/reachability` already established.

Entrypoint detection covers six framework conventions: FastAPI and Flask decorators, Django
`urlpatterns`, Express route registration, Next.js App Router and Pages Router (by file location,
not decorator shape — Next.js has no decorator to inspect), and Go's `net/http.HandleFunc`/
`Handle`.

## Python uses `ast`, not `tree-sitter-python`

Deliberate, matching the precedent `core/reachability/imports.py` already set: Python ships a
real, maintained parser in the standard library, so tree-sitter would add a dependency for no
benefit. JavaScript/TypeScript and Go have no such built-in, so they use tree-sitter
(`tree-sitter-go` added this week; JS/TS grammars were already a dependency).

## Real-world validation, not just synthetic snippets

Hand-written test snippets alone would have missed two real gaps. Both were found by running the
freshly-built analyzer against NodeGoat (a real, intentionally-vulnerable Node.js application,
already cloned in `~/.cache/bulwark-benchmarks/` from Week 36's own benchmark), not by inspection:

1. **Express routes registered with an object-method reference**
   (`app.get('/login', sessionHandler.displayLoginPage)` — a `member_expression`, not a bare
   `identifier` or inline function) were silently skipped entirely. This is NodeGoat's actual
   routing style throughout, so only 2 of its ~19 real routes were detected before the fix.
2. **The pre-ES6 "constructor function" idiom** (`this.method = (req, res) => {...}` inside
   `function Foo(db) {...}`) had no matching case in the extractor's dispatch at all, so these
   handler methods — NodeGoat's entire route-handler layer — were never registered as `Symbol`s,
   making every call to them permanently unresolvable regardless of the resolver's own logic.

Fixing gap 1 took entrypoint detection from 2 to 19 routes (matching NodeGoat's real route
surface: `/`, `/login`, `/signup`, `/logout`, `/dashboard`, `/profile`, `/contributions`,
`/benefits`, `/allocations/:userId`, `/memos`, `/learn`, `/research`). Fixing gap 2 took the
resolved-edge rate from 15/417 (3.6%) to 54/417 (12.9%) — verified end to end, not just by count:
`/login` GET's entrypoint symbol now resolves its one call all the way to
`SessionHandler.displayLoginPage`'s own body.

Chasing gap 2 down also surfaced a **third, pre-existing bug**, unrelated to this week's new code:
`value.type in ("arrow_function", "function")` (used in three places — the inline Express handler
case, the `const x = () => {}` case, and the new constructor-function case) never matched a plain
`function () {}` expression, because tree-sitter's JS grammar names that node type
`function_expression`, not `function`. Every one of those checks silently missed the non-arrow,
`function`-keyword form of an inline or assigned function — a real, common pattern, not a
hypothetical. Fixed in all three places; two new regression tests
(`test_const_function_expression_becomes_a_named_symbol`,
`test_express_route_with_inline_function_keyword_handler_gets_its_own_symbol`) cover it going
forward. NodeGoat's own edge/resolution numbers were unaffected by this particular fix (it doesn't
happen to use the `function`-keyword form where it matters for resolution), which is itself a
useful data point: the fix is real and necessary for other codebases, even though this one
benchmark didn't exercise it.

The remaining ~87% of NodeGoat's call edges stay unresolved for reasons the design accepts as
honest limits, not bugs: calls into framework/library code with no local definition
(`res.render(...)`, `db.get().collection(...)`), and genuine dynamic patterns this graph's
name-based resolution was never meant to solve (documented in ADR-0020). Nothing here claims a
higher resolution rate than what was actually measured.

## Call resolution: intra-procedural first, unsound where documented

A call resolves to a same-file symbol first if there's exactly one; otherwise to a repo-wide
unique name match; otherwise it stays unresolved (`callee_id=None`) rather than guessing — the
same "unknown stays unknown" discipline `core/reachability/index.py`'s three-valued `Reachability`
already established. This is explicitly unsound for dynamic dispatch, reflection, and genuine name
collisions with no local definition to disambiguate; `resolve.py`'s own module docstring and
ADR-0020 both say so.

## Persistence: deferred, on purpose

The plan's literal wording asks for the graph to be stored in Postgres as an edges table. This
week's `CodeGraph` is in-memory only. Building and RLS-hardening a schema with zero validating
reader in the same session was judged premature risk; Week 38's taint engine will be the first
real consumer, and its access pattern should inform the schema rather than being guessed at now.
Recorded in ADR-0020 as an intentional sequencing decision, not a silent omission.

## Verified

- 954 backend tests passing (up from 949 before this week: 44 new tests for
  `core/codeintel/` — 10 Python, 16 JS/TS, 7 Go, 7 resolution, 9 end-to-end analysis — plus 2
  skipped, unrelated), 94.6% coverage; ruff/black/mypy (strict) all clean.
- Every framework's entrypoint detection was smoke-tested directly against hand-written snippets
  for its specific shape (FastAPI/Flask decorators, Django `urlpatterns`, Express `.get`/`.post`/
  member-expression handlers, Next.js App/Pages routing, Go `net/http`) before being formalized
  into tests.
- The whole pipeline was run against a real, previously-cloned application (NodeGoat: 40 files,
  120 symbols, 19 entrypoints, 417 call sites) — not just synthetic fixtures — and its measured
  entrypoint count and resolved-edge rate are reported above exactly as observed, including the
  real gaps that remain.
- **Not done**: Postgres persistence of the graph (deferred to Week 38, see above); resolving calls
  through dynamic dispatch, reflection, or genuine cross-file name collisions (documented as
  permanent, not a Week 38 TODO); a fourth language beyond Python/JS/TS/Go (not in this week's
  scope).
