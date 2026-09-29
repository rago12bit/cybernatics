# ADR-0021: Taint analysis — sources, sinks, function summaries, concrete paths

Status: Implemented (2026-09-29, Week 38), in-memory only, not yet wired to Issues/scoring. See
`docs/v2-week38-verification.md`.

## Context

`core.codeintel` (Week 37, ADR-0020) can find functions, resolve calls between them, and detect
HTTP entrypoints — but it says nothing about what a function actually *does* with the data it
receives. The plan's own framing calls this next piece "the most demanding piece of programming in
the project": precise intra-procedural data flow, plus function summaries propagated over the call
graph with a worklist until a fixed point, so a source-to-sink path can be reported step by step
without re-analysing a function once for every caller.

## Decision

`core/taint/`, five pieces:

- **`models.py`**: `SinkHit` (one place a tainted value reached a sink, plus the hop chain that led
  there), `FunctionSummary` (what a function does with its own parameters, computed once,
  independent of any caller), `TaintFinding` (a complete source-to-sink path from a real entrypoint).
- **`catalog.py`** + `catalogs/{python,javascript,go}.yaml`: sources, sinks, and sanitizers, matched
  by name the same way `core.codeintel`'s own call graph already extracts a callee name — not a
  giant table of attribute-access patterns (see "Sources are literally parameters" below).
- **One flow analyzer per language** (`python_flow.py` via `ast`, `js_flow.py`/`go_flow.py` via
  tree-sitter): the actual intra-procedural algorithm, detailed below.
- **`engine.py`**: the call-graph worklist — `compute_summaries` (pass 1) and `find_taint_paths`
  (pass 2).
- **`__init__.py`**: `analyze(root)`/`analyze_or_none(root)`, the same never-raises contract
  `core.codeintel` and `core.reachability` both already established. Every file that contributed a
  `Symbol` is re-parsed here, independently of `core.codeintel`'s own pass, to recover the actual
  function bodies — the same "each analysis parses its own files" precedent ADR-0020 already set,
  now extended one layer further.

### A tainted value's provenance is a *set* of tags, not a boolean

One mechanism has to answer two different questions: "if this function's parameter 2 is ever
tainted, does it reach a sink?" (a hypothetical, caller-independent question — a `FunctionSummary`)
and "starting from this real entrypoint, does a sink actually fire?" (a `TaintFinding`). Both
questions are answered by the exact same per-function analyzer; only the *seed* differs — parameter
indices (`{0}`, `{1}`, ...) for the first, the literal tag `SOURCE` for the second. A `SinkHit`
found while seeded with parameter tags becomes part of that function's summary; the same code path,
re-run later seeded with `SOURCE` from a real entrypoint, produces a real `TaintFinding`.

### Sources are literally "request parameters," per the plan's own wording

Not a table of attribute-access patterns (`request.args.get`, `req.body.x`, ...). Concretely: a
catalog names either a `global_sources` entry (a bare name that is always tainted wherever it's
referenced — Flask's imported `request` object, which also covers a Django view's `request`
*parameter* for free, since `ast`/tree-sitter can't tell a parameter from a global reference; both
are just a name) or a `param_source_positions` entry (the *position* of an entrypoint handler's
request-like parameter — Express's `(req, res) => {}`, Go's `func(w, r) {}` — position, not name,
since a handler is free to call it anything). FastAPI's typed-parameter style (a request body
arriving as a Pydantic model parameter, not an attribute access) needs the parameter's *type
annotation*, not its name or position, to know it carries external input — a documented gap this
catalog format doesn't express, not a silent guess.

### The algorithm: may-taint, not must-taint — over-approximate on purpose

A call's result taint is the union of its argument taints (plus, for a method call, the taint of its
own receiver — `request.args.get('id')` must come out tainted because `request.args` is, even
though `'id'` the literal argument plainly is not). A branch (`if`/`try`) is walked once per arm
from the *same* starting state, and the resulting states are merged by unioning each name's tags —
not visited sequentially into one shared map, which would let one arm's clean reassignment wrongly
erase taint another arm introduced (a real bug caught and fixed during this week's own testing, see
verification doc). A loop body is visited once, not iterated to a fixed point. An unresolved call
(no summary, not in any catalog) is assumed to pass taint through its arguments rather than drop it.

Every one of these choices trades recall for precision in the *safe* direction for a security tool:
a reviewable false positive costs far less than a silently missed real vulnerability. This is not
free, and the plan's own validation instruction — cross-check against Semgrep's taint mode — is what
this week actually measured that trade-off against, not just asserted it (see verification doc).

### Function summaries compose across the call graph via a bounded worklist

`compute_summaries` seeds every function with its own parameters (hypothetically tainted, one tag
per parameter) plus any real `global_sources`, analyses it once, and re-queues its *callers*
(`CodeGraph.callers_of`) whenever its summary changes — a caller can only need re-analysis because a
callee it calls changed, so re-queuing exactly those callers is what keeps this from being
O(passes × graph size). Capped at `MAX_WORKLIST_PASSES = 50` so a call cycle (direct or mutual
recursion, tested explicitly) cannot loop forever; summaries only grow via union operations, so this
is monotonic and converges well inside that cap for any repository this was tested against.

Each `SinkHit` re-exposed from a callee's summary into a caller carries a `hops` tuple, one
`TaintHop` prepended per level — so by the time a `TaintFinding` is built from an entrypoint's own
analysis, the chain already reads in call order (the entrypoint's own hop, then each intermediate
call, in the order they were actually made), fulfilling the plan's "each hop... rendered step by
step" without needing a second reconstruction pass.

### Named-handler route registrations are followed to their real body

`app.get('/login', sessionHandler.displayLoginPage)` (Express) and a Django `urlpatterns` entry both
make `core.codeintel` mint a synthetic symbol that is nothing but a redirect — a route registration
call with no body of its own. `engine._redirect_target` follows that symbol's one outgoing call edge
to the function that actually has a body to seed. Without this, none of NodeGoat's own routing
(entirely written this way) would produce a single finding — confirmed directly, see verification
doc.

### Persistence, and Issue/scoring integration: deferred, on purpose

This week's `TaintFinding`s are in-memory only, returned from `analyze()`, not written to Postgres
or attached to an `Issue`. Building that integration (which findings become which Issue fields, how
a taint path renders in the UI per plan §28.3, whether Postgres persistence happens now or is
deferred again) is real, separable work that benefits from being scoped on its own rather than
appended to an already-large week — the same reasoning ADR-0020 gave for deferring `CodeGraph`
persistence to this week.

## Consequences

- Every finding's hop chain, source, and sink location is real and traceable to actual source
  positions — never fabricated or estimated — but the *rate* of resolved findings depends entirely on
  `core.codeintel`'s own call-resolution soundness (ADR-0020): a call this project's own resolver
  can't attribute to a symbol, taint can't follow either.
- The catalogs are intentionally small and named after the plan's own examples (`cursor.execute`,
  `subprocess.run`, `eval`, parameterized queries, escaping functions) rather than an exhaustive
  sink/sanitizer library; extending them is additive, low-risk work for a future week, not a
  redesign.
- Anything this analysis cannot express — dynamic dispatch, reflection, FastAPI's typed-parameter
  sourcing, object-field-level taint (as opposed to bare-name taint), path-sensitive branches, loop
  fixed points — is a documented "doesn't know," the same discipline `core.reachability` and
  `core.codeintel` both already established, not a silent wrong answer.
