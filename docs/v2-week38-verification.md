# Week 38 verification — taint analysis (plan §20.3)

Honest record of what was built, run, and measured — for Week 38: `core/taint/`, an
intra-procedural data-flow analyzer with function summaries propagated over `core.codeintel`'s call
graph (Week 37), producing concrete source-to-sink paths from real HTTP entrypoints. The plan calls
this "the most demanding piece of programming in the project"; see
`docs/adr/0021-taint-analysis.md` for the design decisions and their reasoning.

## What was built

Source/sink/sanitizer catalogs (YAML, one per language, matching the plan's own examples: request
parameters as sources; `cursor.execute`, `subprocess.run`, `eval`, unescaped template rendering as
sinks; parameterized-query helpers and escaping functions as sanitizers); a per-language
intra-procedural flow analyzer (Python via `ast`, JavaScript/TypeScript and Go via tree-sitter) that
tracks which local variables become tainted, records sink hits, and computes function summaries; and
a call-graph worklist (`engine.py`) that composes those summaries into complete, real source-to-sink
paths with a full hop-by-hop chain.

## Real-world validation, not just synthetic snippets — three independent true positives

Hand-written test snippets validated the algorithm's individual mechanics (branch merging, sanitizer
suppression, cross-function summary composition — all covered by unit tests, 56 passing across the
four language/engine test files). But the actual measure of whether this analysis finds real
vulnerabilities came from running it against real, previously-known-vulnerable applications, not
code written to make the analyzer look good:

| Application | Real vulnerability | Found? | Sink location |
|---|---|---|---|
| Vulnerable-Flask-App | SQL injection in `/search` (`db.engine.execute(str_query)` built from `request.json`) | Yes | `app/app.py:265` |
| NodeGoat | `eval()` injection in `POST /contributions` (the app's own comment: *"Insecure use of eval() to parse inputs"*) | Yes | `app/routes/contributions.js:32-34` |
| nodejs-goof (Snyk) | Command injection in `exports.create` (`exec('identify ' + url, ...)` from `req.body.content` via a regex match) | Yes | `routes/index.js:174` |

All three were confirmed by reading the actual source before trusting the tool's own output, not the
other way around. NodeGoat's case in particular exercises the full pipeline at once: its entire
route layer is written as `this.handlerName = (req, res) => {...}` inside a constructor function
(the exact pattern Week 37 needed a dedicated fix for), registered via
`app.get('/login', sessionHandler.displayLoginPage)` — a named-handler redirect with no body of its
own, requiring `engine._redirect_target` to follow the call edge to the real handler before any
analysis could even begin. Without that piece, NodeGoat would have produced zero findings regardless
of how correct the flow analysis itself was.

## Cross-checked against Semgrep's own taint mode, as the plan requires

The plan's own validation instruction: "cross-check against Semgrep's taint mode on the same code;
every disagreement becomes a labelled test case." Semgrep 1.178.0 (pip-installed, not this project's
own pinned Docker adapter) was run against the same two files with its public registry rulesets
(`p/python`, `p/flask`, `p/javascript`, `p/nodejsscan`):

- **NodeGoat's `eval()` case: exact agreement.** `ajinabraham.njsscan.eval.eval_node.eval_nodejs`
  flagged the identical three lines (32, 33, 34) this analysis found independently.
- **Vulnerable-Flask-App's SQLi case: same vulnerability, different anchor line — explained, not
  papered over.** Semgrep's own taint-mode rule,
  `python.flask.security.injection.tainted-sql-string.tainted-sql-string`, flagged line 261 — the
  string-construction site (`str_query = "..." % search_term`) — while this analysis reports line
  265, the sink call itself (`db.engine.execute(str_query)`). Both tools are tracing the *same*
  tainted flow (`content['search'] → search_term → str_query → execute`); they differ only in which
  step of that flow they choose to anchor the report to. This analysis anchors at the sink
  deliberately: that is where the dangerous operation actually executes and where a fix
  (parameterizing the query) needs to happen, which is also the location this project's own
  `SinkHit`/`TaintFinding` model was designed around from the start (ADR-0021).
- **Semgrep's `p/security-audit` pack also flagged two `render_template_string` SSTI sites (lines
  103/114, 271/281) this analysis did not find.** Read directly rather than assumed away: the one
  inside `@app.errorhandler(404)` is not reachable through this analysis because
  `core.codeintel`'s own entrypoint detector doesn't recognize `errorhandler` as a route decorator
  (a documented Week 37 gap, ADR-0020) — no entrypoint, no seed, no path to find. The one inside
  `/search`'s `except Exception as e:` block builds its template from `str(e)`, an exception message
  — this analysis does not model "an exception raised while handling tainted data carries that
  taint," a real, honest gap in scope, not a bug.

This is exactly the outcome the plan's validation step is meant to produce: real agreement on real
vulnerabilities, and every disagreement traced to a specific, named, already-documented design
decision rather than shrugged off.

## Real bugs found and fixed during this week's own testing

Consistent with the project's "measured, not assumed" standard, validating against real code (not
just synthetic fixtures) surfaced genuine bugs in the analysis itself, beyond what unit tests alone
caught:

- **Branch-merge order-dependence.** An early version visited an `if`/`else`'s two arms sequentially
  into one shared tainted-name map; a clean reassignment in the second arm silently erased taint the
  first arm had introduced, because the two arms were not independent by construction. Fixed by
  snapshotting the pre-branch state and visiting each arm from that same snapshot, merging the
  results by unioning tags afterward — caught by a direct test before this ever reached real-code
  validation.
- **A receiver's own taint was dropped.** `request.args.get('id')` was computed as untainted at
  first, because only the call's *arguments* (`'id'`, a literal) were checked — not the receiver
  chain (`request.args`) the method was called on. This is the single most common shape in real
  Flask/Express code and was caught immediately by the very first hand-written smoke test, before
  any formal test suite existed for it.
- **TypeScript's parameter grammar silently dropped every handler's source.** tree-sitter-typescript
  wraps every function parameter in a `required_parameter` node — even with no type annotation at
  all — while plain tree-sitter-javascript never does. `param_names` only recognized a bare
  `identifier`, so it returned an empty list for *every* TypeScript arrow-function handler, meaning
  the `param_source_positions` seed (position 0, the `req`-like parameter) was never applied to any
  `.ts` file's entrypoint. This was invisible to every JavaScript-only synthetic test and was only
  caught by deliberately exercising the TypeScript path end-to-end — a `.ts` version of the exact
  same Express handler already covered for `.js` produced zero findings where one was expected. Fixed
  alongside a related gap found in the same pass: TypeScript's `as`/`satisfies` casts and the `!`
  non-null assertion had no case in `expr_taint` and silently stripped taint through any type cast, a
  very common pattern in real TypeScript handler code (`req.query.q as string`). Both are now
  regression-tested (`test_taint_js_flow.py`, plus an end-to-end `.ts` case in
  `test_taint_analyze.py`), and neither NodeGoat nor Vulnerable-Flask-App contains any `.ts` files, so
  this gap would not have been caught by this week's own real-world corpus without the deliberate
  TypeScript smoke test.

## Verified

- 1010 backend tests passing (up from 954 after Week 37: 56 new tests for `core/taint/` — 19 Python
  flow, 15 JavaScript/TypeScript flow, 10 Go flow, 12 end-to-end analysis across all three
  languages), 2 skipped (unrelated), 94.2% coverage; ruff/black/mypy (strict) all clean.
- Mutual recursion (two functions calling each other) is confirmed, by a direct test, not to hang
  summary computation — bounded by `MAX_WORKLIST_PASSES = 50` in `engine.py`.
- The same physical sink reached from one entrypoint through two different internal call paths is
  confirmed to produce exactly one finding, not two (de-duplicated by sink location).
- A named-handler route redirect with no resolvable target (an undefined reference) is confirmed to
  produce no finding and not raise, rather than crash the whole analysis.
- Full-repository timing on real applications: NodeGoat (40 files) in 0.07s, nodejs-goof (10 files)
  in 0.04s — the worklist and flow analysis add negligible time on top of Week 37's own call-graph
  construction at this scale.
- **Not done**: Postgres persistence of findings, or any Issue/scoring/UI integration (plan §28.3's
  step-by-step rendering) — deferred on purpose, recorded in ADR-0021, the same reasoning ADR-0020
  gave for deferring the code graph's own persistence to this week. FastAPI's typed-parameter source
  style, object-field-level taint (as opposed to bare-name taint), path-sensitive branch analysis,
  and loop-fixed-point iteration are documented permanent limits of this design, not TODOs for a
  future week (ADR-0021).
