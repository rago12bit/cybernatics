# Taint engine corpus expansion (closing part of docs/evaluation-v2.md's own gap)

Honest record of real, additional measurement work, done after v2.0.0 shipped (during v3's own
timeline) to shrink -- not erase -- one of the gaps `docs/evaluation-v2.md` already disclosed: the
taint engine's own spot-check was N=3 confirmed cases on one repository (NodeGoat). This expands it
to the project's own 25-repository corpus's Python- and JavaScript-taint-catalog-relevant subset,
and along the way found and fixed two real bugs in `core/taint/` itself -- not assumed correct from
re-running the same two repositories again.

## Method

Of the corpus's 12 "deliberately vulnerable" repositories, 8 are Python or JavaScript (the two
languages with a taint catalog mature enough for `global_sources` to mean something; Go's own
catalog exists but the corpus has no deliberately-vulnerable Go project): NodeGoat and nodejs-goof
(already measured, Week 52), plus six not measured before -- VAmPI, Vulnerable-Flask-App, pygoat,
dvpwa, vulpy (Python), and dvna (JavaScript). Ran the real scan pipeline
(`bulwark scan --tools bandit,semgrep`, no mocks) against each, already-cached at its pinned commit
from `benchmarks/corpus/corpus.json`, and hand-verified every `reachable: true` confirmation against
the real source -- the same method Week 52 used, just over more repositories.

## Two real bugs found and fixed

**1. A resolved call to a same-named but unrelated function could silently erase real taint,
across all three language analyzers.** `pygoat`'s `mitre_lab_25_api` view does exactly the pattern
the plan's own example describes -- `expression = request.POST.get('expression'); eval(expression)`
-- a direct, intra-procedural, textbook case. It was not confirmed. Traced the cause to
`core.codeintel.resolve.resolve_one`: it matches a call by the plain name written at the call site
(`.get(...)`) against every symbol in the project with that name, and when exactly one candidate
exists anywhere in the codebase, resolves to it confidently -- here, a completely unrelated
`challenge/views.py`-based Django class-based view's own `get(self, request)` handler, the project's
only symbol named `get`. `core/taint/engine.py`'s per-language `_call_taint` then trusted that
resolved function's own (irrelevant) return-taint summary *instead of* the conservative "assume
taint passes through" fallback every unresolved call already gets -- silently replacing real taint
with none.

This is not the documented "two functions share a name, the call site could mean either, so it's
left unresolved" trade-off `core/codeintel/resolve.py`'s own docstring already names (that path is
safe: unresolved falls back to the taint-preserving default). It is the opposite, more dangerous
case: resolution is *confident* (exactly one candidate) but *wrong* (the true callee -- a stdlib or
framework method like `dict.get`/`QueryDict.get` -- was never a candidate at all, because
`core.codeintel` has no notion of it). Fixed in all three flow analyzers
([`core/taint/python_flow.py`](https://github.com/Rag2102/cyberimp/blob/main/core/taint/python_flow.py),
[`core/taint/js_flow.py`](https://github.com/Rag2102/cyberimp/blob/main/core/taint/js_flow.py),
[`core/taint/go_flow.py`](https://github.com/Rag2102/cyberimp/blob/main/core/taint/go_flow.py)) by unioning the resolved-summary result with
the same conservative fallback (`result | arg_taint | receiver_taint`) rather than trusting the
summary alone -- a resolved call can now only ever add taint beyond the fallback, never remove it,
consistent with ADR-0021's own stated "over-approximate on purpose, a reviewable false positive
costs far less than a silently missed real one" design.

**2. The Python catalog's command-injection sinks had `os.popen` but not `subprocess.Popen`.**
`pygoat`'s `cmd_lab` (`subprocess.Popen(command, shell=True, ...)`, `command` built from
`request.POST.get('domain')`) and `mitre_lab_17_api` → `command_out` (the same shape, one call deeper)
were both missed for this reason alone -- the catalog's `popen` entry matches `os.popen` by name,
and `Popen` (capital P, `subprocess.Popen`, the far more common real-world shape) is a different
identifier. Added `Popen` as its own sink entry in
[`core/taint/catalogs/python.yaml`](https://github.com/Rag2102/cyberimp/blob/main/core/taint/catalogs/python.yaml), category
`command_injection`, next to the existing `popen`.

Both fixes verified: full unit suite (1803 passed, 1 skipped) green after each, `ruff`/`black`/`mypy`
clean. `pygoat`'s own confirmed count went from 1 (a correct but unrelated `ImageMath.eval` catch --
see below) to 5, all 5 hand-verified genuine.

## Results across all 8 repositories

| Repository | Findings | Confirmed reachable | Hand-verified |
|---|---:|---:|---|
| NodeGoat (Week 52, unchanged by the fix) | 154 | 3 | 3/3 true positives (unchanged) |
| nodejs-goof (Week 52, unchanged by the fix) | 8 | 0 | consistent -- no sink-shaped finding in this sample |
| pygoat | 267 | 4 (+1 more below catalog's own criteria) | 5/5 true positives |
| Vulnerable-Flask-App | 52 | 1 | 1/1 true positive |
| dvna | 15 | 1 | 1/1 true positive |
| VAmPI | 7 | 0 | 0 -- real gap, see below |
| dvpwa | 162 | 0 | 0 -- real gap, see below |
| vulpy | 114 | 0 | 0 -- real gap, see below |

**Combined: 9 confirmed reachable findings across 5 of 8 repositories, 9/9 hand-verified genuine true
positives, 0 false confirmations** -- up from Week 52's N=3 on one repository. Each one read against
the real source before counting it:

- `pygoat`: `cmd_lab` (`subprocess.Popen`, `request.POST.get('domain')`), `cmd_lab2`
  (`eval(val)`, `request.POST.get('val')`), `mitre_lab_25_api` (`eval(expression)`,
  `request.POST.get('expression')`), `mitre_lab_17_api` → `command_out` (`subprocess.Popen`, two
  hops from `request.POST.get('ip')` through a helper function -- a genuine interprocedural catch).
  A 5th, `views.py:588`'s `ImageMath.eval(function_str, ...)` where `function_str =
  request.POST.get("function")`, is also a real confirmed reachable sink (PIL's `ImageMath.eval`
  calls Python's own `eval` on the expression string internally) but had no SAST finding at that
  exact line in this bandit+semgrep run to attach the signal to, so it doesn't appear as a
  `reachable: true` *Finding* -- correct behavior per `core/taint/reachability.py`'s own documented
  "a Finding whose location has no matching sink gets no signal" contract, not a miss.
- `Vulnerable-Flask-App`: `content['search']` (from `request.json`) formatted into a raw SQL string,
  `db.engine.execute(str_query)`.
- `dvna`: `req.body.login` concatenated into a raw SQL string, `db.sequelize.query(query, ...)`.

## Three real, non-bug scope limits, freshly confirmed with concrete examples

Not new design flaws -- each is a documented, accepted trade-off (ADR-0021's "anything this analysis
cannot express... is a documented doesn't-know," `core/codeintel`'s own entrypoint-detector scope) --
but this corpus pass is the first time each one has a real, named instance behind it instead of being
stated in the abstract.

- **VAmPI's SQL injection is real and reachable, and this analysis cannot see it**: `GET
  /users/v1/{username}` is routed by Connexion from an OpenAPI spec
  (`openapi_specs/openapi3.yml`), not a Flask `@app.route` decorator or Django `urlpatterns` entry --
  `username` arrives as a plain function parameter with no `request` reference anywhere in its own
  file, flows unchanged into `f"SELECT * FROM users WHERE username = '{username}'"` →
  `db.session.execute(text(...))`. Neither `core.codeintel`'s Flask/Django entrypoint detectors nor
  the taint catalog's `global_sources: [request]` has any way to know an OpenAPI-routed path
  parameter is tainted input -- a third source-detection gap alongside the already-documented
  "Flask bare name" and "FastAPI typed parameter" cases.
- **vulpy's `bad/libuser.py:login`'s SQL injection is real, reachable, and ambiguously named**:
  `do_login` (correctly detected as a Flask Blueprint entrypoint) calls `libuser.login(username,
  password)`, where the real sink (`c.execute(... .format(username, password))`) lives inside
  `login`'s own body. vulpy deliberately ships parallel `bad/` and `good/` implementations with
  identical function names, so `resolve_one`'s own by-name index has two candidates for `login` and
  correctly declines to resolve it (the safe, intended behavior bug #1 above does not touch) -- but
  the side effect is that the real sink, one call away, is never re-exposed, since re-exposure
  requires a resolved `callee_id` to look up a summary by. A real, if deliberately-constructed,
  instance of the "two functions share a name" limitation ADR-0021 already names.
- **dvpwa's whole Python backend is invisible to entrypoint detection**: it's an `aiohttp` app
  (`app.router.add_route('POST', '/students/', views.students)`), and `core.codeintel`'s Python
  entrypoint detector only recognizes Flask and Django -- 0 real entrypoints found for the entire
  backend. (A separate, harmless quirk surfaced alongside this: the *JavaScript* entrypoint
  detector's loose `.method(...)`-shaped matching picked up 6 "GET select" false entrypoints from a
  vendored, minified `materialize.min.js` file's own internal `.select()` calls -- cosmetic, since
  nothing in the catalog matches a sink there either, so it produced no wrong security signal, but
  worth naming rather than quietly ignoring.)

## What this does NOT prove (read before relying on it)

- **Still not a corpus-scale precision/recall study.** 9 confirmed cases across 8 repositories,
  hand-verified one at a time, is a larger and more honest spot-check than Week 52's 3-on-1, not the
  plan's own "labelled Python and JavaScript corpus."
- **Still no comparison against Semgrep's own taint mode** for any of these 8 repositories --
  unchanged from Week 52's own disclosure.
- **The three scope limits above are real gaps, not edge cases invented for this write-up** -- a
  production OpenAPI-routed service, an aiohttp service, or a codebase with same-named
  staging/production module pairs would see the same under-detection today. None are fixed by this
  pass; fixing them (OpenAPI/path-parameter sourcing, an aiohttp entrypoint detector, type-aware call
  resolution) is real, separable feature work, not a bug fix.
- **The two bugs fixed here are real precision improvements, not completeness ones** -- they make
  already-reachable sinks within the *existing* catalogs and frameworks easier to find; they do not
  extend taint analysis to a new language, framework, or sink category.
- **No Go-language deliberately-vulnerable repository exists in the corpus**, so the Go catalog
  (`core/taint/catalogs/go.yaml`) has no real-world spot-check at all, before or after this work.
