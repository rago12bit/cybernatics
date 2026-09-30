# ADR-0028: Triage assistant and Hypotheses lane

Status: Implemented (2026-09-30), Week 43 (plan §21.3/§21.4), building on Week 41's model gateway
(ADR-0026) and Week 42's verified-fix agent (ADR-0027) rather than inventing new LLM plumbing.

## Context

Week 43 is two related but distinct plan sections bundled into one week: §21.3 (a model reads one
finding's taint path and code and returns a `likely_real`/`likely_false_positive`/`unsure` verdict
that feeds the ranker) and §21.4 (an off-by-default lane where a model reasons over structured
route/authorization facts to hypothesize about flaws SAST can't express, promotable to a real Issue
only by a person). Both ship this week; the Hypotheses lane's scope is deliberately narrower than
the plan's own three-example list, for reasons below.

## Decisions

### Two separate LLM contracts, never one shared with `core.llm.contract`

`core/triage_assistant/contract.py` and `core/hypotheses/contract.py` are each their own small,
hand-rolled JSON validator, structurally identical in shape to `core.llm.contract.parse_response`
(reject unknown fields, control characters, oversized replies) but NOT importing or reusing it. The
reason is not code organization: `core.llm.contract`'s `_DISMISS` regex exists specifically to
REJECT a fix suggestion that claims a finding is a false positive, because a remediation reply must
never suppress a finding. The triage assistant's entire purpose is to say exactly that when it
believes it. Sharing one validator between "must never dismiss" and "must be able to dismiss" would
mean one of the two call sites has to punch a hole in the other's guarantee. Three separate
contracts, three separate call sites, is what lets all three promises hold at once without any of
them trusting the others not to regress.

### The triage verdict is advisory, stored per-Issue, and only ever dampens/nudges a score

`IssueRow.assistant_verdict*` (migration 0013) is a new, separate set of columns, never
`triage_status` (migration 0009's human decision) and never a new value inside it. Nothing in this
codebase lets a model write `triage_status`; the only writer of that column remains
`repo.triage_issue`, called only from the human-facing `/triage` endpoint.

`core.risk.score.score_finding` takes an optional `verdict: TriageVerdict | None` and applies a
bounded multiplier -- 0.6-0.9 for `likely_false_positive`, 1.0-1.15 for `likely_real`, depending on
the model's own stated confidence, `unsure` a deliberate no-op -- before the KEV floor is applied,
so a KEV-listed CVE's guaranteed minimum score is never affected by a verdict. This satisfies the
plan's "never suppresses an issue on its own" literally: even a high-confidence false-positive
verdict can only ever produce `score * 0.6`, never zero, and the finding is never hidden or removed.

**A verdict cannot retroactively change a score already computed and persisted.** It is generated
on demand (mirroring how "Generate AI suggestion" and the verified-fix agent both work: a model call
happens on request, not automatically for every finding on every scan, which would multiply model
cost by the finding count on every single scan). It takes effect starting with the asset's *next*
scan: `core.pipeline._run_scan_job` looks up every stored verdict for the asset by fingerprint
(`repo.assistant_verdicts_for_asset`) before calling `finalize()`, and passes it through as a
`verdict_lookup` callback -- the same shape `core.postprocess.finalize`'s existing `assess`
(reachability) callback already uses. Validated live, end to end, not just at the unit level:
`tests/unit/test_pipeline.py::test_a_stored_triage_verdict_dampens_the_next_scan_of_the_same_asset`
runs two real scans of the same repo path through the real pipeline and proves the second scan's
risk score is lower than the first's, with the verdict named in `risk_factors`.

The CLI path (`core.scan.scan`, used with no database) always passes `verdict_lookup=None`: there is
no asset, no history, and nothing to look a verdict up against there.

### The Hypotheses lane's v1 scope: one hypothesis type, not three

The plan names three flaw types for this lane: a route missing the authorization check its siblings
have, IDOR (an object id from the request used without an ownership check), and mass assignment.
Only the first ships this week. IDOR and mass assignment both need reasoning about object identity
and field binding across a request/response boundary that a deterministic, testable candidate
generator cannot produce responsibly in the time this week has -- building a heuristic detector for
either badly (high false-positive rate, no real evidence) would cost more trust in the lane than
shipping one well-specified type does. This is the plan's own **Cut Order v2** item #4 ("Hypotheses
lane, part of Week 43") exercised as a scope narrowing rather than a wholesale cut: the lane exists,
is real, and is fully wired end to end, just for one flaw type. Deferred, not abandoned.

### Candidate generation is 100% deterministic; the model's only job is to judge it

`core.hypotheses.facts.missing_auth_candidates` needs no model call: group a repository's HTTP
entrypoints (`core.codeintel`) by the file they're defined in, and flag any route with no
auth-looking marker in a file where a sibling route has one. This is exactly the plan's own framing,
"the model reasons over facts rather than guessing from raw text" -- the facts are computed first,
by ordinary code, and are independently unit-tested with no model involved
(`tests/unit/test_hypotheses_facts.py`). The model's job is purely downstream: given one candidate's
facts and its own code, decide whether it's worth a person's time (`surface: bool`) and, if so,
write the evidence and a suggested manual check. A model that always said "surface: true" would
still be bounded by a real, inspectable candidate list; a model that never ran at all (`client is
None`) short-circuits to zero hypotheses rather than fabricating one.

The keyword heuristic (`AUTH_KEYWORDS`) that decides whether a marker "looks like" authorization is
exactly that: a heuristic, disclosed as such in `facts.py`'s own docstring, prone to both false
positives (a decorator that merely mentions "auth" in its name) and false negatives (an
unconventionally-named in-house check). Narrowing that judgement is explicitly left to the model
step, not fixed by growing the keyword list indefinitely.

### `core.codeintel.Entrypoint.auth_markers`: a new field, populated for Python and Express only

Extending code intelligence (Week 38) to capture "which decorators/middleware apply to this route"
needed a new `Entrypoint.auth_markers: tuple[str, ...]` field. Populated for:
- **Python** (`python_lang.py`): every decorator on a route function OTHER than the one recognized
  as the route registration itself (`@app.get(...)`/`@app.route(...)`) -- `@login_required` or
  `@auth.requires_role("admin")` both contribute a name, matched by shape, not resolved to a real
  definition.
- **Express/JS** (`js_lang.py`): every argument between the path and the final handler in a route
  registration call -- `router.get(path, requireAuth, checkAdmin, handler)` -- including a called
  middleware factory (`passport.authenticate('jwt')` contributes `"authenticate"`).

**Not populated for Go or Django this week**, a disclosed gap: Go's ecosystem has no single
dominant middleware convention the way Express does, and Django's decorator-based views (as opposed
to `urlpatterns`) weren't in scope for the route-registration work Week 38 already did. A Go or
Django route simply never becomes a Hypotheses candidate today, which is a false-negative gap
(missed candidates), not a false-positive risk.

### Promotion is a direct, narrow insert -- never `core.issues.sync`

`repo.promote_hypothesis` builds one real `IssueRow` (`source="llm-confirmed"`, a new column,
migration 0014) and one `FindingRow` occurrence attached to the asset's *latest* scan, as if that
scan had reported it. It deliberately does NOT call `core.issues.sync` (the function every real scan
uses to reconcile a full scan's findings against history): handed just one synthetic finding, that
function would read every other currently-open Issue as "absent from this scan, therefore fixed" and
silently mark the whole asset's issue history wrong. `tests/unit/test_hypotheses_repo.py::
test_promote_does_not_touch_other_open_issues` proves this against a real second, unrelated Issue.

The promoted Issue is scored with the same `core.risk.score_finding` every scanner-sourced finding
uses (`Feeds()`, empty -- there's no CVE or scanner-agreement signal here), with the model's own
stated confidence (`high`/`medium`/`low`) mapped to a fixed `0.8`/`0.6`/`0.4` scoring-confidence
value: a documented, honest floor, not a precisely-calibrated number nothing here has evidence for.

`HypothesisRow.snippet` stores the exact code shown to the model at generation time specifically so
promotion never needs to re-clone the repository a second time.

### Generation re-clones the repository; it is on demand, gated by the gateway, not a new toggle

`POST /assets/{id}/hypotheses/generate` re-checks out the asset's latest scan's git source
(`core.gitfetch.clone_repo`, the same SSRF-guarded clone the verified-fix agent already uses) into a
throwaway directory, runs `core.codeintel.analyze` fresh, and cleans up unconditionally. "Off by
default" is enforced the same way triage and fix already are: `Task.HYPOTHESES` has no route unless
an operator configures one (`core.llm.gateway`), so `app_state.llm_hypotheses` is `None` and the
endpoint returns `409` -- no separate per-org feature-flag table was built for this, since the
gateway's own task routing already is that toggle, and a second one would just be two ways to
express the same on/off state.

Model-call budget is checked once per `generate` call (`UsageLimiter.acquire()`), not once per
candidate inside it: candidates are processed as one batch triggered by one user action, not N
independent requests, and `MAX_CANDIDATES_PER_RUN` (30) bounds the worst case regardless.

## Consequences

- A hosted deployment is unaffected by default, same as Week 41/42: nothing here calls a model
  unless `Task.TRIAGE`/`Task.HYPOTHESES` are explicitly routed to a backend.
- The Hypotheses lane's real coverage is narrower than the plan's own three-example list (IDOR and
  mass assignment are not detected); revisiting this needs a genuinely new candidate-generation
  approach for each, not just a bigger keyword list.
- Go and Django routes never produce a Hypotheses candidate this week (no `auth_markers` extraction
  for either yet) -- a false-negative gap, not a false-positive risk.
- A triage verdict changes ranking starting with an asset's *next* scan, never retroactively; the
  issue detail screen shows the verdict immediately (advisory text), but the numeric risk score
  shown for the CURRENT scan is unaffected until a new one runs.
- No live hosted-model run for either feature in this environment (no API key here); both are
  unit-tested against fake clients covering the real control-flow paths (a valid reply, a malformed
  reply repaired once, a give-up), the same posture Week 41/42 already documented for their own LLM
  call sites. Both promptfoo suites (`core/llm/prompts/triage/`, `core/llm/prompts/hypotheses/`)
  are real, runnable, schema-conformance gates, following the exact pattern
  `core/llm/prompts/fix/` established.
