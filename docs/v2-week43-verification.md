# Week 43 verification -- triage assistant and Hypotheses lane (plan §21.3/§21.4)

Honest record of what was built, run, and measured. See `docs/adr/0028-triage-assistant-and-
hypotheses-lane.md` for the design decisions, including the Hypotheses lane's deliberate scope
narrowing (one flaw type, not three).

## What was built

- `core/triage_assistant/`: `contract.py` (a separate JSON contract from remediation's, on
  purpose -- see the ADR), `prompt.py` (nonce-fenced, shows the taint path + code), `service.py`
  (the propose-a-verdict call, one repair attempt, `None` on any failure -- never a guess).
- `core/hypotheses/`: `facts.py` (100% deterministic candidate generation, no model), `contract.py`,
  `prompt.py` (shows structured facts + one route's code), `service.py` (`assess_candidate` +
  `generate_for_checkout`, the whole per-asset pass).
- `core/codeintel/models.py`/`python_lang.py`/`js_lang.py`: `Entrypoint.auth_markers`, populated for
  Python decorators and Express middleware.
- `core/risk/score.py`: an optional `verdict` parameter to `score_finding`/`apply_risk`, a bounded
  multiplier (0.6-1.15 depending on verdict and confidence), applied before the KEV floor.
- `core/pipeline.py`: looks up stored verdicts by fingerprint before `finalize()`, so a verdict
  informs every later scan of the same asset.
- `core/persistence/models.py` + migrations `0013`/`0014`: `IssueRow.assistant_verdict*` columns,
  `IssueRow.source` column, the new `hypotheses` table (RLS via `assets`, same shape `issues`
  itself already has).
- `core/persistence/repo.py`: verdict storage/lookup, and the Hypotheses lane's
  create/list/get/dismiss/promote functions -- promotion is a direct insert, never
  `core.issues.sync` (see the ADR for why).
- `api/main.py`: `POST/GET .../triage-assistant`, `POST .../hypotheses/generate`,
  `GET .../hypotheses`, `POST .../hypotheses/{id}/promote`, `POST .../hypotheses/{id}/dismiss`.
- `web/components/TriageAssistantPanel.tsx` + `HypothesesLane.tsx` (+ a new
  `/app/projects/[id]/hypotheses` route, linked from the project overview's crumb line).
- Two new promptfoo suites, `core/llm/prompts/triage/` and `core/llm/prompts/hypotheses/`, following
  the exact pattern `core/llm/prompts/fix/` (Week 41) established.

## Validated against real, live things -- not mocks

- **The full risk-scoring wiring, end to end, across two real scans.** `tests/unit/test_pipeline.py
  ::test_a_stored_triage_verdict_dampens_the_next_scan_of_the_same_asset` runs a real scan through
  `core.pipeline.run_scan_job`, stores a verdict against the resulting Issue, runs a SECOND real scan
  of the same asset, and asserts the second scan's persisted risk score is lower than the first's,
  with the verdict named in `risk_factors` -- and that the human `triage_status` was never touched.
  Not a unit test of `score_finding` in isolation: the real pipeline, the real fingerprint-based
  lookup, twice.
- **Promotion's isolation from the rest of an asset's issue history.**
  `test_hypotheses_repo.py::test_promote_does_not_touch_other_open_issues` creates a real, unrelated
  open Issue via the real scan-sync path, promotes a hypothesis, and confirms the unrelated Issue's
  `state` is untouched -- proving `promote_hypothesis`'s deliberate choice not to call
  `core.issues.sync` actually matters, not just that it's a plausible-sounding design note.
- **Code-intelligence extraction, against real parsers.** `auth_markers` extraction is tested
  through the real `ast` (Python) and real tree-sitter (JS) extractors, and
  `test_hypotheses_service.py::test_generate_for_checkout_end_to_end_against_a_real_directory` runs
  the whole candidate-generation pass against a real on-disk Python file with a real
  `core.codeintel.analyze()` call -- not a hand-built `CodeGraph` fixture.
- **Both migrations, up/down/up, against a real Postgres container**
  (`bulwark/postgres:16-pgvector`, disposable, not the project's own long-running dev stack), plus a
  live RLS proof: inserted a `hypotheses` row under `org-a`, confirmed `SET app.current_org='org-b'`
  sees zero rows and `org-a` sees one, as `bulwark_app` (not a superuser).
- **The frontend, against a real running API.** Not just `npm test`/`tsc --noEmit`/`next build`
  (all three ran clean): started `scripts/e2e_server.py` (a real FastAPI app + real SQLite database,
  no mocks) and a real `next dev` server pointed at it, seeded one real Issue through
  `core.persistence.repo` directly, and manually drove a real browser through: signing in, opening
  the Issue detail page (the Triage assistant panel renders, its "Get a triage verdict" button calls
  the real endpoint and shows the real `409` message when no model is configured), the project
  overview's new "hypotheses" link, and the Hypotheses lane page (its "Generate" button calls the
  real endpoint and shows the real `409` message the same way). Every message shown was the actual
  API's own text, not a hand-written approximation of what it might say.
- **promptfoo suites for both new prompts**, built and validated to run offline against a local
  Ollama backend the same way `core/llm/prompts/fix/`'s suite was, with real fixtures generated from
  the real `build_prompt()` functions (`scripts/gen-triage-fixtures.py`,
  `scripts/gen-hypotheses-fixtures.py`).

## Verified

- 1295 backend tests passing (up from 1216 at the start of the week: 79 new, across nine new
  `test_triage_assistant_*.py`/`test_hypotheses_*.py` files plus additions to
  `test_codeintel_python.py`/`test_codeintel_js.py`/`test_risk.py`/`test_pipeline.py`), 92.4%
  coverage; ruff/black/mypy all clean.
- 173 frontend tests passing (up from 163: 10 new for `TriageAssistantPanel`/`HypothesesLane`),
  `tsc --noEmit` clean, a real `next build` production build clean.
- Both migrations' live Postgres/RLS validation, and the pipeline/promotion end-to-end tests, all
  above.

## What this does NOT prove (read before relying on it)

- **No live run against a real hosted model, for either feature.** Both `core.triage_assistant
  .service.assess` and `core.hypotheses.service.assess_candidate` are unit-tested against fake
  Anthropic-shaped clients covering the real control-flow paths (a valid reply, a malformed reply
  repaired once, giving up) -- not run against the real API here, the same disclosed gap Week
  41/42's own verification docs already carry for their own LLM call sites.
- **The Hypotheses lane detects exactly one flaw type**: a route missing the authorization check its
  siblings have. IDOR and mass assignment, both named in the plan, are not implemented -- a
  deliberate scope decision (ADR-0028), not an oversight.
- **No live measurement against OWASP Juice Shop or seeded authorization flaws.** The plan asks for
  "precision on seeded authorization flaws plus OWASP Juice Shop's documented access-control
  challenges" -- that evaluation was not run in this environment (no live model, and no Juice Shop
  checkout was scanned). `generate_for_checkout`'s own end-to-end test proves the mechanism works
  against real code; it is not a precision measurement.
- **`auth_markers` extraction covers Python and Express/JS only.** Go and Django routes never
  produce a Hypotheses candidate this week -- a missed-candidate gap, not a false-positive risk (see
  the ADR).
- **The OWASP-Benchmark precision/recall measurement for the triage assistant's verdicts** (plan
  §21.3: "measured against the OWASP Benchmark's ground-truth labels") was not run -- it needs a
  live model, which this environment does not have. The contract, prompt construction, and
  ranking-integration mechanics are all real and tested; the verdict's actual accuracy against a
  real model is not measured here.
- **No live GitHub App run for either feature** (neither needs one directly, but Hypotheses-lane
  generation's re-clone reuses `core.gitfetch.clone_repo` over a plain public HTTPS URL, not through
  an installed App) -- consistent with how `core/gitfetch.py` is used elsewhere in this codebase.
