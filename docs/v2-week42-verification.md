# Week 42 verification — the verified-fix agent (plan §21.2)

Honest record of what was built, run, and measured — for Week 42: "the flagship v2 feature." See
`docs/adr/0027-verified-fix-agent.md` for the design decisions, including several deliberate,
disclosed scope cuts. This closes part of PHASE 10 (M9 is Weeks 41-45; this is Week 42 only).

## What was built

- `core/fixagent/limits.py`: ADR-0015's three safety limits, with real, documented numbers.
- `core/fixagent/tools.py` + `context.py`: `read_file`/`search_code`/`get_call_path`, path-contained,
  built on a fresh `core.codeintel.analyze()` run per attempt (nothing about the call graph survives
  past the original scan, confirmed before writing this).
- `core/fixagent/agent.py`: the propose-patch tool-calling loop, the first tool-calling code in this
  repository, hosted (Anthropic) only.
- `core/fixagent/verify.py`: `apply_patch` (a real `patch -p1` call), `rerun_rule`, `rerun_scanners`
  -- all reusing `core.scan.scan()`, none inventing new scan-scoping infrastructure.
- `core/fixagent/sandbox.py`: a second, more permissive Docker sandbox for opt-in project test runs.
- `core/fixagent/github_pr.py`: `create_pull_request`, built on GitHub's Contents API.
- `core/fixagent/workflow.py` + `worker.py` + `client.py`: the Temporal workflow, its activities, the
  worker entrypoint, and the API's own Temporal client wrapper.
- `core/fixagent/store.py` + `core/persistence/models.py::VerifiedFixRun` + migration `0012`:
  persistence for one run, RLS-protected.
- `api/main.py`: `POST/GET /assets/{asset_id}/issues/{issue_id}/verified-fix[/approve|/reject]`.
- `docker-compose.yml`: `temporal`, `temporal-ui`, `fixagent-worker`, all behind `--profile fixagent`.
- `web/components/VerifiedFixPanel.tsx` + `verified-fix-panel.css`: the fix-review screen (plan
  §28.4), embedded in the existing issue detail page.
- `core/tokens.py`: two new scopes, `fixes:read`/`fixes:write`, added only alongside the endpoints
  that actually check them (the file's own stated rule for adding a scope).

## Validated against real, live things — not mocks

- **A real local Temporal server** (`temporal server start-dev`): a hand-written hello-world
  workflow was run to prove basic connectivity, then specifically to prove **worker-restart
  durability** -- started a workflow, killed the worker process mid-run (before it received the
  human-approval signal), started a brand-new worker process with no shared memory, and it resumed
  and completed correctly purely from Temporal's own event history. This is the plan's own stated
  reason for choosing Temporal over Celery for this feature, and it was checked, not assumed.
- **`VerifiedFixWorkflow.run()` itself**, against `temporalio.testing.WorkflowEnvironment
  .start_time_skipping()` (a real, disposable Temporal server whose clock fast-forwards through
  workflow timers): four scenarios run the actual workflow code end to end --
  approve-opens-a-pr, reject-never-opens-a-pr, max-attempts-exhausted-never-asks-for-approval, and
  overall-timeout-stops-starting-new-attempts-and-reports-inconclusive. All four passed against the
  real engine (`tests/unit/test_fixagent_workflow.py`, ~42s total).
- **The context-gathering and tool layer**: `gather_context`/`read_file`/`search_code`/
  `get_call_path` were run against a real, on-disk two-function Python file with a real call
  relationship (`handler` calls `get_user`) -- `core.codeintel.analyze()` correctly found the
  enclosing function and its real caller. Path containment was checked against `../` escapes, bare
  absolute paths, and mixed traversal -- all correctly rejected.
- **The test-execution sandbox**: a real `python:3.12-slim` container, a real `pip install pytest`
  over the network, a real passing test run, then a real failing one (with the actual pytest failure
  output captured and returned) -- both confirmed by hand before the mocked-subprocess unit tests
  were written around the already-proven mechanism.
- **The migration**: `0012` was run up, down, and up again against a real
  `bulwark/postgres:16-pgvector` container, including confirming RLS actually isolates one org's
  `verified_fix_runs` row from another's (`SET ROLE bulwark_app; SET app.current_org = ...`).
- **`docker compose config`**: the new `temporal`/`temporal-ui`/`fixagent-worker` services (plus
  every existing profile) resolve cleanly with no schema errors -- not started end-to-end (no real
  GitHub App or hosted LLM key configured in this environment to run a full live workflow through
  Temporal against real containers), but the compose file itself is proven valid, not just written.
- **The frontend**: `npm run build` (a real Next.js production build, not just `tsc --noEmit`)
  compiled cleanly with the new route wiring; all 163 frontend tests pass (up from 155), including
  8 new tests for `VerifiedFixPanel` that caught one real integration gap (an existing a11y test's
  fetch mock needed a branch for the new endpoint) before it could have shipped as a console error
  on a real issue page.

## A real bug caught while writing tests, not by inspection

`core.scan.scan()` always recomputes `Finding.fingerprint` via `correlate()`, discarding whatever a
caller set beforehand -- a first draft of `test_fixagent_verify.py` hand-assigned matching
fingerprint strings to two fake `Finding` objects and got real, failing assertions back, because the
correlator silently replaced both with freshly-computed (and, since the two fakes had subtly
different shapes, *different*) values. Fixed by constructing both findings with identical
path/snippet/CWE/rule-ids so they hash the same way a real rescan would. This is documented in
ADR-0027 as a real, useful discipline the test uncovered, not a test-only workaround.

## Verified

- 1216 backend tests passing (up from 1151: 65 new, across seven new `test_fixagent_*.py` files),
  2 skipped (unrelated), 93.0% coverage; ruff/black/mypy all clean (`mypy core api`).
- 163 frontend tests passing (up from 155: 8 new for `VerifiedFixPanel`), `tsc --noEmit` clean, a
  real `next build` production build clean.
- The Temporal workflow's own live validation and the migration's live Postgres/RLS validation,
  both above.

## What this does NOT prove (read before relying on it)

- **No end-to-end run against a real GitHub App installation.** `create_pull_request`'s five-call
  sequence was built from GitHub's documented REST v3 contract and is unit-tested against a fake,
  sequenced transport -- this environment has no real App credentials to exercise it against live.
  The request shapes are believed correct, not proven correct against the real API.
- **No end-to-end run through Temporal against a real hosted LLM key.** The propose-patch tool-
  calling loop (`core/fixagent/agent.py`) is unit-tested against a fake Anthropic-shaped client
  covering the real control-flow paths (valid patch, invalid patch retried once, giving up, secret
  scrubbing on tool results) -- it has not been run against the real Anthropic API with a real key in
  this environment. Week 41's own `AnthropicClient.complete()` (the simpler, non-tool-calling path)
  has real-world usage from the base remediation feature; `complete_with_tools` is new and unproven
  against a live model.
- **The per-attempt-timeout scenario (a genuinely hung Temporal *activity*) was not validated with a
  live timing test.** The other three ADR-0015 scenarios were; this one is covered by code review
  and Temporal's own documented `ActivityError` behavior, not a live run -- scripting a reliable,
  fast-running "activity hangs past its own timeout" test proved awkward in this environment.
- **No MLX/local tool-calling** (ADR-0027's own cut, mirroring ADR-0026's Ollama-only decision):
  verified-fix does not work in Week 41's privacy mode.
- **No "Edit" action** on a pending patch before approving it, unlike the plan's own three-button
  mockup (`[Reject] [Edit] [Open pull request]`) -- this ships two.
- **No precise minimal capability set for the test-execution sandbox** -- it runs with Docker's
  default capabilities (not `--cap-drop=ALL`, unlike the scanner sandbox), disclosed as the honest
  floor for "hardened Docker, for now" rather than a guessed-at middle ground. ADR-0015/ADR-0027 both
  point at Firecracker (Phase 11, not yet built) as the real fix.
- **`docker compose --profile fixagent up -d` was not run end-to-end** in this environment (no real
  GitHub App/LLM credentials to make a real run meaningful) -- `docker compose config` confirms the
  compose file itself is valid, not that a full stack boots and completes a real verified-fix run.
