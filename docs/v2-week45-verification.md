# Week 45 verification -- attack paths, threat model draft, red team (plan §21.6/§21.7/§21.9)

Honest record of what was built, run, and measured. See `docs/adr/0030-attack-paths-threat-model-and-red-team.md`
for the design decisions, including why several pieces reuse existing infrastructure (the call graph,
`core.taint.catalog`'s sink patterns, an already-curated but previously-unused payload corpus)
rather than building new detection.

## What was built

- `core/attackpath/` (task 1): `model.py` (Node/Edge/AttackPath dataclasses), `nodes.py`
  (entrypoint/issue node construction from already-persisted data), `rules.py` (three chaining
  rules -- one call-graph-verified, two disclosed co-location heuristics), `service.py`
  (fetch-issues -> apply-rules -> rank orchestration, pure, no I/O).
- `core/attackpath/prompt.py`/`contract.py`/`narrative.py` + `checkout.py` (task 2): a model-written
  narrative per path, contract-enforced to mention every node label it was given; a one-shot
  clone+analyze helper (deliberately uncached, unlike the copilot's `CheckoutCache`, since this
  screen is typically opened once per visit). `Task.ATTACK_PATH` added to the gateway. One API
  endpoint (`GET /assets/{id}/attack-paths`) that never gates on a model being configured. A
  paginated attack-path screen at `/app/projects/[id]/attack-paths`.
- `core/threatmodel/` (task 3): `model.py`/`generate.py` -- a fully deterministic Mermaid DFD +
  STRIDE table generator, no LLM call. New `threat_models` table (migration 0017, one current row
  per asset, RLS via `assets`). Three endpoints (`GET` auto-generates, `POST .../regenerate`,
  `PUT` for edits). An editable diagram + table screen at `/app/projects/[id]/threat-model`,
  rendered with the new `mermaid` npm dependency (pinned to 11.17.2 + `npm audit fix` after the
  default install pulled in a high-severity transitive `lodash-es` vulnerability via `chevrotain`).
- `tests/redteam/` (task 4): wires up `tests/fixtures/injection_payloads.json` (20 payloads, curated
  in an earlier week, never used until now) into a real test suite against the fix/triage/copilot
  pipelines. Fixed a real bug it caught: `core/llm/prompt.py` and `core/triage_assistant/prompt.py`
  scrubbed secrets from a finding's `code` block but never its `title`/`description`.
- `docs/adr/0030-*.md`, `docs/attack-paths.md`, `docs/threat-model-draft.md`, `docs/redteam.md`.

## Validated against real, live things -- not mocks

- **The SSRF chaining rule, against a real analyzed checkout.** A real Flask fixture (route ->
  helper -> sink) run through `core.codeintel.analyze`, proving the backward call-graph walk
  actually finds the reachable entrypoint -- not a hand-built `CodeGraph` standing in for real
  analysis. A negative case (an orphan symbol with no callers) confirmed no path is produced when
  unreachable.
- **The full attack-path service, against real persisted issues.** Seeded through
  `core.persistence.repo.sync_issues_for_scan`/`add_findings`, the same real path production scans
  use, not fixtures shaped by hand to match what the code expects. Caught a real bug during
  development: the `secret_grants_resource` rule had no exclusion for `.github/workflows/` paths,
  producing a redundant path alongside the more specific `ci_secret_workflow` rule for the exact
  same secret+workflow pair -- fixed before this was committed.
- **The narrative contract, against a fake model covering the real control-flow paths**: a valid
  reply, a reply missing a node retried once then succeeding, two failed attempts returning `None`
  rather than a guess, and a transport failure doing the same.
- **`threat_models`' RLS, against a real disposable Postgres container** (`pgvector/pgvector:pg16`,
  since migration 0002 needs the `vector` extension): the full migration chain, then a real insert
  under org-a and org-b each, connected as `bulwark_app` (not a superuser), confirming each org sees
  only its own row -- the same standard already held for `hypotheses`, `code_chunks`, and both
  copilot tables.
- **The threat-model generator, against a real analyzed checkout** with three real routes (one
  reaching a SQL sink, one reaching a command sink, one reaching neither): confirmed the Database
  and OS-process nodes and their STRIDE rows each appear exactly once, not once per reaching route.
- **The API layer, against real persisted rows**: first access auto-generates and persists; a
  second access returns the same row without re-cloning; a `PUT` edit persists and survives a
  subsequent `GET`; `regenerate` discards the edit and re-clones.
- **The red-team corpus, against the real contracts and pipelines, not mocks of them.** All 20
  payloads rejected as raw replies by three different contracts (60 cases); schema-valid replies
  isolating one adversarial detail at a time (patch redirection, dismissal language, an extra field)
  still rejected; a fully-compliant fake model's legitimate "likely_false_positive" verdict proven to
  never touch the real `Finding` object; an injected instruction naming a disallowed copilot tool
  proven to error safely via `_dispatch`'s real unknown-tool branch; cross-tenant reach proven
  impossible against two real seeded assets, not merely argued from the function signature.

## Verified

- Backend: `test_attackpath_*.py` (model/nodes/rules/service/contract/narrative/checkout/api, 29
  tests), `test_threatmodel_*.py` (generate/repo/api, 15 tests), `tests/redteam/*.py` (73 tests),
  plus `test_llm_gateway.py`/`test_llm.py` updated for the new `Task.ATTACK_PATH` route. Full suite
  re-run clean after every task (ruff/mypy, and the affected areas' own tests); one full-suite run
  at the end: 1487 passed, 1 pre-existing unrelated Docker-integration flake
  (`test_grype_agrees_with_trivy_and_osv_on_the_same_dependency`, not caused by this week's work),
  2 skipped.
- Frontend: `attack-paths-screen.test.tsx` (4 tests), `threat-model-editor.test.tsx` (4 tests,
  `mermaid`'s `render`/`initialize` mocked since jsdom cannot do real SVG layout), full existing
  suite re-run clean, `tsc --noEmit` clean.
- `threat_models`' live Postgres/RLS validation, above.
- `scripts/gen-licenses.py --check` passes with a new, disclosed manual override for `khroma`
  (mermaid's color-math dependency): its `package.json` omits a license field entirely, verified by
  hand against its actual MIT `LICENSE` file in `node_modules` rather than assumed.

## What this does NOT prove (read before relying on it)

- **The two co-location heuristic rules are not proven causal links.** `secret-grants-resource-v1`
  and `ci-secret-workflow-v1` connect a secret to a resource/workflow only because both exist in the
  same asset -- neither Checkov nor gitleaks output in this codebase records which credential
  actually grants access to which resource. Disclosed in both the rule docstrings and
  `docs/attack-paths.md`, not silently presented as equally certain to the verified SSRF rule.
- **No multi-hop path combination.** Two separately-matched rules never combine into one longer
  chain this week. A real generalization, not attempted.
- **No live run against a real hosted model**, for either the attack-path narrative or the
  red-team suite's live-model half (garak). Both are unit-tested against fake clients covering the
  real control-flow paths -- the same disclosed gap every LLM call site in this project already
  carries (Weeks 41-44).
- **No attack-success-rate tracking.** The plan asks for one; it only means something for a
  probabilistic, live-model run, which this week deliberately does not add (real API spend on every
  scheduled run, non-deterministic results a hardcoded number would misrepresent). See
  `docs/redteam.md` for what wiring this up later would need.
- **A fully-compliant model reciting its own system prompt back in free text is not structurally
  prevented.** No contract filters `rationale`/`explanation` fields against echoing prompt text; the
  mitigating factor is that no system prompt in this project contains secrets, only instructions.
- **`core/attackpath/checkout.py`'s one-shot clone is uncached**, unlike the copilot's
  `CheckoutCache` -- a disclosed perf limitation (slower page load on repeat visits), not a
  correctness issue.
- **Threat-model `version` is a plain counter, not full history.** An edit or regenerate overwrites
  the prior content in place; there is no way to view or restore an earlier version.
