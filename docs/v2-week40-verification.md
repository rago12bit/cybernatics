# Week 40 verification — supply-chain risk (plan §20.5)

Honest record of what was built, run, and measured — for Week 40: malicious-package severity,
license policy, typosquat detection, OpenSSF Scorecard for direct dependencies, and the
direct/transitive dependency graph. See `docs/adr/0024-supply-chain-risk.md` for the design
decisions, including what was deliberately deferred. This closes Milestone M8 (`v1.3.0`).

## What was built

- `core/adapters/osv_scanner.py`: a `MAL-` id now forces `CRITICAL` severity and `1.0` confidence
  instead of falling through to `INFO`; `core/policy/input.py` exposes this as `malicious`, and the
  starter policy library gained a sixth rule (no malicious packages, ever).
- `core/sbom/syft.py`: `summarize()` now also returns `SbomPackage`s (name/version/ecosystem/purl/
  license/manifest path) and a direct/transitive dependency graph built from CycloneDX's own
  `dependencies[].dependsOn` array.
- `core/sbom/enrich.py::apply_licenses`: joins the SBOM's own package licenses onto findings before
  policy evaluation. `bulwark ci compare` gained `--sbom PATH`; the GitHub Action's existing
  `sbom: true` input now also feeds this (its step moved before "Compare and gate").
- `core/supplychain/typosquat.py`: a new Finding for any SBOM package within edit distance 1–2 of a
  popular package in the same ecosystem (`popular_packages.json`, a small curated seed).
- `core/supplychain/scorecard.py`: OpenSSF Scorecard for each *direct* dependency, via deps.dev
  (purl → source repo) and the Scorecard REST API, cached for a week.
- `core/supplychain/dependency_view.py::path_to`: the shortest root-to-package path over the SBOM's
  own dependency graph.
- `core/scoring/versions.py::smallest_safe_upgrade`: a real bug fix, shared by `osv_scanner.py` and
  `grype.py` — both previously used whichever fixed version a scanner listed first, not the smallest.
- `bulwark supply-chain analyze --sbom PATH --output PATH`: typosquats + Scorecard as a JSON report.

## Validated against real, live endpoints — not mocks

Every external integration was exercised against the real thing before any Python was written
around it, the same discipline ADR-0023 used for OPA:

- **`api.osv.dev`**: queried live for a known typosquat (`reuests` on PyPI) to confirm `MAL-`
  records are ordinary OSV records with no CVSS/severity fields — this is *why* the severity bug
  existed, not an assumption.
- **`bulwark/syft:1.52.0`**: run via Docker against a real two-level npm project (`once` → `wrappy`,
  installed with real `npm install`) to capture the actual CycloneDX shapes this feature depends on:
  `licenses[].license.id` / `.expression`, the `syft:location:0:path` property, and — critically —
  that a component's `dependencies[].ref` is its purl *plus* a `?package-id=...` qualifier, not the
  bare purl. Missing that distinction would have silently produced empty direct/transitive sets for
  every real SBOM; it was caught before writing `summarize()`, not after a test failed.
- **`api.deps.dev/v3alpha/purl/...`** and **`api.securityscorecards.dev/projects/...`**: both
  fetched live (`pkg:pypi/requests@2.31.0` → `github.com/psf/requests`; that repo's real Scorecard
  run, score 8.3) to confirm the exact REST paths and JSON shapes before `core/supplychain/
  scorecard.py` was written. (Unit tests mock `fetch` — the module is a thin, injectable wrapper —
  but the shapes being mocked are real captured responses, not invented ones.)

## A real bug found and fixed while writing this, not assumed

`core/adapters/osv_scanner.py` and `core/adapters/grype.py` both picked `fixed[0]` for their
remediation summary — whichever fixed version a scanner's own JSON listed first. Checked against
this codebase's own `tests/golden/osv-scanner/raw.json`: PYSEC-2023-62's flask record lists two git
commit hashes *and* two real releases (`2.2.5`, `2.3.2`), in that order. `smallest_safe_upgrade` was
written to compare dotted-numeric versions and refuse to order a list where any entry doesn't parse
that way — confirmed, by running it against this exact fixture, that it correctly declines to guess
(returns `None`, and the caller falls back to the old `fixed[0]` behavior) rather than lexically
"sorting" a git hash against a release number. The three real golden-fixture cases with mixed
hash/version lists were confirmed to produce byte-identical output to before this change.

## Verified

- 1102 backend tests passing (up from 1049: 52 new tests across `test_scoring_versions.py`,
  `test_sbom_syft.py`, `test_sbom_enrich.py`, `test_supplychain_typosquat.py`,
  `test_supplychain_scorecard.py`, `test_supplychain_dependency_view.py`,
  `test_cli_supply_chain.py`, plus additions to `test_adapters.py`, `test_policy_input.py`,
  `test_ci.py`, `test_action.py`), 2 skipped (unrelated), 94.4% coverage; ruff/black/mypy all clean
  (`mypy core api`, the project's own configured scope).
- `opa test core/policy/starter`: 15/15 passing (13 existing + 2 new, for the malicious-package
  rule), against the real `opa` binary.
- An end-to-end run: a real `bulwark/syft:1.52.0` SBOM piped through `bulwark ci compare --policy
  --sbom`, with a policy denying `issue.license == "ISC"`, correctly failed the gate with "x uses
  denylisted ISC license" in the generated PR comment — the license value came from the real SBOM,
  not a stub.
- `bulwark supply-chain analyze` end-to-end against the same real SBOM: correctly reported zero
  typosquats (a two-package project, neither a look-alike name) and the real direct/transitive split
  (`once` direct, `wrappy` transitive) with `--no-scorecard`.
- `tests/unit/test_action.py`'s own static-safety checks (no `${{ }}` shell injection, every
  third-party action pinned, every input wired) pass unchanged after moving the "Generate SBOM" step
  earlier; a new test asserts that step now runs strictly before "Compare and gate" and that
  `SBOM_FILE` is wired into it.
- **Since done, as a follow-up (ADR-0025, see below)**: the Dependencies screen UI, and wiring Syft
  into the hosted pipeline's own scan flow (`"syft"` in `Scan.tools`) -- both deferred here
  originally, now implemented.

## Follow-up (2026-09-30): the Dependencies screen, end to end

`core/sbom/syft.py::SyftAdapter` is now registered in `core/scan.py`'s `ADAPTERS`, selectable via
`Scan.tools` exactly like grype/checkov/gosec. `core/pipeline.py::_process_sbom` reshapes its raw
CycloneDX output into typosquat Findings (folded into the normal correlate/finalize/persist
pipeline, so they get fingerprints and Issue tracking for free) and a JSON summary persisted on a
new `Scan.sbom_summary` column (migration `0010`, one nullable JSON column -- no new table, matching
`FindingRow.data`'s own pattern). `GET /assets/{asset_id}/dependencies` (`api/schemas.py::
DependenciesView`) serves it, empty rather than 404 when no scan has opted in yet, mirroring
`/assets/{id}/issues`'s own shape. `web/app/app/projects/[id]/dependencies` renders it: a filterable
package table (name, ecosystem, direct/transitive/root, license, OpenSSF Scorecard for direct
dependencies), each row expandable to its own path-from-root (a client-side BFS over the same graph
`core.supplychain.dependency_view.path_to` walks server-side) and its direct dependents -- no new
graph-drawing library, since none existed in this codebase and the actual need (a small tree/DAG,
shortest-path) didn't warrant adding one. `SubmitForm.tsx` gained a "Supply-chain risk" checkbox so
a user can opt a hosted scan into this from the web UI, not only the API/CLI. Full design reasoning
in `docs/adr/0025-dependencies-screen.md`.

Verified: a synthetic scan with `tools=["syft"]` and a fake CycloneDX raw output (a real
`ToolOutcome`, run through the actual `run_scan_job`, not a mocked pipeline) correctly persisted
`Scan.sbom_summary` (component count, per-package license/relation) and a real typosquat `Finding`
in the `findings` table with `reported_by=["bulwark-typosquat"]` -- confirming the whole
tools-loop-to-persistence path, not just `_process_sbom` in isolation. 7 new backend tests (1117
total), 5 new frontend tests (155 total; the dependency-path/relation-filter logic exercised against
realistic fixture data matching the real API response shape), `tsc --noEmit` and mypy/ruff/black all
clean. The new page was confirmed live in a real browser (Next.js dev server) to compile, route, and
render correctly behind `TokenGate` -- verifying the component's own data rendering against a real
backend (Postgres/Redis/Celery/a real scan) was not done this session; that path is covered instead
by the automated component tests above, which exercise the exact same API response shape.
