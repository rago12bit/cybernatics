# Week 53 verification -- Gate and hierarchy (plan Phase 13, §39.5/§40)

Honest record of what was built, run, and measured. First week of v3; see
[ADR-0038](adr/0038-hosted-mode-opengrep.md) and [ADR-0039](adr/0039-portfolio-engagement-hierarchy.md)
for the real design decisions.

## What was built

- **Task 1 -- Verification gate (§39.5)**: found that the "two-tenant RLS test passes on every
  endpoint" gate item was false by a wide margin -- the existing test covered 4 of this API's 50+
  endpoints, a scope that hadn't grown since Week 29/30. Closed with
  `tests/integration/test_api_tenancy_coverage_rls_docker.py`, extending real cross-org coverage to
  every `/assets/{asset_id}/...` endpoint and the remaining `/scans/{id}/...` ones (~27 more
  endpoints).
- **Task 2 -- ADR-0038**: hosted mode runs Opengrep, not Semgrep, closing the plan's "ADR-015" gate
  item. New `core/adapters/opengrep.py`, `docker/opengrep/` (a from-scratch image, since no official
  one exists), and an originally-written starter ruleset (`docker/opengrep/rules/`) -- Opengrep's own
  bundled rules turned out to carry the identical "no hosting as a service" restriction Semgrep's do,
  discovered by actually reading their LICENSE file rather than assuming the fork solved licensing by
  itself.
- **Task 3 -- ADR-0039**: `Portfolio` and `Engagement` tables (plan §40 change C11), plus a real data
  migration (0026) giving every existing Asset one "ci" Engagement and linking its history to it.
  "Test" is deliberately not a third new table -- `ToolRun` already was one, gaining only an
  `engagement_id` column.
- **Task 4**: RLS + the two-tenant leak test for both new tables, live-verified against real Postgres.

## Validated against real, live things -- not mocks

- **The "every endpoint" gap, proven by actually trying every endpoint.** Seeded one real
  asset/issue/hypothesis/conversation/scan for an org via direct ORM inserts, then hit all ~27
  previously-untested `/assets/{asset_id}/...` and `/scans/{id}/...` routes with another org's
  header against a real, freshly migrated Postgres connected as `bulwark_worker`. All correctly
  404; no leak found, but the coverage gap itself was real before this task closed it. Three real
  test-design bugs were found and fixed getting this to pass cleanly (a missing required query
  param, a client gated on the wrong `AppState` field, a Copilot endpoint's additional
  `isinstance(client, AnthropicClient)` check) -- documented in the task's own commit.
- **Opengrep's actual licensing, checked by fetching and reading the real files**, not assumed from
  marketing copy: the engine's `LICENSE` (plain LGPL-2.1) and `opengrep-rules`' `LICENSE` (LGPL-2.1
  **plus** a Commons Clause "no selling as a service" condition) were both fetched directly from
  GitHub and read before any adapter code was written. A web search's suggested Docker image names
  (`ghcr.io/opengrep/opengrep`, `opengrep/opengrep`) were checked against both registries' own APIs
  and found not to exist, before building `docker/opengrep/` around the real binary-release
  distribution mechanism instead.
- **Every one of the 11 new Opengrep rules, hand-verified against real true/false-positive pairs**
  inside the actual built image (`docker run ... opengrep scan --config ...`) before being trusted --
  not assumed correct from the YAML alone.
- **A real sandbox incompatibility, reproduced and isolated, not guessed at.** Opengrep's binary
  failed every run with "couldn't launch child (exec): Permission denied" against the sandbox's
  shared `/tmp`. Isolated to the tmpfs mount itself (a bare, unrestricted `--tmpfs=/tmp` mount with
  no flags at all still failed the same way; a totally unmounted default `/tmp` did not) before
  settling on redirecting `HOME`/`TMPDIR` to a plain writable volume instead of loosening the shared
  sandbox protection.
- **The Portfolio/Engagement data migration, run against real seeded data on a real Postgres**: one
  asset with a real scan and two real ToolRuns correctly got one Engagement with both ToolRuns
  linked; one asset with no scans correctly got one empty, `"completed"` Engagement. The full
  migration chain (0001 through 0026) was also run against a brand-new, from-scratch Postgres, not
  only the incrementally-migrated one used throughout the rest of the week's work.
- **Cross-org isolation for both new tables and for the Tests (ToolRuns) inside an Engagement**,
  live against real Postgres RLS, including the fail-closed guarantee for a connection that never
  set an org context at all.

## Verified

- Backend: `ruff check .`, `black --check .`, `mypy` (217 source files) clean throughout.
- Full unit suite: 1803 passed, 1 skipped (up from Week 52's close of 1779 -- +24: 8 Portfolio/
  Engagement repo tests, 9 Opengrep/hosted-mode tests across two files, 7 miscellaneous from the
  golden-fixture conformance parametrization picking up the new adapter).
- 23 `tests/integration/*_rls_docker.py` tests pass together against one real Postgres instance (4
  of them new this week), connected as `bulwark_worker`.
- `THIRD_PARTY_LICENSES.md` regenerated and passing its own policy check (`scripts/gen-licenses.py
  --check`) with Opengrep's real license correctly recorded.
- `docs/severity-matrix.md` regenerated and passing its own freshness test with Opengrep's severity
  mapping included.

## What this does NOT prove (read before relying on it)

- **The verified-fix agent's verification record on a real pull request** (plan §39.5's own fourth
  gate item) is still not demonstrated -- it needs a live model, which this environment is not
  configured with. Not newly discovered this week; carried over from every prior week's own
  disclosure of the same gap.
- **Opengrep's starter ruleset is small and unmeasured at corpus scale** (7 Python + 4 JS/TS rules,
  each hand-verified individually, not run against a labelled corpus) -- see ADR-0038's own
  disclosure.
- **No Portfolio/Engagement API or UI exists yet.** This week's scope was the data model and its
  migration; the v3 screens and endpoints that read and write it are later weeks' own tasks.
- **The "every endpoint" cross-tenant test still doesn't cover `/plugins`, `/settings/integrations`,
  or `/settings/retention`'s own cross-org behavior at the HTTP layer** -- those are already
  covered, but at the repository layer (their own `*_rls_docker.py` files from Weeks 47/51), not by
  an HTTP request through the live API the way this week's new test covers the asset-scoped surface.
  Not a known gap so much as a different, already-covered layer -- noted for completeness, not as a
  new finding.
