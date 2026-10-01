# Week 49 verification -- DAST: ownership verification, egress proxy, scanning tiers, SAST/DAST correlation (plan §22.4)

Honest record of what was built, run, and measured. See [ADR-0035](adr/0035-dast-scanning.md) for
the design decisions, including the one piece (campaign execution routed through the egress proxy)
that was not wired together this week despite both halves existing and being independently proven.

## What was built

- `core/dast/ownership.py`, new `asset_verifications` table (migration 0021): DNS TXT / `.well-known`
  proof-of-control, re-checked live everywhere it gates something, never trusted from a cached
  status (task 1).
- `core/dast/proxy.py`, `core/dast/egress.py`, `docker/dast-egress-proxy/`: a real allow-list forward
  proxy and the nftables policy that would force a campaign runner through it (task 2).
- `core/dast/campaign.py`, `core/dast/pipeline.py`, `core/dast/adapters/{zap,nuclei}.py`,
  `scans.dast_mode` (migration 0022): passive (ZAP baseline) always-on, active (+curated Nuclei)
  opt-in and rate-limited, the campaign UI (`/app/projects/[id]/campaigns`), and audit logging (task
  3).
- `core/dast/routes.py`, `core/dast/correlate.py`, `scans.route_map` and `issues.
  confirmed_at_runtime_at`/`confirmed_by_scan_id` (migration 0023), `assets.linked_source_asset_id`:
  a DAST finding on a route with a related-CWE SAST finding near its handler marks that Issue
  confirmed at runtime (task 4).

## Validated against real, live things -- not mocks

- **Ownership verification**: real DNS/HTTPS lookups against `example.com` (confirmed failing, no
  such record exists there) via both the CLI and a real FastAPI `TestClient` request path; the full
  browser → Next.js dev server → FastAPI → Postgres → DNS path exercised in a real browser session,
  showing the real DNS failure message end to end. A real bug was found and fixed this way: the new
  CLI commands never set the Postgres session's `app.current_org`, so every write hit RLS's own
  INSERT denial under a real (non-SQLite) connection -- fixed by calling `set_session_org` first,
  the same as every other admin/CLI code path already does.
- **The egress proxy**: a real running instance relaying a real local HTTP server's response and
  refusing (and reporting, as structured JSON) a disallowed host; a real CONNECT tunnel plus a real
  TLS handshake to `example.com` over the real network; the actual `docker/dast-egress-proxy` image
  built and run standalone with the same results via `curl -x`.
- **ZAP and Nuclei adapters**: a real `zap-baseline.py` run against a real local HTTP target found 19
  real findings, including discovering a `/admin` link it found by actually spidering the page -- not
  a canned fixture. A real Nuclei run against `https://example.com/` produced real findings with real
  CWEs. Two real bugs were found this way and fixed, each with a regression test: ZAP's rule 90004
  reporting three distinct alerts under one shared `pluginid` against the same URL (fixed by including
  the alert name in the finding id); Nuclei reporting the same template against the same URL more
  than once (fixed by hashing the whole raw record instead of just the matched URL).
- **The full DAST campaign pipeline**: with only the live ownership check stubbed (genuine DNS/HTTP
  verification was already proven separately above; a synthetic domain can never pass a real check),
  a complete campaign ran against real Postgres -- live rate-limit check, real ZAP+Nuclei execution
  against `https://example.com/`, real correlation/dedup (69 raw findings → 46 unique), real
  persistence, real issue sync (19 issues created), a real audit-log entry. A third real bug was
  found here: the worker's own active-scan rate-limit re-check compared the campaign's own
  `created_at` to itself to exclude it from "the most recent prior active campaign" -- under SQLite
  this comparison silently failed (naive vs. aware datetimes), which would have made every active
  campaign instantly rate-limit itself in production. Fixed by excluding the current scan by id in
  the query instead of comparing timestamps at all.
- **Route extraction**: run against this project's own `api/main.py` (1700+ real lines) found all 44
  real FastAPI routes, including `/assets/web`, `/assets/{id}/verify`, and `/assets/{id}/campaigns`
  -- the exact routes this week's own earlier tasks added -- a stronger proof than any hand-built
  fixture that the decorator-matching logic works on real code.
- **SAST/DAST correlation end to end**: a real `bandit` scan (via `core.pipeline.run_scan_job`, the
  actual worker code path) of a real, deliberately vulnerable Flask app (`subprocess.call(query,
  shell=True)`, CWE-78) against a real zip archive produced a real, correctly-extracted route map
  (`/search` at the right line) persisted to real Postgres. Registering a web Asset linked to that
  SAST Asset, then running the correlator with a synthetic CWE-78 DAST finding on the same route,
  correctly wrote `confirmed_at_runtime_at`/`confirmed_by_scan_id` onto the real `Issue` row for the
  real command-injection finding. Committed as `tests/integration/test_dast_sast_correlation_live.py`,
  not just an ad-hoc script.
- **Cross-tenant isolation**: `asset_verifications`' RLS policy (join-based through `assets.org_id`,
  the same pattern `issues`/`findings`/`tool_runs` already use) verified against real Postgres --
  org B cannot see org A's verification row even querying the table directly by id, bypassing
  application-level `org_id=` filtering entirely. `assets.linked_source_asset_id` cross-org linking
  is rejected at write time (`repo.register_web_asset` raises `ValueError`), verified directly.
  Migration 0021's up/downgrade round-trip verified against real Postgres.

## Verified

- 1578 unit tests passed, 1 skipped (consistent with prior weeks' disclosed never-executed paths),
  up from Week 48's 1481. New: `test_dast_ownership.py`, `test_asset_verification_repo.py`,
  `test_asset_verification_api.py`, `test_dast_proxy.py`, `test_dast_egress.py`,
  `test_dast_zap_adapter.py`, `test_dast_nuclei_adapter.py`, `test_dast_campaign.py`,
  `test_dast_campaign_api.py`, `test_dast_routes.py`, `test_dast_correlate.py`. `black --check .`,
  `ruff check .`, `mypy` (core+api, the project's own enforced scope) all clean.
- 9 integration tests against real Postgres/real sockets/real network, all passing:
  `test_asset_verification_rls_docker.py` (2), `test_tenancy_rls_docker.py` (2, no regression),
  `test_dast_proxy_live.py` (3), `test_dast_adapters_live.py` (2, ZAP+Nuclei), plus
  `test_dast_sast_correlation_live.py` (1).
- Frontend: 211 tests passed (up from 198), `tsc --noEmit` clean. New: `web-asset-verification.
  test.tsx`, `campaigns-view.test.tsx`, `confirmed-at-runtime-badge.test.tsx`.
- Golden fixture tests (`test_adapters.py`) updated for the new `Location.route` field appended to
  the canonical `Finding` schema -- a clean, purely-additive diff across 9 fixture files, re-verified
  passing.

## What this does NOT prove (read before relying on it)

- **The egress proxy is not in the loop for a real campaign.** `core/dast/pipeline.py` runs ZAP/
  Nuclei as plain `docker run` subprocesses on the worker host today; it does not start a
  per-campaign proxy instance or apply the nftables egress policy to the scanner containers. Both
  halves are real and independently verified; connecting them is real remaining work (ADR-0035 has
  the detail), not a rounding error.
- **The nftables ruleset itself has never loaded into a real network namespace**, on this machine or
  any other, for this feature -- Linux-only, same disclosed boundary as Week 46's own egress work.
- **Route extraction covers one decorator shape.** Django's `urls.py` table, non-Python frameworks,
  and any route built from a runtime string (not a string literal in the decorator) are invisible to
  it -- correlation simply finds nothing for those, never a wrong match.
- **The DAST-side half of one correlation test was synthetic.** Getting a real ZAP/Nuclei scan to
  report a genuine "OS command injection" finding needs a real vulnerable live server with the
  injectable code path actually running, not static source on disk -- the adapters' own real-scanner
  execution was separately and fully verified live (above); only the specific "this scanner found
  this specific CWE at this specific route" fact in the correlation test is a stand-in for that.
- **Linking a web Asset to its source project is API/CLI-only.** The "Add web target" registration
  screen does not yet offer a picker for `linked_source_asset_id`.
- **Branch protection, a real production deployment of any of this, and an actual Celery worker
  process consuming `bulwark.run_dast_campaign` were not part of this review** -- the campaign
  pipeline was run directly (as a real function call against real Postgres), not via a running
  Celery worker consuming from a real Redis queue, matching the same practical boundary this
  project's other "run the real job function directly" verifications have drawn before.
