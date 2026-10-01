# Week 50 verification -- Scale: Helm chart with KEDA, k6 load testing, cost-per-scan dashboard (plan §23)

Honest record of what was built, run, and measured. See [ADR-0036](adr/0036-scale.md) for the design
decisions, including every disclosed simplification.

## What was built

- `helm/bulwark/`: a Helm chart for the core product (Postgres, Redis, object storage, OpenBao,
  migrate Job, API, worker, a new single-replica Celery beat, web), plus an optional KEDA
  `ScaledObject` scaling the worker on Celery queue depth.
- `k6/scan-submission.js`, `k6/browse-results.js`: real load-test scripts against a real running API.
- `core/observability/cost.py`, two new API endpoints (`/scans/{id}/cost`, `/costs/summary`), a new
  Prometheus gauge + two Grafana panels, and a new web page (`/app/costs`) for cost-per-scan
  visibility.
- Along the way: `core/persistence/db.py`'s connection pool sizing, `docker-compose.yml`'s `api`
  command (`--workers 4`) and `postgres` command (`max_connections=300`), and a real fix to an
  existing, previously-undiscovered `openbao` healthcheck bug.
- A real, pre-existing production bug in `core.maintenance.reap_stale_scans`, unrelated to Scale
  itself but found while doing this week's own RLS/connection work: it queried `scans` with no
  `app.current_org` ever set, which real Postgres RLS reads as "see nothing," not "see everything" --
  the housekeeping task meant to fail scans whose worker died was silently a no-op in any real,
  RLS-enforced deployment. Fixed to iterate one org at a time with `set_session_org`, the same
  pattern `core.retention.shred_expired_scans` already used (and whose own docstring already named
  `reap_stale_scans` as needing it).

## Validated against real, live things -- not mocks

- **A real `kind` Kubernetes cluster**, not a dry-run. `helm install bulwark helm/bulwark` into a
  freshly created `kind create cluster` brought every pod to Ready: Postgres (StatefulSet), Redis,
  object storage, OpenBao, a migrate Job that ran `alembic upgrade head` for real, the API (passed its
  own `/healthz` readiness probe), the worker (2/2 containers Ready, including the `docker:27-dind`
  sidecar), beat, and web.
- **A real KEDA installation** (`helm install keda kedacore/keda -n keda`), not a stub. Its own
  `ScaledObject` genuinely reads Redis `LLEN celery` through the KEDA operator's metrics API server --
  confirmed via `kubectl get scaledobject` showing `READY=True` only after fixing the Redis address to
  be fully qualified (see ADR-0036).
- **A real, deliberately isolated 3,000-task backlog, and a real scale event.** The worker Deployment
  was paused at 0 replicas (`autoscaling.keda.sh/paused-replicas=0`) specifically so the backlog being
  built wasn't also being drained at the same time; `kubectl exec`'d into the real API pod,
  `celery_app.send_task('bulwark.update_feeds')` was called 3,000 times for real, and Redis was queried
  directly to confirm the depth held at exactly 3,000 with nothing consuming it. Unpausing and polling
  `kubectl get hpa`/`kubectl exec ... redis-cli llen celery` every 4 seconds showed: depth 3000 at
  t=4s, replicas already at 5 (the configured max) by t=16s, depth down to 0 by t=28s. A second
  `kubectl get pods -l app.kubernetes.io/component=worker` poll loop, run in the background, confirmed
  the Deployment scaled back down to 1 replica (the configured min) roughly 5 minutes after the queue
  emptied -- HPA's own default scale-down stabilization window, unmodified.
- **The beat-is-a-scheduler-only fix, proven by the same backlog technique**: before the fix (beat
  running `worker -B -P solo -c 1`), a 100-task backlog pushed onto a paused worker Deployment drained
  to 0 anyway within seconds, proving beat was silently consuming the very queue KEDA was supposed to
  scale on. After switching beat to the dedicated `celery beat` subcommand, the identical technique
  (100 tasks, worker paused, checked depth) held the queue at 100 until the worker was unpaused.
- **k6, against the real docker-compose dev stack**, not a mock API. `k6 run k6/scan-submission.js`
  (`BULWARK_API_TOKEN` a real scoped token minted via `bulwark token create`):

  ```
  checks_succeeded...: 99.83% (2476/2480 — 4 transient 500s)
  http_req_duration..: avg=406.63ms min=270µs med=380.23ms p(50)=380.23ms p(90)=593.9ms p(95)=675.18ms p(99)=809.99ms max=1.16s
  http_reqs..........: 2480   122.182577/s
  ```

  `k6 run k6/browse-results.js` (final run, after the `--workers 4` + pool-sizing + `max_connections`
  fixes; `BULWARK_SCAN_ID` a real completed scan):

  ```
  checks_succeeded...: 96.75% (9854/10184)
  http_req_duration..: avg=2.64s med=696.41ms p(50)=696.41ms p(90)=1.08s p(95)=1.84s p(99)=1m0s
    { expected_response:true }...: avg=809.44ms med=686.89ms p(50)=686.89ms p(90)=1s p(95)=1.18s p(99)=2.33s
  http_reqs..........: 10184  127.298695/s
  iterations.........: 3292   41.149578/s
  ```

  (The earlier, unfixed runs -- single uvicorn process timing out at ~31s on 85%+ of requests, then a
  mis-sized connection pool doing the same thing for a different reason -- are recorded in full in
  ADR-0036, since they're exactly the evidence for why each fix was needed, not just the final number.)
- **The cost dashboard, end to end, with real scan data.** `GET /scans/{id}/cost` against a real,
  just-completed scan (a real `octocat/Hello-World` clone-and-scan) returned
  `{"compute_seconds": 0.39, "compute_usd": 0.000117, "llm_tokens": 0, ...}` -- `0.39` is the real
  summed `ToolRun.duration_seconds` for that scan's real bandit/semgrep/gitleaks/trivy/osv-scanner
  runs. `GET /costs/summary?days=30` against the real dev database (15 real scans accumulated across
  this whole project's history -- OWASP NodeGoat, terragoat, VAmPI, nodejs-goof, and others) returned a
  real aggregate ($0.33 total, 18m37s of real summed scanner compute time). The `/app/costs` web page
  was opened in a real browser against the real running web app and API (`localhost:3010`, not
  `127.0.0.1:3010` -- the difference is a real CORS origin mismatch this exposed, not a bug in the
  page itself, since `BULWARK_CORS_ORIGINS` only allow-lists `localhost:3010`), showing the identical
  15-scan, $0.33 breakdown with working "Last 7d/30d/90d" window switching. The new Grafana panels
  (`bulwark_estimated_cost_usd` as a stat and a bargauge split by component) were confirmed rendering
  the same live Prometheus data after a Grafana restart picked up the updated dashboard JSON.
- **The `reap_stale_scans` fix, against real Postgres, connected as the real worker's own
  `bulwark_worker` role** -- not `bulwark_app`, which does nothing to prove the bug since the worker
  never connects as it. Two organizations, each with one real "stuck" scan row; calling
  `reap_stale_scans` exactly the way `core.tasks.maintenance_task` really does (no org context set on
  the caller's own session beforehand) correctly reaped both, one per org, via the internal
  `set_session_org` loop -- the old implementation would have reaped neither, since the query it ran
  had no org context at all and RLS reads that as "nothing," not "everything."

## Verified

- 1591 unit tests passed, 1 skipped (up from Week 49b's 1583); new: `test_observability_cost.py` (6
  tests), two new tests in `test_observability.py` for the `CostSummary` Prometheus collector (a happy
  path against a real SQLite-backed session, and an unreachable-DB path). `black --check .`,
  `ruff check .`, and `mypy` (core+api, 197 files) all clean.
- 215 frontend tests passed (up from 211), `tsc --noEmit` clean; new: `cost-dashboard.test.tsx` (4
  tests: empty state, a real-shaped response rendering totals and a linked row, window switching
  refetching with the right `days` value, and an error state).
- The Helm chart: `helm lint helm/bulwark` clean; `helm template` output validated against the real
  kind cluster's own API schema via `kubectl apply --dry-run=client`, including the KEDA
  `ScaledObject` CRD.
- 2 new integration tests against real Postgres/real RLS, connected as `bulwark_worker`:
  `tests/integration/test_maintenance_rls_docker.py`, both passing; no regressions in the existing
  `test_tenancy_rls_docker.py`/`test_data_protection_rls_docker.py` against the same database.
- Coverage: 90.62% (`pytest tests/unit`), above the project's enforced 80% gate.

## What this does NOT prove (read before relying on it)

- **The Helm chart's simplifications are real, not cosmetic.** No mTLS to Postgres, OpenBao in dev
  mode only, a privileged DinD sidecar instead of socket-proxy's narrow allowlist, and a
  single-node-only `hostPath` workdir volume by default -- see ADR-0036's own list and
  `helm/bulwark/README.md` for exactly what each means for a real production deployment.
- **k6's absolute numbers are this one developer laptop's, not a provisioned server's.** It was
  running a `kind` cluster, a browser, and the rest of this session's work at the same time as the
  load test. The *relative* findings (single-process uvicorn cannot serve 500 concurrent users; a
  15-connection pool across 6 processes needs Postgres's own `max_connections` raised to match) are
  real engineering facts independent of the hardware; the specific p50/p95 milliseconds are not a
  capacity-planning number for any other machine.
- **The cost estimate is relative visibility, not a bill.** Blended per-token pricing (no real
  input/output split), no historical model attribution, and placeholder $/compute-second and
  $/token defaults that need overriding with a deployment's own real figures -- all disclosed in
  `core/observability/cost.py`'s own docstring and repeated on the dashboard page itself.
- **The Prometheus cost metric covers the default org only**, consistent with the rest of
  `core/observability/metrics.py` and this project's self-hosted, single-tenant scope -- not a
  cross-tenant SaaS billing figure.
- **The nftables egress backstop (Week 49b) and gVisor/Firecracker sandboxing (Week 46) are untouched
  by this week's work** and remain exactly as previously disclosed; nothing here closes those gaps.
