# ADR-0036: Scale -- Helm chart with KEDA autoscaling, k6 load testing, cost-per-scan dashboard

Status: Implemented (2026-10-01), Week 50 (plan §23).

## Context

Everything Bulwark has run on through Week 49 is a single Docker Compose stack on one machine.
Week 50 is the plan's own "Scale" week: package the product for Kubernetes with autoscaling on real
demand, measure its actual capacity under load rather than assuming it, and give an operator
visibility into what a scan costs. All three turned up real, fixable problems that only existed
because nobody had ever generated real concurrent load or a real Kubernetes deployment before.

## Decisions

### A Helm chart, built from scratch, with two deliberate simplifications and one real architectural split

`helm/bulwark/` packages Postgres, Redis, S3-compatible object storage, OpenBao, a migrate Job, the
API, the Celery worker, a new single-replica Celery beat, and the web app. Live-verified end to end
against a real `kind` cluster: every pod reaches Ready, and a real KEDA installation scales the worker
Deployment from 1 to 5 replicas on a real 3,000-task Redis backlog, draining it in under 30 seconds,
then scaling back to 1 once idle.

Two things docker-compose.yml's dev stack has were deliberately not reproduced, both disclosed in
`helm/bulwark/README.md`:
- **Postgres has no mTLS.** The custom `bulwark/postgres:16-pgvector` image needs client certificates
  a chart would have to generate and distribute itself (cert-manager or an equivalent CA Job); the
  default here is the plain upstream `pgvector/pgvector:pg16` image with password auth, matching the
  substitution this repo's own CI already makes for its RLS tests. RLS enforcement itself
  (`FORCE ROW LEVEL SECURITY`, ADR-0013) is unaffected either way.
- **The shared upload workdir is a `hostPath` volume.** The API writes an uploaded archive and the
  worker reads it by the same path (`core/config.py`'s `BULWARK_WORKDIR`); a `hostPath` PersistentVolume
  only works when both pods land on the same node, true by construction on a single-node cluster like
  `kind`, false on a real multi-node one. `workdir.existingClaim` lets an operator supply a real
  ReadWriteMany-backed PVC (NFS, EFS, Longhorn) instead.

The one real architectural change, not a simplification: **Celery's embedded beat (`-B`) had to be
split into its own fixed-at-1-replica Deployment.** `docker-compose.yml`'s own comment already says
why -- run exactly ONE process with `-B`, or scheduled jobs (feed updates, retention housekeeping,
crypto-shredding) fire once per replica instead of once. That constraint was compatible with compose's
single worker container; it is not compatible with a Deployment KEDA might scale to 5 replicas. The
worker's own scanner-launching capability (`docker run`, via `core.dast`'s and `core.scan`'s existing
code) needed a Kubernetes-native stand-in for `docker-compose.yml`'s `socket-proxy` service, since a
Kubernetes node doesn't expose a host Docker socket the way a compose host does: `templates/
worker.yaml` runs a privileged `docker:27-dind` sidecar in the worker Pod instead, a real, commonly
used pattern (the same one CI systems use to run Docker-based jobs on Kubernetes) -- with the real,
disclosed trade-off that it needs a broader privilege than socket-proxy's deliberately narrow API
allowlist.

Two real bugs surfaced only by actually deploying and driving the chart, not by writing it:

- **A Helm pre-install hook Job ran before the chart's own Secret existed.** `templates/migrate-job.
  yaml`'s first version was a `pre-install,pre-upgrade` hook; Helm creates hook resources before its
  normal resource-ordering pass (which is what creates the Secret), so the very first `helm install`
  failed with `secret "bulwark-secrets" not found`. Fixed by making it a plain Job with its own
  `wait-for-postgres` init container instead of relying on hook ordering at all -- Secrets and PVCs are
  created before Jobs/Deployments in Helm's normal ordering, which is what the chart actually needed.
- **KEDA's Redis trigger needs a fully-qualified address, not the short Service name.** `bulwark-redis`
  alone resolved from the `keda-operator` Pod's own namespace (`keda`), not this release's namespace --
  confirmed live as `dial tcp: lookup bulwark-redis: no such host` in the `ScaledObject`'s own events.
  Fixed by qualifying it as `bulwark-redis.<release-namespace>.svc.cluster.local`.
- **Celery beat's first implementation was still a worker, not a scheduler.** Splitting `-B` out
  (above) first ran `celery worker -B -P solo -c 1` for beat, reasoning in its own comment that "this
  process runs no task workers of its own" -- which was false: `worker -B` is still a worker. This was
  caught directly during the KEDA demo: a 100-task backlog, pushed onto Redis while the real worker
  Deployment was deliberately paused at 0 replicas to build an isolated backlog to scale from, quietly
  drained to 0 anyway -- beat's own solo worker was consuming it one task at a time, and KEDA never saw
  the depth it was supposed to react to. Fixed by using Celery's dedicated `beat` subcommand (scheduler
  only, never a consumer) instead.

### k6 load testing found two real capacity bugs that had nothing to do with the test scripts

`k6/scan-submission.js` (50 concurrent virtual users hitting `POST /scans` for 20s) and `k6/
browse-results.js` (500 concurrent VUs ramped over 15s, held 30s, browsing `/scans`, `/scans/{id}`,
and `/scans/{id}/findings`) both run against the real docker-compose dev stack, not a mock server.
Final measured numbers (`docs/v2-week50-verification.md` has the full k6 output): scan submission
p50=380ms, p95=675ms, ~122 req/s, 99.84% success; browsing p50=696ms, p95=1.18s (successful requests),
~127 req/s, 96.75% success.

Getting to those numbers surfaced two real, previously-invisible bugs, because nothing had ever put
real concurrent load on this API before:

- **A single uvicorn process cannot serve 500 concurrent requests.** The first `browse-results.js` run
  against an unmodified `docker-compose.yml` mostly timed out at k6's own 30s HTTP timeout -- p50 was
  ~31 seconds, not milliseconds. The API ran as one uvicorn process with no `--workers` flag; every
  synchronous request handler (`api/deps.py`'s `db()` dependency) runs via Starlette's
  `run_in_threadpool`, whose default AnyIO thread-pool capacity is nowhere near 500. Fixed by adding
  `--workers 4` to `docker-compose.yml`'s `api` command -- safe because `core/events.py`'s scan-progress
  relay is Redis pub/sub, not in-process memory, so a client's WebSocket connection landing on a
  different worker process than the one that published an event still receives it.
- **SQLAlchemy's default connection pool (5 + 10 overflow) was never sized for this concurrency, and
  neither was the fix tried first.** Raising it to `pool_size=20, max_overflow=30` (compensating for
  the newly-added 4 processes) immediately hit a second ceiling: 4 processes × 50 connections each
  attempted 200 total against Postgres's own default `max_connections=100`, failing as "FATAL: sorry,
  too many clients already" on 71% of requests. Shrinking the per-engine pool alone (12/engine = 48
  total) traded back the other way -- requests queued for a connection and hit the pool's own 30s
  checkout timeout again. The real fix needed both halves: Postgres's own `max_connections` raised to
  300 (`docker-compose.yml`'s `postgres` service), and a `core/persistence/db.py` default
  (`pool_size=15, max_overflow=10`, both env-overridable via `BULWARK_DB_POOL_SIZE`/
  `BULWARK_DB_MAX_OVERFLOW`) sized to add up sensibly against that raised ceiling across 4 API
  processes, the worker, and beat together.

Two more real bugs were found and fixed along the way, both pre-existing and unrelated to this week's
own code, surfaced only because getting the dev stack healthy enough to run k6 against required
actually exercising paths nothing had exercised in a while:

- **OpenBao's own healthcheck used `localhost`, which resolves to `::1` first** in this image, but
  `-dev-listen-address` only binds the IPv4 `0.0.0.0:8200` -- the healthcheck failed every time even
  against a genuinely healthy, unsealed server, which blocked the `api` service from ever starting at
  all (`depends_on: condition: service_healthy`). Fixed by pointing the healthcheck at `127.0.0.1`
  instead.
- **Three per-service Postgres roles (`bulwark_api`/`bulwark_worker`/`bulwark_fixagent`, migration
  0020) were missing from this dev database**, even though Alembic considered itself at head --
  historical drift from an earlier manual debugging session, not something this week's work caused,
  but something it had to notice and fix (re-running migration 0020's own role-creation SQL directly)
  before the API could authenticate at all.

### Cost per scan: an estimate, computed on demand, never stored

`core/observability/cost.py` combines two numbers this project already tracked -- `ToolRun.
duration_seconds` (every scanner's own wall-clock time, summed per scan) and `Scan.llm_tokens_used`
(every real LLM call's token count) -- into an estimated USD figure, using a small, explicitly
placeholder pricing table (`MODEL_PRICING_USD_PER_1K_TOKENS`, `DEFAULT_COMPUTE_USD_PER_SECOND`), both
overridable per deployment via `BULWARK_LLM_COST_PER_1K_TOKENS_USD`/
`BULWARK_COMPUTE_COST_PER_SECOND_USD`. The cost is computed fresh on every call (`GET /scans/{id}/
cost`, `GET /costs/summary?days=N`) rather than written once at scan-completion time, because a scan's
LLM spend keeps growing after the scan job itself finishes -- remediation suggestions, hypotheses, and
copilot messages are all requested later, independently of the scan pipeline.

Disclosed, not hidden, imprecision: `Scan.llm_tokens_used` is a combined input+output count (`core.
llm.client.Completion.tokens` sums them before this project ever sees the split), so pricing is one
blended $/token figure per model, not real provider pricing's separate and usually very different
input/output rates; a token count carries no record of which model it was spent against if
`BULWARK_LLM_MODEL` changes mid-month, so every token is always priced at whatever model is configured
*now*; and the whole figure is explicitly an internal visibility estimate, not a reconcilable bill.

Surfaced in three places: a new web page (`/app/costs`, linked from the app shell's own nav bar) with
per-window totals and a per-scan breakdown table; two new Prometheus panels on the existing Grafana
dashboard (`bulwark_estimated_cost_usd{component="compute"|"llm"}`, read from Postgres at scrape time
the same way `QueueDepth` already reads Redis); and the same two API endpoints the web page itself
calls. The Prometheus metric is scoped to the bootstrap default org only, consistent with every other
metric in `core/observability/metrics.py` (none of them carry an org label) and with this project's own
stated scope as a self-hosted, single-tenant deployment, not a multi-tenant SaaS -- a cross-org
aggregate would need `set_session_org` called once per org, since RLS hides every other org's rows
from a session with no org context set.

## What is NOT done

- The Helm chart doesn't reproduce Postgres mTLS, OpenBao's production (non-dev) mode, the
  verified-fix agent (Temporal + `fixagent-worker`), or the observability stack (Prometheus/Jaeger/
  Grafana) -- all disclosed cuts, not oversights, in `helm/bulwark/README.md`.
- The worker's DinD sidecar needs a privileged container, a broader security surface than
  socket-proxy's narrow allowlist; `worker.dind.enabled: false` turns it off (and scanning off with
  it) for a cluster policy that forbids privileged Pods.
- `web.publicApiUrl` in the Helm chart's values only reaches server-side code
  (`web/proxy.ts`); the browser-side bundled `API_URL` constant (`web/lib/api.ts`) is baked in at
  image build time via `web/Dockerfile`'s `ARG NEXT_PUBLIC_API_URL`, unaffected by a runtime value.
- The nftables egress backstop from Week 49b and the gVisor/Firecracker sandboxing from Week 46
  remain exactly as disclosed there; nothing in this week's Kubernetes work touches them.
- k6's own numbers were measured on a single developer laptop running this chart's dev stack
  alongside a `kind` cluster, a browser, and everything else this session had open concurrently --
  not a provisioned, isolated load-test target. The relative findings (a single process can't handle
  500 concurrent requests; a 15-connection pool can't either) are real; the absolute throughput numbers
  are this machine's, not a production server's.
