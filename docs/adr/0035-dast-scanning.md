# ADR-0035: DAST -- ownership verification, scope-enforcing egress, safe scanning tiers, SAST/DAST correlation

Status: Implemented (2026-10-01), Week 49 (plan §22.4).

## Context

Everything Bulwark has scanned through Week 48 is something the user handed it directly -- a git
URL, an uploaded archive. A web target is different: it's someone's live, internet-reachable site,
and nothing about possessing a domain name proves the person asking Bulwark to scan it actually
controls it. Scanning it without permission is not a scanning feature, it's an attack. Week 49 is
the whole DAST feature, built around that constraint from the start rather than bolted on after.

## Decisions

### Ownership verification is a live gate, never a cached status

`core/dast/ownership.py` supports two standard proof-of-control methods -- a DNS TXT record at
`_bulwark-challenge.<domain>`, or a fixed file at `/.well-known/bulwark-verification.txt` -- the
same mechanisms CDNs and cert issuers use for the same reason. The critical design choice: a
"verified" status stored in `asset_verifications` is never trusted on its own. Every place that
gates on it -- `POST /assets/{id}/campaigns`, the CLI's `campaign-start`, and the worker's own
`core.dast.pipeline.run_dast_campaign_job` -- re-runs the real DNS/HTTP check at that exact moment.
A domain can be reassigned, a DNS record removed, five minutes after it last passed; a campaign
starting on stale trust is the exact failure mode this is designed to prevent. Verified live: real
DNS/HTTPS lookups against `example.com` (confirmed failing, since no such record exists there), and
the full browser → Next.js → FastAPI → Postgres → DNS path in a real browser session.

### Scope enforcement is two independent layers, and only one of them is wired into campaign execution yet

`core/dast/proxy.py` is a real allow-list forward proxy (CONNECT tunneling for HTTPS, plain HTTP
relaying) -- exact-host-match only, reporting every refused attempt as structured JSON.
`core/dast/egress.py` denies all direct 80/443 in a runner's network namespace except to that proxy,
via the same nftables-sidecar mechanism `core.fixagent.egress` already uses for Week 46's
fix-verification sandbox. Both were built and verified independently: the proxy with real sockets, a
real local HTTP target, and a real CONNECT tunnel to `example.com` over the real network, including
inside the actual `docker/dast-egress-proxy` image; the nftables ruleset with unit tests only --
loading it into a real namespace is Linux-only and wasn't executed on this (macOS) dev machine, the
same disclosed boundary Week 46 already drew.

**What is NOT done**: `core/dast/pipeline.py`'s actual campaign runner calls
`core.dast.adapters.zap.run_zap_baseline`/`nuclei.run_nuclei` as plain `docker run` subprocesses on
the worker host -- it does not yet start them behind the allow-list proxy, or apply the nftables
egress policy to their containers. The scope-enforcement machinery is real and independently proven,
but it is not in the loop for an actual campaign today. Wiring it in means the worker provisioning a
proxy instance per campaign (with that campaign's one verified host as its allow-list) and launching
the scanner containers with `--network=container:<proxy>` plus the nftables sidecar applied to that
shared namespace -- a real piece of remaining work, not a detail.

### Safe-by-default scanning tiers: passive always, active is opt-in and rate-limited

A DAST campaign is a `Scan` row with `source_type="web"` and a new `dast_mode` column
("passive"/"active") -- no new table, because `scans`/`tool_runs`/`findings` already hold everything
a campaign's result is. Passive mode runs ZAP baseline only -- it spiders and observes, never sends
an attack payload. Active mode adds curated Nuclei, with `dos`/`fuzz`/`intrusive`/`bruteforce`
template tags excluded unconditionally in the adapter itself (`core.dast.adapters.nuclei.
EXCLUDED_TAGS`), not as a caller-controlled option -- "active" authorizes probing more thoroughly,
not authorizing degrading the target. Active campaigns are limited to one per asset per 24h
(`core.dast.campaign.check_active_scan_rate_limit`), checked both at campaign creation (API/CLI) and
again by the worker itself before running (defense in depth against two requests racing past the
first check).

Live-verified extensively, with three real bugs found and fixed: ZAP's rule 90004 reporting three
alerts under one shared `pluginid` (fixed the finding-id derivation); Nuclei reporting the same
template against the same URL more than once (fixed by hashing the whole raw record); and the
worker's own rate-limit re-check comparing timestamps in a way that would have made every active
campaign instantly rate-limit itself under SQLite's naive-datetime behavior (fixed by excluding the
current scan by id instead of by timestamp equality). The full pipeline -- live ownership re-check,
rate limiting, real ZAP+Nuclei execution, correlation, persistence, issue sync, audit logging -- was
run end to end against real Postgres with RLS.

### SAST/DAST correlation needs an explicit link between a live site and its source, because nothing else provides one

A `web` Asset (what a DAST campaign runs against) and the git/archive Asset for the same
application's source (what a SAST scan runs against) are different rows with different identities --
nothing in the existing schema connects "this live site" to "this repository." `assets.
linked_source_asset_id` is that explicit, optional, same-org-enforced link. Without it, correlation
has nothing to check against and does nothing, silently -- a missing confirmation is correct; a wrong
one is not. The registration UI doesn't expose setting this link yet (API and CLI only) -- a
disclosed scope cut.

The "code intelligence" matching a DAST finding's route to source is a small `ast`-based extractor
(`core/dast/routes.py`) recognizing the FastAPI/Flask decorator shape (`@app.get("/path")`,
`@app.route(...)`) -- verified live against this project's own 1700+ line `api/main.py` (44 real
routes found, including every route this week's own work added). It runs as part of every ordinary
SAST scan (`core.pipeline._extract_route_map`, best-effort, never fails a scan) and the route map is
persisted on the `Scan` row, since nothing else keeps a scan's source around afterward.
`core/dast/correlate.py` matches a DAST finding's route (via the route map) and CWE (via
`core.correlation.engine.cwe_family`, the same grouping the ordinary cross-tool correlator already
uses) against existing SAST findings near that route's handler, marking the matching `Issue`
`confirmed_at_runtime`. Verified live end to end: a real bandit scan of a real vulnerable Flask app
(CWE-78 command injection) produced a real route map in real Postgres, and a DAST finding on the
same route/CWE correctly confirmed the right Issue.

## What is NOT done

- The scope-enforcing egress proxy and nftables policy (Week 49 task 2) are built and independently
  verified, but not yet wired into the actual campaign runner -- see task 2's section above.
- The nftables ruleset itself has never been loaded into a real network namespace on any machine;
  Linux-only, the same disclosed boundary as Week 46's `core.fixagent.egress`.
- Registering a web asset's link to its source project (`linked_source_asset_id`) is API/CLI-only;
  the "Add web target" screen doesn't expose picking one yet.
- Route extraction recognizes one decorator shape (FastAPI/Flask-style); Django's `urls.py` table,
  non-Python frameworks, and routes built from runtime strings are invisible to it -- a conservative
  miss, never a false match.
- Nuclei's own request concurrency could not reach a target through `host.docker.internal` on this
  Docker-Desktop-for-Mac machine -- reproduced directly, a host-networking limitation, not an adapter
  bug (`tests/integration/test_dast_adapters_live.py`'s own docstring has the detail).
