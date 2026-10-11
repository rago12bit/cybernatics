# ADR-0035: DAST -- ownership verification, scope-enforcing egress, safe scanning tiers, SAST/DAST correlation

Status: Implemented (2026-10-01), Week 49 (plan §22.4); egress-proxy wiring completed in a Week 49b
follow-up (2026-10-01), a standalone task inserted before tagging `v1.5.0` specifically because the
plan's own M10 milestone claims "scope enforced at the network layer" and that wasn't true yet.

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

### Scope enforcement is two independent layers: one is now in the loop, the other is still a disclosed gap

`core/dast/proxy.py` is a real allow-list forward proxy (CONNECT tunneling for HTTPS, plain HTTP
relaying) -- exact-host-match only, reporting every refused attempt as structured JSON.
`core/dast/egress.py` denies all direct 80/443 in a runner's network namespace except to that proxy,
via the same nftables-sidecar mechanism `core.fixagent.egress` already uses for Week 46's
fix-verification sandbox. Week 49 built and verified both independently but wired neither into an
actual campaign; Week 49b (below) wires the proxy in. The nftables half remains exactly as it was:
unit-tested only, never loaded into a real namespace, Linux-only.

**Week 49b: the proxy is now in the campaign runner's actual path.** `core.dast.pipeline.
run_dast_campaign_job` starts a `core.dast.proxy.BackgroundProxy` -- a real `AllowListProxy` on a
background thread, scoped to exactly the campaign's one verified host -- before invoking either
adapter, and tears it down after, on every exit path including a tool error (`core/dast/proxy.py`'s
`BackgroundProxy` is a context manager for exactly this). `core.dast.adapters.zap.run_zap_baseline`
and `nuclei.run_nuclei` both gained a `proxy: ProxyConfig | None` parameter: ZAP is pointed at it via
`-z "-config network.connection.httpProxy.enabled=true -config network.connection.httpProxy.host=...
-config network.connection.httpProxy.port=..."`, and Nuclei via its native `-proxy` flag; both
containers get `--add-host host.docker.internal:host-gateway` so the hostname resolves identically
on macOS Docker Desktop and real Linux (Docker Engine >= 20.10).

Two real findings came out of making this actually work, not just compile:

- **ZAP's config keys had moved.** The legacy `network.connectionParam.proxyChain*` keys (what most
  ZAP documentation and forum answers still reference) are silently ignored by the Network add-on
  this image ships; a real `zap-baseline.py` run with those keys showed zero traffic reaching a real
  running proxy. Inspecting the add-on's own compiled `ConnectionOptions.class` inside the shipped
  `network-beta-*.zap` file found the keys it actually reads: `network.connection.httpProxy.
  {enabled,host,port}`. A second live run with the corrected keys showed the real scan's CONNECT to
  the target succeed through the proxy, and ZAP's own background "check for updates"/telemetry calls
  (`news.zaproxy.org`, `cfu.zaproxy.org`, `tel.zaproxy.org`) correctly refused with 403 -- proof the
  enforcement is real, not just a passthrough, and that the scan completes and reports findings
  normally regardless.
- **Nuclei's default templates legitimately contact third parties that are not the target.** A real
  run (before the proxy was scoped down) showed `dns`-type templates querying whatever DNS resolver
  the container uses, and an `http`-type template (`rdap-whois`) calling `rdap.verisign.com` to look
  up the target's WHOIS record -- by design, not a bug, and not covered by the `dos`/`fuzz`/
  `intrusive`/`bruteforce` tag exclusions Week 49 already had. A single-host allow-list can't permit
  this without widening the scope past the one host ownership verification actually covers, so
  `core.dast.adapters.nuclei.ALLOWED_PROTOCOL_TYPES = ("http",)` now restricts every campaign run to
  `-pt http` unconditionally, the same kind of non-negotiable restriction as `EXCLUDED_TAGS`. This is
  arguably a correction to Week 49's own curation, caught only once egress was actually constrained
  enough to expose it.

Both fixes are proven by `tests/integration/test_dast_pipeline_egress_proxy_live.py` (new): the real
`run_dast_campaign_job`, against real Postgres, running a real `zap-baseline.py` through a real
`BackgroundProxy` against a real local HTTP target, asserting the campaign completes with real
findings *and* that the blocked call-home attempts land as both a `tool_runs` row (`"egress-proxy"`)
and an audit-log entry (`dast.campaign.egress_blocked`) -- Task 4 of this follow-up, so a blocked
attempt during a real campaign is visible to an operator instead of only appearing in a log line
nobody reads.

**What is still NOT done.** This wiring is cooperative, not a kernel-level backstop: it works because
ZAP and Nuclei were configured to use the proxy and chose to honor that configuration. Nothing at the
network-namespace level yet stops a scanner container that ignored its proxy settings entirely (a
compromised scanner, a future adapter that doesn't take a `proxy` argument, a template with its own
raw-socket logic) from reaching the internet directly -- that backstop is exactly what `core.dast.
egress`'s nftables ruleset is for, and it has still never been loaded into a real network namespace,
on any machine, for this feature. Linux-only, the same disclosed boundary as Week 46's own egress
work; closing it needs a real Linux host or CI runner, not this (macOS) dev machine.

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
one is not. Week 49 left the link API and CLI only; the "Add web target" screen offers it since
2026-10-12, listing the organization's git and archive projects.

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

### Amendment (2026-10-08): Nuclei's egress, templates and timeouts

Measured against OWASP Juice Shop v17.3.0 with Nuclei v3.11.1:

- **Interactsh went around the proxy.** By default Nuclei registers with a public interactsh server
  and plants its URLs in payloads; a run held an open connection to `oast.me` (178.128.209.14)
  straight from the container. That is a third party, and the target is asked to call it. Every run
  now passes `-ni`; the OAST templates are excluded with it, so blind out-of-band issues are not found.
- **Templates came from GitHub on every run, also around the proxy.** The upstream image ships none
  (about 86 MB, 14,036 files, fetched each time). `bulwark/nuclei:3.11.1` (docker/nuclei) bakes in
  templates v10.5.0 and runs with `-duc`; it lists 11,278 HTTP templates with networking off.
- **A timeout lost everything.** `run_nuclei` now reads output as it comes; a run that hits its
  deadline raises `NucleiTimeout` carrying the findings reported so far, the campaign keeps them and
  ends `partial` (so it closes nothing), and the container is killed by name -- stopping the `docker`
  client alone left it running. ZAP's adapter kills its container the same way.

- **Nuclei stalled through the proxy (fixed 2026-10-12).** Through `BackgroundProxy` it stopped
  making progress after about five minutes (17 findings, then 75-81 tunnels open with no traffic for
  over 30 minutes), while the same scan without the proxy finished in 111 s. Every stuck goroutine
  was in rawhttp 0.1.91's CONNECT dialer (raw/unsafe templates; the rest of Nuclei uses Go's own
  client). That code reads the reply's status line and then peeks 5 bytes, to skip a repeated status
  line some devices send. The proxy replied `HTTP/1.1 200 Connection Established\r\n\r\n`, which
  leaves only 2. The target sends nothing until the client speaks, so the peek waited forever with
  no deadline. It was not Docker Desktop: the same stall happened with the proxy in a container on a
  plain Docker network (16 findings, 98%, 28 minutes). The reply now carries a `Proxy-Agent`
  header. Through the proxy, Nuclei finished against Juice Shop in 101 s and 108 s (two runs), 17
  findings each; its attempts to reach `www.rdap.net` and `login.microsoftonline.com` were refused,
  as they should be. Direct, it found 19.
- **The two missing findings were the proxy's, not the refusals (fixed 2026-10-12).** Diffed
  against a direct run on the same target, the missing two were `robots-txt-endpoint` and
  `security-txt`: plain GETs to the allowed host. The plain-HTTP relay rewrote only a connection's
  first request and then piped raw, so a request reusing the connection (keep-alive) reached the
  target still in absolute form (`GET http://host/robots.txt`), which Juice Shop answered with its
  app page -- and it was never checked against the allow-list, and the client's Host header always
  went through untouched. The TCP connection was pinned to the allowed host, but a shared front end
  routes by Host header. Now one request per plain connection: origin form, Host set to the allowed
  target, `Connection: close` both ways, so the next request comes on a new connection and is checked.
  Through the proxy: 19 findings, the same 19 as direct, in 105 s; the proxy now also refuses
  requests naming `oast.me`, `interact.sh`, `localhost` and random hosts that host-header and SSRF
  templates send, which the raw pipe used to carry.

## What is NOT done

- The egress proxy is now wired into the campaign runner (Week 49b), but only at the application
  layer -- a scanner's own cooperation, not a network-namespace-level guarantee. The nftables policy
  that would make bypassing it a dropped packet rather than a policy violation has never been loaded
  into a real network namespace on any machine; Linux-only, the same disclosed boundary as Week 46's
  `core.fixagent.egress`.
- A web asset's link to its source project (`linked_source_asset_id`) can only be set when the site
  is registered (on the "Add web target" screen since 2026-10-12, or by API or CLI); there is no way
  to add or change it afterwards without registering again, which resets verification.
- Route extraction (since 2026-10-12) reads the HTTP entrypoints code intelligence finds for
  FastAPI, Flask, Django (the view a urls.py entry names), Express, Next.js and Go's net/http, and
  falls back to the FastAPI/Flask decorator shape when code analysis did not run. Still invisible: a
  Django regex route, a route built from a runtime string, and the prefix an `include()` or a
  mounted router adds -- such a route is matched by its app-relative part only, so a full URL misses
  it. A conservative miss, never a false match.
- Nuclei's own request concurrency could not reach a target through `host.docker.internal` on this
  Docker-Desktop-for-Mac machine -- reproduced directly, a host-networking limitation, not an adapter
  bug (`tests/integration/test_dast_adapters_live.py`'s own docstring has the detail).
