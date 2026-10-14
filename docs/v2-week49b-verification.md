# Week 49b verification -- wiring the DAST egress proxy into campaign execution (plan §22.4 follow-up)

Honest record of what was built, run, and measured. This is a standalone task inserted between Week
49 and Week 50, not a numbered plan week: the plan's own M10 milestone (tag `v1.5.0`) claims "scope
enforced at the network layer" for DAST, and Week 49 itself disclosed that the egress proxy it built
was not actually wired into campaign execution -- so that claim wasn't true yet. See
[ADR-0035](adr/0035-dast-scanning.md) for the design detail; this doc is the evidence.

## What was built

- `core/dast/proxy.py`: a new `ProxyConfig` dataclass and `BackgroundProxy` class -- a real
  `AllowListProxy` run on its own thread and event loop, usable as a context manager from a
  synchronous caller. Extracted from (and now shared with) the test fixture
  `tests/integration/test_dast_proxy_live.py` already used.
- `core/dast/pipeline.py`: `run_dast_campaign_job` now starts a `BackgroundProxy` scoped to exactly
  the campaign's one verified host before running either scanner, and tears it down after, on every
  exit path including a tool error. Blocked egress attempts are recorded as a `tool_runs` row
  (`"egress-proxy"`) and an audit-log entry (`dast.campaign.egress_blocked`).
- `core/dast/adapters/zap.py`, `adapters/nuclei.py`: both adapters gained a `proxy: ProxyConfig |
  None` parameter, pointing the real tool at the real proxy when a campaign supplies one.
- `core/dast/adapters/nuclei.py`: a new unconditional restriction, `ALLOWED_PROTOCOL_TYPES =
  ("http",)` (`-pt http`), alongside the existing `EXCLUDED_TAGS` -- see "What this found" below.

## Validated against real, live things -- not mocks

- **The ZAP proxy-config keys were wrong, and a real test proved it.** The legacy `network.
  connectionParam.proxyChain*` keys (most ZAP documentation still shows these) produced zero traffic
  at a real running `BackgroundProxy` when used with a real `zap-baseline.py` run against
  `https://example.com/`. The add-on's own compiled `ConnectionOptions.class`, extracted from the
  shipped `network-beta-*.zap` file inside the real `ghcr.io/zaproxy/zaproxy:stable` image, gave the
  keys it actually reads: `network.connection.httpProxy.{enabled,host,port}`. A second real run with
  the corrected keys showed the proxy's own log recording a successful `CONNECT example.com:443`
  (the allowed host) and three refused `CONNECT` attempts to `news.zaproxy.org`, `cfu.zaproxy.org`,
  and `tel.zaproxy.org` -- ZAP's own background telemetry, correctly blocked -- while the scan itself
  still completed and produced 11 real findings.
- **Nuclei's default templates legitimately reach third parties, found by a real run.** Running the
  existing (pre-Week-49b) `run_nuclei` invocation for real against `https://example.com/` -- with
  only the already-shipped `EXCLUDED_TAGS` applied -- produced real DNS-template findings (an `NS`,
  `DNSSEC`, `MX`, `DMARC`, `SPF`, `AAAA` lookup, each a genuine DNS query to whatever resolver the
  container uses) and a real `rdap-whois` template finding that called `rdap.verisign.com` directly,
  not `example.com`. Once the campaign's proxy was scoped to exactly `example.com`, the same
  unmodified invocation failed outright (`"no templates provided for scan"`, because its own
  template-list fetch from GitHub was also blocked) -- a real, live demonstration that a single-host
  allow-list and Nuclei's default template set are incompatible without a further restriction. Adding
  `-pt http` (confirmed against Nuclei's own `-h` output: `-pt, -type value[] templates to run based
  on protocol type`) and re-running produced a clean, successful scan through the proxy with no
  blocked attempts other than template-irrelevant noise.
- **The full campaign pipeline, through the real proxy, against real Postgres.** New:
  `tests/integration/test_dast_pipeline_egress_proxy_live.py`. The real `run_dast_campaign_job` (not
  a stand-in), with only the live DNS/HTTP ownership re-check stubbed to `ok=True` -- the same
  deliberate, disclosed exception Week 49's own correlation test made, since a synthetic local target
  can never pass a real DNS TXT or `.well-known` check, and that check's own real pass/fail behavior
  is separately and fully proven in `tests/unit/test_dast_ownership.py` and `tests/integration/
  test_asset_verification_rls_docker.py`. Everything else is real: a real Postgres-backed `Scan` row,
  a real `BackgroundProxy`, a real `zap-baseline.py` run against a real local `http.server` target
  through that proxy, real `findings` rows persisted, and both a real `tool_runs` row and a real
  `audit_entries` row for the campaign's own blocked egress attempts (ZAP's background telemetry
  calls, exactly as seen in the adapter-level test above). The campaign completed with real findings
  every run.

  **Correction (2026-10-14): until then this test never reached its target.** It named the target
  `host.docker.internal`, which the proxy -- running on the host, not in a container -- cannot
  resolve. Every request ZAP sent through the proxy failed there (4 failed lookups, 0 requests at
  the target, measured on 2026-10-14), and the "real findings" were about the proxy's error pages.
  What the test did prove is unchanged: ZAP's traffic goes through the proxy, and the blocked
  call-home attempts are recorded as a `tool_runs` row and an audit entry. What it did not prove
  until 2026-10-14 is a campaign scanning its target through the proxy. The test now names the target
  `dast-target.test`, resolved to this machine for the proxy only, and asserts the target was asked
  for `/` (4 requests reach it); it runs in CI as the `dast-live` job, which passed on its first run.
  The manual ZAP run against `https://example.com/` above (an allowed `CONNECT` and 11 findings) was
  real and is not affected.
- **Shutdown correctness.** The first live run surfaced a real `asyncio` cleanup bug: closing a
  `BackgroundProxy` while a scanner's connection was still mid-relay abandoned that connection's task
  when the background thread's event loop was torn down, producing a `Task was destroyed but it is
  pending` / `Event loop is closed` warning. Fixed by draining any still-pending relay tasks (with a
  2-second bound) before the thread's event loop closes. Re-ran the same live ZAP-through-proxy
  scenario after the fix with no warnings, and the existing `test_dast_proxy_live.py` suite passes
  clean under `-W error::pytest.PytestUnhandledThreadExceptionWarning`.
- **No regressions.** `tests/integration/test_asset_verification_rls_docker.py`, `test_dast_sast_
  correlation_live.py`, and `test_tenancy_rls_docker.py` all still pass against the same real
  Postgres instance used for the new test above.

## Verified

- 1583 unit tests passed, 1 skipped (up from Week 49's 1578); new: 5 tests across `test_dast_zap_
  adapter.py` and `test_dast_nuclei_adapter.py` covering the argv built with and without a proxy, and
  a regression guard that `ALLOWED_PROTOCOL_TYPES` stays `{"http"}`. `black --check .` (382 files
  unchanged), `ruff check .`, and `mypy` (core+api, 196 files) all clean.
- 6 integration tests against real Postgres/real Docker/real sockets, all passing: the 3 existing
  `test_dast_proxy_live.py` tests (now sharing `BackgroundProxy` instead of a duplicated fixture), the
  2 existing `test_dast_adapters_live.py` tests (unchanged, still pass with the new `-pt http`
  restriction in place), and the 1 new `test_dast_pipeline_egress_proxy_live.py` test.
- Coverage: 90.71% (`pytest tests/unit`), above the project's enforced 80% gate.

## What this does NOT prove (read before relying on it)

- **This is cooperative scope enforcement, not a kernel-level guarantee.** The proxy wiring works
  because ZAP and Nuclei were configured to use it and chose to honor that configuration. Nothing at
  the network-namespace level yet stops a scanner container that ignored its proxy settings (a
  compromised scanner, a future adapter that skips the `proxy` argument, a template with its own
  raw-socket logic) from reaching the internet directly. `core.dast.egress`'s nftables ruleset is
  exactly the backstop for that case, and it has still never been loaded into a real network
  namespace, on any machine, for this feature -- Linux-only, the same disclosed boundary as Week 46's
  own egress work.
- **DNS resolution itself is not proxied or restricted here.** The egress proxy only sees HTTP(S)
  traffic; a scanner's own DNS queries (for the target's hostname, or -- before the `-pt http` fix --
  for a DNS-type template) go out however the container's network is configured, unaffected by this
  week's work. Restricting DNS at the network layer is also the nftables ruleset's job, not this
  proxy's.
- **The `-pt http` restriction narrows what Nuclei can report in a campaign.** Any DNS/SSL/TCP/
  whois/headless-type template -- not just the third-party-contacting ones discovered this week -- is
  now excluded from every DAST campaign, not only the specific `rdap-whois`/DNS templates that caused
  the problem. This is a deliberate, disclosed trade of coverage for scope correctness, not an
  oversight.
- **Linking a web Asset to its source project is still API/CLI-only** (unchanged from Week 49) --
  not something this follow-up touched.
