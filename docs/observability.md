# Observability: logs, traces and metrics

Everything here works without any extra service. The dashboard and trace viewer are optional.

## Structured logs

The API and the worker write **one JSON object per line** to stderr:

```json
{"ts": "2026-09-25T18:34:55.960+00:00", "level": "INFO", "logger": "core.scan", "message": "tool finished",
 "scan_id": "fc44a2ae-185d-40a9-971f-113fce2c61b9", "tool": "gitleaks", "trace_id": "7b97e4…", "span_id": "…",
 "status": "ok", "findings": 0, "duration_s": 3.5}
```

- **`scan_id` is on every line that belongs to a scan**, including lines from the parallel scanner threads. It travels in
  a context variable, so code does not pass it around. API request lines carry it when the path names a scan.
- `trace_id` and `span_id` appear when a trace is active, so a log line leads to its trace and back.
- Set `BULWARK_LOG_FORMAT=text` for human-readable lines, `BULWARK_LOG_LEVEL=DEBUG` for more.
- Secrets that reach a log message or an exception are scrubbed with the detector the LLM layer uses. A newline in a
  message cannot forge another log line (it is JSON-escaped). Request lines log the route template
  (`/scans/{scan_id}`), never raw paths or query strings, which can carry search text.
- Implemented with the standard library rather than structlog: one small formatter, no new dependency.

## Traces (OpenTelemetry)

Set `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP over HTTP) on the worker and the API to export traces. Without it, nothing
is exported and spans cost almost nothing. A failing exporter never fails a scan.

One scan is one trace, `scan`, with these children:

```
scan  (scan_id, status, findings)
├─ ingest            clone / copy and sanitise the source
├─ reachability
├─ tools             the parallel section
│   ├─ tool.semgrep    tool, image, status, findings, exit_code
│   ├─ tool.gitleaks
│   ├─ tool.trivy
│   └─ tool.osv-scanner
├─ correlate         raw and unique counts
├─ finalize          taxonomy, risk score, redaction
└─ persist
```

The tool spans start within milliseconds of each other: the waterfall shows the scanners running in parallel and
which one sets the scan's duration. A failed or timed-out scanner marks its span as an error.

Not covered: the API request that queued the scan is a separate trace (context is not propagated through the queue),
and with `--distributed` (Celery task per tool) tool spans are not linked to the scan trace.

## Metrics (Prometheus)

The worker serves `/metrics` on port 9101 (`BULWARK_METRICS_PORT`, `0` disables; `BULWARK_METRICS_ADDR`, loopback by
default, `0.0.0.0` in the compose file). It is **unauthenticated and not published to the host**: only containers on
the compose network reach it. Do not expose it publicly.

| Metric | Type | Labels |
|---|---|---|
| `bulwark_scans_total` | counter | `status` = completed, partial, failed |
| `bulwark_scan_duration_seconds` | histogram | |
| `bulwark_scans_in_progress` | gauge | |
| `bulwark_tool_runs_total` | counter | `tool`, `status` = ok, error, timeout, skipped |
| `bulwark_tool_duration_seconds` | histogram | `tool` |
| `bulwark_findings_total` | counter | `severity` |
| `bulwark_queue_depth` | gauge | read from Redis at scrape time |

Labels come from fixed sets (anything else becomes `other`), never a scan id or path, so cardinality is bounded. All
series exist from the first scrape.

**Limits:** counters are per worker process and reset when it restarts (Prometheus handles resets in `rate` and
`increase`); run more than one worker and Prometheus needs to scrape each. `bulwark_findings_total` counts every scan,
so re-scanning the same code counts its findings again.

## Dashboard and trace viewer

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318 docker compose --profile observability up -d
```

| Service | URL | |
|---|---|---|
| Grafana | http://localhost:3001 | provisioned "Bulwark overview" dashboard; anonymous viewer, admin password `GRAFANA_ADMIN_PASSWORD` (default `admin`, localhost only) |
| Prometheus | http://localhost:9090 | scrapes the worker every 5 s, keeps 7 days |
| Jaeger | http://localhost:16686 | service `bulwark-worker` |

The dashboard has nine panels: queue depth, scans running, scans finished (24 h), scan success rate, scan duration
p50/p95, per-scanner success rate, per-scanner duration p95, scanner outcomes and findings by severity.

**Verified for real:** with this stack up, four scans of public repositories completed; the logs carried `scan_id`
and trace ids, Jaeger held the full span tree with the four scanners overlapping, Prometheus showed the counters,
and every dashboard query returned data (checked by running each panel's query). **Not verified:** how the
dashboard looks; the panels have not been viewed in a browser here, so there is no screenshot yet. Open the Grafana
URL after a scan and capture one for the README.
