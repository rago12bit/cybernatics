"""Prometheus metrics for the worker: scan and tool outcomes, durations, findings and queue depth.

Metrics live in the worker process (the one that runs scans) and are served on an internal port. Labels are
bounded sets (tool names, fixed statuses, severities), never a scan id or a path. The queue depth is read from
Redis at scrape time, so it is always current and needs no bookkeeping.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)
from prometheus_client.core import GaugeMetricFamily

log = logging.getLogger(__name__)

REGISTRY = CollectorRegistry(auto_describe=True)
SCAN_BUCKETS = (5, 15, 30, 60, 120, 300, 600, 1200, 1800)
TOOL_BUCKETS = (1, 5, 15, 30, 60, 120, 300, 600, 900)

SCANS = Counter("bulwark_scans_total", "Finished scans.", ["status"], registry=REGISTRY)
SCAN_SECONDS = Histogram(
    "bulwark_scan_duration_seconds",
    "Wall-clock time of a whole scan job.",
    buckets=SCAN_BUCKETS,
    registry=REGISTRY,
)
SCANS_RUNNING = Gauge(
    "bulwark_scans_in_progress", "Scans being processed right now.", registry=REGISTRY
)
TOOL_RUNS = Counter(
    "bulwark_tool_runs_total",
    "Scanner runs by outcome (ok, error, timeout, skipped).",
    ["tool", "status"],
    registry=REGISTRY,
)
TOOL_SECONDS = Histogram(
    "bulwark_tool_duration_seconds",
    "Wall-clock time of one scanner run.",
    ["tool"],
    buckets=TOOL_BUCKETS,
    registry=REGISTRY,
)
FINDINGS = Counter(
    "bulwark_findings_total",
    "Unique findings produced, by normalized severity.",
    ["severity"],
    registry=REGISTRY,
)

TOOLS = (
    "bandit",
    "semgrep",
    "gitleaks",
    "trivy",
    "osv-scanner",
    "grype",
    "checkov",
    "gosec",
    "dockle",
)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_STATUSES = ("ok", "error", "timeout", "skipped")
_SCAN_STATUSES = ("completed", "partial", "failed")


def _label(value: str, allowed: tuple[str, ...], other: str = "other") -> str:
    return value if value in allowed else other


def observe_tool(tool: str, status: str, seconds: float | None) -> None:
    t = _label(tool, TOOLS)
    TOOL_RUNS.labels(t, _label(status, _STATUSES)).inc()
    if seconds is not None and status != "skipped":
        TOOL_SECONDS.labels(t).observe(max(seconds, 0.0))


def observe_scan(status: str, seconds: float, severities: dict[str, int]) -> None:
    SCANS.labels(_label(status, _SCAN_STATUSES)).inc()
    SCAN_SECONDS.observe(max(seconds, 0.0))
    for sev, n in severities.items():
        if sev in SEVERITIES and n > 0:
            FINDINGS.labels(sev).inc(n)


class QueueDepth:
    """Collector: length of the Celery queue, read from Redis when Prometheus scrapes."""

    def __init__(self, redis_url: str, queue: str = "celery") -> None:
        self.redis_url, self.queue = redis_url, queue

    def collect(self) -> Any:
        g = GaugeMetricFamily("bulwark_queue_depth", "Scan jobs waiting for a worker.")
        try:
            import redis

            client = redis.Redis.from_url(
                self.redis_url, socket_timeout=2, socket_connect_timeout=2
            )
            g.add_metric([], float(int(client.llen(self.queue))))  # type: ignore[arg-type]
        except (
            Exception
        ):  # noqa: BLE001 - an unreachable broker is reported by omission, not by crashing the scrape
            log.warning("queue depth unavailable", exc_info=True)
            return
        yield g


class CostSummary:
    """Collector: estimated cost over the last 24h, read from Postgres when Prometheus scrapes --
    same "always current, no bookkeeping" shape as `QueueDepth`, just against SQL instead of Redis
    (plan §23, Week 50's cost-per-scan dashboard; `core.observability.cost` has the actual pricing
    logic and its own disclosed accuracy caveats, which apply here identically).

    Scoped to the bootstrap default org, like every other metric in this module (none of them carry
    an org label) -- this project's own stated scope is a self-hosted single-tenant deployment, not a
    multi-tenant SaaS (see Part 1's explicit non-goals), so that's the one org an operator's own
    Grafana dashboard actually needs. A real multi-tenant deployment wanting cross-org cost visibility
    here would need `set_session_org` called once per org (RLS hides every other org's rows from a
    session with no org context at all, which is why this can't just query across all orgs in one
    pass the way QueueDepth's single Redis key can)."""

    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    def collect(self) -> Any:
        g = GaugeMetricFamily(
            "bulwark_estimated_cost_usd",
            "Estimated cost over the last 24h for the default org, by component.",
            labels=["component"],
        )
        try:
            from datetime import datetime, timedelta, timezone

            from core.observability.cost import estimate_cost
            from core.persistence.repo import cost_summary_scans
            from core.tenancy import DEFAULT_ORG_ID, set_session_org

            with self._session_factory() as s:
                set_session_org(s, DEFAULT_ORG_ID)
                since = datetime.now(timezone.utc) - timedelta(hours=24)
                compute_usd = llm_usd = 0.0
                for scan, compute_seconds in cost_summary_scans(
                    s, org_id=DEFAULT_ORG_ID, since=since
                ):
                    breakdown = estimate_cost(
                        compute_seconds=compute_seconds,
                        llm_tokens=scan.llm_tokens_used,
                        model="claude-sonnet-5",
                    )
                    compute_usd += breakdown.compute_usd
                    llm_usd += breakdown.llm_usd
            g.add_metric(["compute"], compute_usd)
            g.add_metric(["llm"], llm_usd)
        except Exception:  # noqa: BLE001 - an unreachable DB is reported by omission, not a crash
            log.warning("cost summary unavailable", exc_info=True)
            return
        yield g


def init_series() -> None:
    """Create every label combination at zero so rates and 'no failures yet' show up from the first scrape."""
    for t in TOOLS:
        for s in _STATUSES:
            TOOL_RUNS.labels(t, s)
        TOOL_SECONDS.labels(t)
    for s in _SCAN_STATUSES:
        SCANS.labels(s)
    for sev in SEVERITIES:
        FINDINGS.labels(sev)


def start_metrics_server(port: int | None = None, redis_url: str | None = None) -> int | None:
    """Serve /metrics (BULWARK_METRICS_PORT, 0 disables; BULWARK_METRICS_ADDR, default loopback)."""
    raw = os.environ.get("BULWARK_METRICS_PORT", "9101") if port is None else str(port)
    if not raw or raw == "0":
        return None
    p = int(raw)
    init_series()
    if redis_url:
        REGISTRY.register(QueueDepth(redis_url))  # type: ignore[arg-type,unused-ignore]
    try:
        from core.persistence.db import get_session_factory

        REGISTRY.register(CostSummary(get_session_factory()))  # type: ignore[arg-type,unused-ignore]
    except Exception:  # noqa: BLE001 - no DB configured (e.g. a unit test importing this module)
        log.warning("cost summary metric not registered (no database available)")
    try:
        start_http_server(
            p, addr=os.environ.get("BULWARK_METRICS_ADDR", "127.0.0.1"), registry=REGISTRY
        )
    except OSError:
        log.warning("metrics port %d is unavailable; metrics are not served", p)
        return None
    log.info("metrics served", extra={"metrics_port": p})
    return p
