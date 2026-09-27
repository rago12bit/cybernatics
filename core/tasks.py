"""Celery orchestration: fan out one task per tool, tolerate partial failure.

Broker/backend default to a local Redis; override with BULWARK_BROKER_URL / BULWARK_RESULT_URL.
Workers must share a filesystem with the caller (the target path is passed by reference) and have
access to the Docker daemon. Start one with:  celery -A core.tasks worker -l info
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from celery import Celery, group
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import setup_logging, worker_ready, worker_shutdown

from core.runner import RunnerError
from core.scan import ADAPTERS, ToolOutcome

_REDIS = os.environ.get("BULWARK_REDIS_URL", "redis://localhost:6379/0")
_BROKER = os.environ.get("BULWARK_BROKER_URL", _REDIS)
# Results live in a separate Redis db from the broker unless overridden.
_BACKEND = os.environ.get("BULWARK_RESULT_URL", re.sub(r"/0$", "/1", _REDIS))

celery_app = Celery("bulwark", broker=_BROKER, backend=_BACKEND)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
)

celery_app.conf.beat_schedule = {
    "housekeeping": {"task": "bulwark.maintenance", "schedule": 300.0},  # every 5 minutes
    "risk-feeds": {"task": "bulwark.update_feeds", "schedule": 86400.0},  # EPSS is published daily
}


@setup_logging.connect  # type: ignore[untyped-decorator]  # connecting here stops Celery from installing its own log handlers
def _configure_worker_logging(**_: Any) -> None:
    from core.observability import configure_logging

    configure_logging()


@worker_ready.connect  # type: ignore[untyped-decorator]
def _start_observability(**_: Any) -> None:
    """Start tracing (when OTEL_EXPORTER_OTLP_ENDPOINT is set) and serve metrics."""
    from core.observability import setup_tracing
    from core.observability.metrics import start_metrics_server

    setup_tracing("bulwark-worker")
    start_metrics_server(redis_url=_BROKER)


@worker_shutdown.connect  # type: ignore[untyped-decorator]
def _stop_observability(**_: Any) -> None:
    from core.observability import shutdown_tracing

    shutdown_tracing()


# Wall-clock margin above the tool's own timeout before Celery steps in as a backstop.
SOFT_MARGIN, HARD_MARGIN = 20, 40


@celery_app.task(  # type: ignore[untyped-decorator]
    name="bulwark.run_tool",
    bind=True,
    autoretry_for=(RunnerError,),  # infra hiccup (docker unavailable): retry once, never a timeout
    retry_kwargs={"max_retries": 1},
    retry_backoff=2,
)
def run_tool_task(self: Any, tool: str, target: str) -> dict[str, Any]:
    from core.scan import execute_tool

    try:
        return execute_tool(tool, Path(target)).to_dict()
    except SoftTimeLimitExceeded:
        return ToolOutcome(tool, "timeout", error="celery soft time limit").to_dict()


@celery_app.task(name="bulwark.run_scan", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def run_scan_task(self: Any, scan_id: str, org_id: str | None = None) -> str:
    """Server-side scan job (used by the API). Idempotent: a redelivered task restarts cleanly.

    `org_id` (ADR-0013): passed by the API at enqueue time, which already knows it; see
    `core.tenancy.scoped_sessions` for why the worker can't just look it up itself. Optional so an
    already-queued task from before this week (if one were ever redelivered) still runs.
    """
    from core.config import Settings
    from core.events import RedisPublisher
    from core.persistence.db import get_session_factory
    from core.persistence.storage import S3Store
    from core.pipeline import run_scan_job

    settings = Settings.from_env()
    return run_scan_job(
        scan_id,
        get_session_factory(),
        S3Store(settings),
        RedisPublisher(settings.redis_url),
        org_id=org_id,
    )


@celery_app.task(name="bulwark.update_feeds", ignore_result=True)  # type: ignore[untyped-decorator]
def update_feeds_task() -> dict[str, str]:
    """Refresh the EPSS and CISA KEV caches; failures are recorded in meta.json, never raised."""
    from core.risk import update_feeds

    return dict(update_feeds()["errors"])


@celery_app.task(name="bulwark.maintenance", ignore_result=True)  # type: ignore[untyped-decorator]
def maintenance_task() -> dict[str, int]:
    """Periodic housekeeping (scheduled by Celery beat: run the worker with -B)."""
    from datetime import timedelta

    from core.config import Settings
    from core.events import RedisPublisher
    from core.maintenance import cleanup_containers, cleanup_scratch, reap_stale_scans
    from core.persistence.db import get_session_factory

    settings = Settings.from_env()
    max_minutes = int(os.environ.get("BULWARK_SCAN_MAX_MINUTES", "30"))
    with get_session_factory()() as s:
        reaped = reap_stale_scans(
            s, timedelta(minutes=max_minutes), RedisPublisher(settings.redis_url)
        )
    killed = cleanup_containers()
    removed = cleanup_scratch(settings.workdir / "tmp") + cleanup_scratch(settings.upload_dir)
    return {
        "scans_reaped": len(reaped),
        "containers_killed": len(killed),
        "scratch_removed": len(removed),
    }


def celery_executor(tools: list[str], target: Path) -> list[ToolOutcome]:
    """Executor for scan(): dispatch to workers, isolating each tool's failure."""
    sigs = [
        run_tool_task.s(t, str(target)).set(
            soft_time_limit=ADAPTERS[t].spec.timeout_seconds + SOFT_MARGIN,
            time_limit=ADAPTERS[t].spec.timeout_seconds + HARD_MARGIN,
        )
        for t in tools
    ]
    async_result = group(sigs).apply_async()
    outcomes: list[ToolOutcome] = []
    overall = max(ADAPTERS[t].spec.timeout_seconds for t in tools) + HARD_MARGIN + 30
    for tool, res in zip(tools, async_result.results, strict=True):
        try:
            outcomes.append(ToolOutcome.from_dict(res.get(timeout=overall)))
        except Exception as exc:  # noqa: BLE001 - worker died / hard-killed / lost
            outcomes.append(ToolOutcome(tool, "error", error=f"{type(exc).__name__}: {exc}"[:500]))
    return outcomes
