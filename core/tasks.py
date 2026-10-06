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
    # Retention is measured in days; hourly is far more often than needed but cheap, and keeps a
    # scan's data from lingering long past its org's own retention window (plan §22.2).
    "crypto-shred": {"task": "bulwark.crypto_shred", "schedule": 3600.0},
    # Connectors (Week 60, plan §42.5): each has its own interval; this only finds the due ones.
    "connectors": {"task": "bulwark.connectors_due", "schedule": 300.0},
    # SLA (Week 61, plan §44.1): announce Issues that crossed into "due soon" or "breached".
    "sla": {"task": "bulwark.sla_sweep", "schedule": 300.0},
    # Risk acceptance (Week 62, plan §44.2): end the ones whose date has come.
    "risk-acceptance-expiry": {"task": "bulwark.expire_risk_acceptances", "schedule": 300.0},
    # Rules (Week 65, plan §45): hand new outbox events to the rules engine, and fire the
    # triggers no event carries (a quiet project, a schedule).
    "outbox": {"task": "bulwark.dispatch_outbox", "schedule": 10.0},
    "rules-sweep": {"task": "bulwark.rules_sweep", "schedule": 300.0},
    # Week 66 (plan §49): the daily digest at each person's hour, and ticket sync both ways.
    "notification-digest": {"task": "bulwark.notification_digest", "schedule": 600.0},
    "tickets-sync": {"task": "bulwark.tickets_sync", "schedule": 600.0},
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
    from core.persistence.storage import build_object_store
    from core.pipeline import run_scan_job
    from core.tenancy import scoped_sessions

    settings = Settings.from_env()
    session_factory = get_session_factory()
    # scan_data_keys has the same direct-org_id RLS as verified_fix_runs (migration 0018):
    # build_object_store's own repo calls need app.current_org set, same as everything else
    # run_scan_job does under this org, so this scopes the factory itself rather than adding a
    # second, separate scoping path.
    store_sessions = (
        scoped_sessions(session_factory, org_id) if org_id is not None else session_factory
    )
    return run_scan_job(
        scan_id,
        session_factory,
        build_object_store(settings, store_sessions, org_id),
        RedisPublisher(settings.redis_url),
        org_id=org_id,
    )


@celery_app.task(name="bulwark.run_dast_campaign", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def run_dast_campaign_task(self: Any, scan_id: str, org_id: str | None = None) -> str:
    """Server-side DAST campaign job (used by the API). Same idempotent-redelivery and `org_id`
    reasoning as `run_scan_task` -- see its docstring."""
    from core.config import Settings
    from core.dast.pipeline import run_dast_campaign_job
    from core.events import RedisPublisher
    from core.persistence.db import get_session_factory

    settings = Settings.from_env()
    return run_dast_campaign_job(
        scan_id,
        get_session_factory(),
        RedisPublisher(settings.redis_url),
        org_id=org_id,
    )


@celery_app.task(name="bulwark.run_import", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def run_import_task(self: Any, import_id: str, org_id: str) -> str:
    """Server-side import job (Week 54 task 7, ADR-0040): parse an uploaded report in the sandbox
    and preview or apply it. Idempotent -- a redelivered task finds the import no longer queued and
    does nothing -- and run under `org_id` the way every other worker job is."""
    from core.config import Settings
    from core.imports.jobs import process_import
    from core.persistence.db import get_session_factory
    from core.tenancy import scoped_sessions

    sessions = scoped_sessions(get_session_factory(), org_id)
    with sessions() as s:
        record = process_import(s, import_id, org_id, Settings.from_env())
        return record.status if record is not None else "missing"


@celery_app.task(name="bulwark.connectors_due", ignore_result=True)  # type: ignore[untyped-decorator]
def connectors_due_task() -> int:
    """Queue every enabled connector whose next run is due, one organization at a time (the
    `organizations` table carries no RLS; each org's connectors are read with its scope set)."""
    from sqlalchemy import select

    from core.connectors import service
    from core.persistence.db import get_session_factory
    from core.persistence.models import Organization
    from core.tenancy import set_session_org

    queued = 0
    with get_session_factory()() as s:
        org_ids = list(s.scalars(select(Organization.id)))
    for org_id in org_ids:
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            for c in service.due(s, org_id):
                run_connector_task.delay(c.id, org_id)
                queued += 1
    return queued


@celery_app.task(name="bulwark.sla_sweep", ignore_result=True)  # type: ignore[untyped-decorator]
def sla_sweep_task() -> int:
    """Each organization's SLA crossings, announced once each (plan §44.1), with its scope set."""
    from sqlalchemy import select

    from core.persistence.db import get_session_factory
    from core.persistence.models import Organization
    from core.sla import service
    from core.tenancy import set_session_org

    announced = 0
    with get_session_factory()() as s:
        org_ids = list(s.scalars(select(Organization.id)))
    for org_id in org_ids:
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            announced += service.sweep(s, org_id).announced
    return announced


@celery_app.task(name="bulwark.expire_risk_acceptances", ignore_result=True)  # type: ignore[untyped-decorator]
def expire_risk_acceptances_task() -> int:
    """End each organization's due risk acceptances, with its scope set (plan §44.2)."""
    from sqlalchemy import select

    from core.acceptance import service
    from core.persistence.db import get_session_factory
    from core.persistence.models import Organization
    from core.tenancy import set_session_org

    ended = 0
    with get_session_factory()() as s:
        org_ids = list(s.scalars(select(Organization.id)))
    for org_id in org_ids:
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            ended += len(service.expire_due(s, org_id).expired)
            service.warn_expiring(s, org_id)
    return ended


def _org_ids() -> list[str]:
    from sqlalchemy import select

    from core.persistence.db import get_session_factory
    from core.persistence.models import Organization

    with get_session_factory()() as s:
        return list(s.scalars(select(Organization.id)))


@celery_app.task(name="bulwark.dispatch_outbox", ignore_result=True)  # type: ignore[untyped-decorator]
def dispatch_outbox_task() -> int:
    """Each organization's new outbox events, to the rules engine (plan §41.1, §45)."""
    from core.dispatch import drain
    from core.persistence.db import get_session_factory
    from core.tenancy import set_session_org

    total = 0
    for org_id in _org_ids():
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            total += drain(s, org_id)
    return total


@celery_app.task(name="bulwark.notification_digest", ignore_result=True)  # type: ignore[untyped-decorator]
def notification_digest_task() -> int:
    """Each organization's digests whose hour has come (plan §49)."""
    from core.notify.service import run_digests
    from core.persistence.db import get_session_factory
    from core.tenancy import set_session_org

    sent = 0
    for org_id in _org_ids():
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            r = run_digests(s, org_id)
            sent += r.emails + r.team_messages
    return sent


@celery_app.task(name="bulwark.tickets_sync", ignore_result=True)  # type: ignore[untyped-decorator]
def tickets_sync_task() -> int:
    """Linked tickets not synced for ten minutes, both ways (plan §49)."""
    from core.persistence.db import get_session_factory
    from core.tenancy import set_session_org
    from core.tickets.sync import sync_due

    n = 0
    for org_id in _org_ids():
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            n += sync_due(s, org_id)
    return n


@celery_app.task(name="bulwark.rules_sweep", ignore_result=True)  # type: ignore[untyped-decorator]
def rules_sweep_task() -> int:
    """Quiet projects and schedules (plan §45), each organization with its scope set."""
    from core.persistence.db import get_session_factory
    from core.rules.engine import sweep
    from core.tenancy import set_session_org

    fired = 0
    for org_id in _org_ids():
        with get_session_factory()() as s:
            set_session_org(s, org_id)
            out = sweep(s, org_id)
            fired += out.applied + out.held
    return fired


@celery_app.task(name="bulwark.recompute_priority", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def recompute_priority_task(self: Any, policy_id: str, org_id: str) -> str:
    """Re-rank every Issue of a project under its newly saved priority policy (plan §44.3). A
    redelivered job for a policy already done does nothing."""
    from core.persistence.db import get_session_factory
    from core.priority import service
    from core.tenancy import scoped_sessions

    with scoped_sessions(get_session_factory(), org_id)() as s:
        row = service.recompute(s, policy_id)
        return row.status if row is not None else "missing"


@celery_app.task(name="bulwark.run_targeted_retest", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def run_targeted_retest_task(self: Any, run_id: str, org_id: str) -> str:
    """One targeted retest (plan §43.3): one rule or DAST template, one location. A redelivered
    task for a run that is no longer queued does nothing."""
    from core.persistence.db import get_session_factory
    from core.retest import targeted
    from core.tenancy import scoped_sessions

    with scoped_sessions(get_session_factory(), org_id)() as s:
        r = targeted.run(s, run_id)
        return r.status if r is not None else "missing"


@celery_app.task(name="bulwark.run_connector", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def run_connector_task(self: Any, connector_id: str, org_id: str) -> str:
    """One connector pull or push (plan §42.5). A redelivered task for a connector that is no longer
    due (it already ran) does nothing."""
    from datetime import datetime, timezone

    from core.config import Settings
    from core.connectors import service
    from core.persistence.db import get_session_factory
    from core.tenancy import scoped_sessions

    with scoped_sessions(get_session_factory(), org_id)() as s:
        c = service.get(s, connector_id, org_id)
        if c is None or not c.enabled:
            return "missing"
        due = c.next_run_at
        if due is not None and (
            due if due.tzinfo else due.replace(tzinfo=timezone.utc)
        ) > datetime.now(timezone.utc):
            return "not-due"
        return service.run(s, c, Settings.from_env()).run.outcome


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
    from core.maintenance import (
        cleanup_containers,
        cleanup_scratch,
        expire_stale_imports,
        reap_stale_scans,
    )
    from core.persistence.db import get_session_factory

    settings = Settings.from_env()
    max_minutes = int(os.environ.get("BULWARK_SCAN_MAX_MINUTES", "30"))
    reaped = reap_stale_scans(
        get_session_factory(), timedelta(minutes=max_minutes), RedisPublisher(settings.redis_url)
    )
    killed = cleanup_containers()
    removed = cleanup_scratch(settings.workdir / "tmp") + cleanup_scratch(settings.upload_dir)
    # Ingest uploads have their own lifetime (a preview waits for a person), tied to the import's
    # status: expire the abandoned ones, then sweep any file no record owns any more (a day later,
    # so a live preview's file is never the one removed).
    imports_expired = expire_stale_imports(get_session_factory(), timedelta(hours=24))
    orphans = cleanup_scratch(settings.ingest_dir, max_age_seconds=48 * 3600)
    return {
        "scans_reaped": len(reaped),
        "containers_killed": len(killed),
        "scratch_removed": len(removed),
        "imports_expired": len(imports_expired),
        "ingest_orphans_removed": len(orphans),
    }


@celery_app.task(name="bulwark.crypto_shred", ignore_result=True)  # type: ignore[untyped-decorator]
def crypto_shred_task() -> dict[str, int]:
    """Periodic crypto-shredding sweep (Week 47 task 2, plan §22.2): destroys the data key for
    every scan past its organization's retention window. Never deletes the scan, its issues, or its
    findings -- only core.retention.shred_expired_scans's own docstring's target, ScanDataKeyRow."""
    from core.persistence.db import get_session_factory
    from core.retention import shred_expired_scans

    shredded = shred_expired_scans(get_session_factory())
    return {"scans_shredded": len(shredded)}


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
