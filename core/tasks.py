"""Celery orchestration: fan out one task per tool, tolerate partial failure.

Broker/backend default to a local Redis; override with BULWARK_BROKER_URL / BULWARK_RESULT_URL.
Workers must share a filesystem with the caller (the target path is passed by reference) and have
access to the Docker daemon. Start one with:  celery -A core.tasks worker -l info
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from celery import Celery, group
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import setup_logging, worker_ready, worker_shutdown

from core.runner import RunnerError
from core.scan import ADAPTERS, ToolOutcome

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

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
    # Week 67 (plan §46.1): SBOMs from before the component inventory, a few projects an hour.
    "inventory-backfill": {"task": "bulwark.inventory_backfill", "schedule": 3600.0},
    # Week 68 (plan §46.2): OSV, KEV and NVD, then what changed matched for every organization.
    "advisories": {"task": "bulwark.update_advisories", "schedule": 6 * 3600.0},
    # Week 70 (plan §48.1, ADR-0054): the metric summary tables -- what changed, every few minutes;
    # everything hourly, as an acceptance expiring changes what is open without changing a row.
    "metrics": {"task": "bulwark.refresh_metrics", "schedule": 120.0},
    "metrics-all": {"task": "bulwark.refresh_metrics_all", "schedule": 3600.0},
    "reports": {"task": "bulwark.run_due_reports", "schedule": 300.0},
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
    from core.connectors import service

    def queue(s: Session, org_id: str) -> int:
        due = service.due(s, org_id)
        for c in due:
            run_connector_task.delay(c.id, org_id)
        return len(due)

    return _each_org("connectors", queue)


@celery_app.task(name="bulwark.sla_sweep", ignore_result=True)  # type: ignore[untyped-decorator]
def sla_sweep_task() -> int:
    """Each organization's SLA crossings, announced once each (plan §44.1), with its scope set."""
    from core.sla import service

    return _each_org("the SLA sweep", lambda s, org_id: service.sweep(s, org_id).announced)


@celery_app.task(name="bulwark.expire_risk_acceptances", ignore_result=True)  # type: ignore[untyped-decorator]
def expire_risk_acceptances_task() -> int:
    """End each organization's due risk acceptances, with its scope set (plan §44.2)."""
    from core.acceptance import service

    def expire(s: Session, org_id: str) -> int:
        ended = len(service.expire_due(s, org_id).expired)
        service.warn_expiring(s, org_id)
        return ended

    return _each_org("risk acceptance expiry", expire)


def _org_ids() -> list[str]:
    from sqlalchemy import select

    from core.persistence.db import get_session_factory
    from core.persistence.models import Organization

    with get_session_factory()() as s:
        return list(s.scalars(select(Organization.id)))


def _each_org(job: str, run: Callable[[Session, str], int]) -> int:
    """`run(session, org_id)` for every organization, each in a session of its own with its scope
    set (the `organizations` table carries no RLS; everything a job reads does). Returns the total.

    One organization failing does not stop the rest. These jobs ran every organization in one
    loop with nothing around each, so a single organization that raised -- a rule that would not
    evaluate, a row another job left half-written -- ended the task there, and every organization
    after it in the list was skipped, on that run and every run after. It is logged with the
    organization, and the next run tries it again."""
    from core.persistence.db import get_session_factory
    from core.tenancy import set_session_org

    total = 0
    for org_id in _org_ids():
        try:
            with get_session_factory()() as s:
                set_session_org(s, org_id)
                total += run(s, org_id)
        except Exception:  # noqa: BLE001 - whatever it was, the other organizations still run
            log.exception("%s failed for organization %s", job, org_id)
    return total


@celery_app.task(name="bulwark.dispatch_outbox", ignore_result=True)  # type: ignore[untyped-decorator]
def dispatch_outbox_task() -> int:
    """Each organization's new outbox events, to the rules engine (plan §41.1, §45)."""
    from core.dispatch import drain

    return _each_org("the outbox", drain)


@celery_app.task(name="bulwark.notification_digest", ignore_result=True)  # type: ignore[untyped-decorator]
def notification_digest_task() -> int:
    """Each organization's digests whose hour has come (plan §49)."""
    from core.notify.service import run_digests

    def digests(s: Session, org_id: str) -> int:
        r = run_digests(s, org_id)
        return r.emails + r.team_messages

    return _each_org("the notification digest", digests)


@celery_app.task(name="bulwark.tickets_sync", ignore_result=True)  # type: ignore[untyped-decorator]
def tickets_sync_task() -> int:
    """Linked tickets not synced for ten minutes, both ways (plan §49)."""
    from core.tickets.sync import sync_due

    return _each_org("ticket sync", sync_due)


@celery_app.task(name="bulwark.rules_sweep", ignore_result=True)  # type: ignore[untyped-decorator]
def rules_sweep_task() -> int:
    """Quiet projects and schedules (plan §45), each organization with its scope set."""
    from core.rules.engine import sweep

    def fired(s: Session, org_id: str) -> int:
        out = sweep(s, org_id)
        return out.applied + out.held

    return _each_org("the rules sweep", fired)


@celery_app.task(name="bulwark.inventory_backfill", ignore_result=True)  # type: ignore[untyped-decorator]
def inventory_backfill_task() -> int:
    """Projects whose SBOMs predate the component inventory (plan §46.1), a few at a time; and
    each library's usage counts, recounted."""
    from core.inventory import backfill, recount_org

    def fill(s: Session, org_id: str) -> int:
        n = backfill(s, org_id)
        recount_org(s, org_id)
        return n

    return _each_org("the inventory backfill", fill)


@celery_app.task(name="bulwark.update_advisories", ignore_result=True)  # type: ignore[untyped-decorator]
def update_advisories_task() -> dict[str, str]:
    """Fetch the advisory sources, then match each organization against what changed (all of it
    when much changed, as on the first run). Failures are recorded per source, never raised."""
    from core.advisories import feeds, impact, issues
    from core.persistence.db import get_session_factory

    with get_session_factory()() as s:
        result = feeds.update_all(s)
    full = len(result.vuln_keys) > impact.FULL_MATCH_OVER

    def match(s: Session, org_id: str) -> int:
        matched = impact.match(s, org_id, vuln_keys=None if full else result.vuln_keys)
        issues.sync_changed(s, org_id, matched.changed_assets)
        return len(matched.changed_assets)

    if result.vuln_keys:
        _each_org("advisory matching", match)
    return result.errors


@celery_app.task(name="bulwark.refresh_metrics", ignore_result=True)  # type: ignore[untyped-decorator]
def refresh_metrics_task() -> int:
    """Each organization's dirty metric scopes (plan §48.1)."""
    from core.metrics import rollup

    return _each_org("the metrics refresh", rollup.refresh_dirty)


@celery_app.task(name="bulwark.refresh_metrics_all", ignore_result=True)  # type: ignore[untyped-decorator]
def refresh_metrics_all_task() -> int:
    """Every project of every organization (plan §48.1)."""
    from core.metrics import rollup

    return _each_org("the full metrics refresh", rollup.refresh_all)


@celery_app.task(name="bulwark.render_report", bind=True, acks_late=True, ignore_result=True)  # type: ignore[untyped-decorator]
def render_report_task(self: Any, run_id: str, org_id: str) -> str:
    """Render one queued report to a signed PDF (plan §48.3). Here, not in the API: only the worker
    may run containers (Chromium, cosign)."""
    from core.persistence.db import get_session_factory
    from core.reports import service
    from core.tenancy import scoped_sessions

    with scoped_sessions(get_session_factory(), org_id)() as s:
        run = service.render_run(s, org_id, run_id)
        s.commit()
        return run.status


@celery_app.task(name="bulwark.run_due_reports", ignore_result=True)  # type: ignore[untyped-decorator]
def run_due_reports_task() -> int:
    """Generate and email each organization's reports whose schedule is due (plan §48.3)."""
    from core.reports import service

    return _each_org("scheduled reports", service.run_due)


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
