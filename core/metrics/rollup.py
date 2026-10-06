"""Keeping the metric summary tables up to date (plan §48.1, ADR-0054).

A project's rows are rebuilt from its Issues -- all of them, in one pass -- whenever the project is
marked dirty. Marking is automatic: any change to an Issue, an SLA policy, a project, a tool run or
an advisory impact flushed through a session marks what it touches (`_mark_on_flush`), in the
same transaction, so nothing that changes Issues needs to remember to. What is dirty is refreshed:

- at once, after a scan or an import commits (`refresh_dirty`, called by the pipeline and the
  import job: "refreshed on ingest");
- every few minutes on the worker, for everything else (triage, priority, SLA policy changes);
- every project of every organization once an hour, because an acceptance that expires changes
  what is open without changing a row.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import delete, event, func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from core.issues import LIVE_STATES
from core.persistence.models import (
    AdvisoryImpact,
    Asset,
    IssueRow,
    KevEntry,
    MetricAssetStatus,
    MetricComponent,
    MetricDirty,
    MetricIssueDay,
    MetricOpenIssue,
    MetricSlaDay,
    Scan,
    SlaPolicy,
    ToolRun,
)
from core.sla.policy import STARTER_POLICY, evaluate, from_row

log = logging.getLogger(__name__)
COMPONENTS = "components"
CHUNK = 2000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def dismissed(triage_status: str, expires: datetime | None, now: datetime) -> bool:
    """Marked not a risk, or accepted with the acceptance still in force."""
    if triage_status == "not_a_risk":
        return True
    if triage_status == "accepted":
        exp = _utc(expires)
        return exp is None or exp > now
    return False


# --- marking ---------------------------------------------------------------------------------


def _upsert(dialect: str, rows: list[dict[str, Any]]) -> Any:
    """Mark, or re-mark with a later time: a change made while a refresh runs must stay dirty
    after it (`refresh_dirty` clears only what was marked before it read)."""
    ins = pg_insert if dialect == "postgresql" else sqlite_insert
    stmt = ins(MetricDirty).values(rows)
    return stmt.on_conflict_do_update(
        index_elements=["org_id", "scope"], set_={"marked_at": stmt.excluded.marked_at}
    )


def mark(s: Session, org_id: str, scopes: Iterable[str]) -> None:
    rows = [{"org_id": org_id, "scope": sc, "marked_at": _now()} for sc in set(scopes) if sc]
    if rows:
        s.execute(_upsert(s.get_bind().dialect.name, rows))


@event.listens_for(Session, "after_flush")
def _mark_on_flush(s: Session, _ctx: Any) -> None:
    assets: set[str] = set()
    components: set[str] = set()
    for obj in (*s.new, *s.dirty, *s.deleted):
        if isinstance(obj, (IssueRow, SlaPolicy)):
            assets.add(obj.asset_id)
        elif isinstance(obj, Asset):
            assets.add(obj.id)
        elif isinstance(obj, AdvisoryImpact):
            components.add(obj.org_id)
        elif isinstance(obj, Scan) and obj.asset_id:  # a scan finishing: last scan, scanners
            assets.add(obj.asset_id)
    if not assets and not components:
        return
    by_org: dict[str, set[str]] = defaultdict(set)
    if assets:
        conn = s.connection()
        for asset_id, org_id in conn.execute(
            select(Asset.id, Asset.org_id).where(Asset.id.in_(sorted(assets)))
        ):
            by_org[org_id].add(asset_id)
    for org_id in components:
        by_org[org_id].add(COMPONENTS)
    now = _now()
    rows = [
        {"org_id": o, "scope": sc, "marked_at": now}
        for o, scopes in by_org.items()
        for sc in scopes
    ]  # noqa: E501
    if rows:
        s.connection().execute(_upsert(s.get_bind().dialect.name, rows))


# --- refreshing ------------------------------------------------------------------------------


def _band(override: str | None, computed: str | None) -> str:
    return override or computed or "none"


def refresh_asset(s: Session, org_id: str, asset_id: str, now: datetime | None = None) -> None:
    """Rebuild one project's rows. Does not commit."""
    now = now or _now()
    asset = s.get(Asset, asset_id)
    for model in (MetricOpenIssue, MetricIssueDay, MetricSlaDay):
        s.execute(delete(model).where(model.org_id == org_id, model.asset_id == asset_id))
    s.execute(delete(MetricAssetStatus).where(MetricAssetStatus.asset_id == asset_id))
    if asset is None or asset.org_id != org_id:
        return
    portfolio = asset.portfolio_id
    row = s.scalar(
        select(SlaPolicy)
        .where(SlaPolicy.asset_id == asset_id)
        .order_by(SlaPolicy.version.desc())
        .limit(1)  # noqa: E501
    )
    policy = from_row(row.enabled, row.basis, row.bands) if row is not None else STARTER_POLICY
    open_rows: list[dict[str, Any]] = []
    days: dict[tuple[date, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])
    sla: dict[tuple[date, str], list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    q = select(
        IssueRow.id, IssueRow.state, IssueRow.severity, IssueRow.priority_band,
        IssueRow.priority_override, IssueRow.priority_score, IssueRow.first_seen_at,
        IssueRow.sla_started_at, IssueRow.fixed_at, IssueRow.triage_status,
        IssueRow.triage_expires_at,
    ).where(IssueRow.asset_id == asset_id)  # fmt: skip
    for (iid, state, severity, computed, override, score, first_seen, sla_start, fixed_at,
         triage, expires) in s.execute(q):  # fmt: skip
        band = _band(override, computed)
        first = _utc(first_seen) or now
        fixed = _utc(fixed_at) if state == "fixed" else None
        gone = dismissed(triage, expires, now)
        points = int(score or 0)
        d = days[(first.date(), band)]
        d[0] += 1
        if not gone:
            d[3] += points
        if fixed is not None:
            f = days[(fixed.date(), band)]
            f[1] += 1
            f[2] += max(0, int((fixed - first).total_seconds()))
            if not gone:
                f[4] += points
        status = None
        if policy.enabled:
            status = evaluate(
                policy, severity=severity, priority_band=override or computed,
                state="fixed" if fixed is not None else state, first_seen_at=first,
                sla_started_at=sla_start, fixed_at=fixed, triage_status=triage,
                triage_expires_at=expires, now=now,
            )  # fmt: skip
            due = _utc(status.due_at)
            if due is not None:
                key = (
                    due.date(),
                    (override or computed or "none") if policy.basis == "priority" else severity,
                )  # noqa: E501
                bucket = {"met": 0, "missed": 1, "exempt": 3}.get(status.state, 2)
                sla[key][bucket] += 1
        if state in LIVE_STATES and not gone:
            open_rows.append({
                "issue_id": iid, "org_id": org_id, "asset_id": asset_id, "portfolio_id": portfolio,
                "band": band, "severity": severity, "priority_score": points,
                "first_seen_at": first,
                "due_at": _utc(status.due_at) if status is not None else None,
            })  # fmt: skip
    for k in range(0, len(open_rows), CHUNK):
        s.execute(insert(MetricOpenIssue), open_rows[k : k + CHUNK])
    day_rows = [
        {"org_id": org_id, "asset_id": asset_id, "portfolio_id": portfolio, "day": day,
         "band": band, "opened": v[0], "fixed": v[1], "fix_seconds": v[2], "risk_opened": v[3],
         "risk_fixed": v[4]}  # fmt: skip
        for (day, band), v in days.items()
    ]
    for k in range(0, len(day_rows), CHUNK):
        s.execute(insert(MetricIssueDay), day_rows[k : k + CHUNK])
    sla_rows = [
        {"org_id": org_id, "asset_id": asset_id, "portfolio_id": portfolio, "day": day,
         "band": band, "met": v[0], "missed": v[1], "unfixed": v[2], "exempt": v[3]}  # fmt: skip
        for (day, band), v in sla.items()
    ]
    for k in range(0, len(sla_rows), CHUNK):
        s.execute(insert(MetricSlaDay), sla_rows[k : k + CHUNK])
    last = s.execute(
        select(Scan.id, Scan.finished_at)
        .where(
            Scan.asset_id == asset_id, Scan.status == "completed", Scan.ref.is_(None),
            Scan.source_type != "import",
        )
        .order_by(Scan.finished_at.desc())
        .limit(1)
    ).first()  # fmt: skip
    ok = applicable = 0
    if last is not None:
        for status_ in s.scalars(select(ToolRun.status).where(ToolRun.scan_id == last[0])):
            if status_ != "skipped":
                applicable += 1
                ok += status_ == "ok"
    s.add(MetricAssetStatus(
        asset_id=asset_id, org_id=org_id, portfolio_id=portfolio,
        last_scan_at=_utc(last[1]) if last else None, scanners_ok=ok,
        scanners_applicable=applicable, refreshed_at=now,
    ))  # fmt: skip


def refresh_components(s: Session, org_id: str) -> None:
    """Rebuild the organization's component rows from its open advisory impacts."""
    s.execute(delete(MetricComponent).where(MetricComponent.org_id == org_id))
    kev = set(s.scalars(select(KevEntry.cve)))
    per: dict[tuple[str, str], list[set[str]]] = defaultdict(lambda: [set(), set()])
    for lib, asset_id, vuln in s.execute(
        select(AdvisoryImpact.library_id, AdvisoryImpact.asset_id, AdvisoryImpact.vuln_key)
        .where(AdvisoryImpact.org_id == org_id, AdvisoryImpact.resolved_at.is_(None))
        .distinct()
    ):
        v = per[(lib, asset_id)]
        v[0].add(vuln)
        if vuln in kev:
            v[1].add(vuln)
    portfolios: dict[str, str | None] = {
        a: pf
        for a, pf in s.execute(select(Asset.id, Asset.portfolio_id).where(Asset.org_id == org_id))
    }
    rows = [
        {
            "org_id": org_id,
            "library_id": lib,
            "asset_id": asset_id,
            "portfolio_id": portfolios.get(asset_id),
            "vulns": len(v[0]),
            "kev": len(v[1]),
        }
        for (lib, asset_id), v in per.items()
    ]
    for k in range(0, len(rows), CHUNK):
        s.execute(insert(MetricComponent), rows[k : k + CHUNK])


def refresh_dirty(s: Session, org_id: str, limit: int = 500) -> int:
    """Refresh what is marked dirty for the organization, committing per project. Returns how
    many scopes were refreshed."""
    scopes = list(
        s.scalars(
            select(MetricDirty.scope)
            .where(MetricDirty.org_id == org_id)
            .order_by(MetricDirty.marked_at)
            .limit(limit)
        )
    )
    for scope in scopes:
        marked = s.scalar(
            select(MetricDirty.marked_at).where(
                MetricDirty.org_id == org_id, MetricDirty.scope == scope
            )
        )
        try:
            if scope == COMPONENTS:
                refresh_components(s, org_id)
            else:
                refresh_asset(s, org_id, scope)
            # Only what was marked before the refresh read: a change made meanwhile stays dirty.
            s.execute(
                delete(MetricDirty).where(
                    MetricDirty.org_id == org_id, MetricDirty.scope == scope,
                    MetricDirty.marked_at <= marked,
                )
            )  # fmt: skip
            s.commit()
        except Exception:  # noqa: BLE001 - one project must not stop the rest
            s.rollback()
            log.exception("metrics: could not refresh %s in %s", scope, org_id)
    return len(scopes)


def refresh_all(s: Session, org_id: str) -> int:
    """Mark every project and the components dirty, then refresh them."""
    assets = list(s.scalars(select(Asset.id).where(Asset.org_id == org_id)))
    mark(s, org_id, [*assets, COMPONENTS])
    s.commit()
    total = 0
    while True:
        n = refresh_dirty(s, org_id)
        total += n
        if n == 0 or not s.scalar(
            select(func.count()).select_from(MetricDirty).where(MetricDirty.org_id == org_id)
        ):
            return total
