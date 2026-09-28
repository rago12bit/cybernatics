"""Data access for scans, tool runs and findings."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import and_, case, delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

import core.audit as audit
from core.assets import asset_key
from core.issues import ExistingIssue, IssueUpdate, State, SyncResult, fallback_key
from core.issues import sync as sync_issues
from core.models import Finding
from core.persistence.models import (
    SEVERITY_RANK,
    ApiToken,
    Asset,
    AuditCheckpoint,
    AuditEntry,
    FindingRow,
    GithubInstallation,
    IssueRow,
    Organization,
    Scan,
    ToolRun,
)
from core.tenancy import DEFAULT_ORG_ID

log = logging.getLogger(__name__)

TERMINAL = frozenset({"completed", "partial", "failed"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_or_create_asset(
    s: Session, *, source_type: str, source_label: str, org_id: str = DEFAULT_ORG_ID
) -> Asset:
    """The row a repeated scan is matched against (ADR-0012). Identity is `core.assets.asset_key`
    scoped to one organization (ADR-0013) — two orgs scanning the same public repo get separate
    Assets, so neither sees the other's Issue history. The label is refreshed to the most recent
    scan's, since that's what a person actually reads."""
    key = asset_key(source_type, source_label)
    asset = s.scalars(
        select(Asset).where(
            Asset.org_id == org_id, Asset.source_type == source_type, Asset.key == key
        )
    ).one_or_none()
    if asset is None:
        asset = Asset(org_id=org_id, source_type=source_type, key=key, label=source_label)
        s.add(asset)
    else:
        asset.label, asset.last_scanned_at = source_label, _now()
    s.commit()
    return asset


def create_scan(
    s: Session,
    *,
    source_type: str,
    source_ref: str,
    source_label: str,
    tools: list[str],
    org_id: str = DEFAULT_ORG_ID,
    ref: str | None = None,
    github_repo: str | None = None,
    github_pr_number: int | None = None,
    github_installation_id: str | None = None,
) -> Scan:
    asset = get_or_create_asset(
        s, source_type=source_type, source_label=source_label, org_id=org_id
    )
    scan = Scan(
        org_id=org_id,
        source_type=source_type,
        source_ref=source_ref,
        source_label=source_label,
        tools=tools,
        asset_id=asset.id,
        ref=ref,
        github_repo=github_repo,
        github_pr_number=github_pr_number,
        github_installation_id=github_installation_id,
    )
    s.add(scan)
    s.commit()
    return scan


def list_scans(s: Session, limit: int = 20, *, org_id: str | None = None) -> list[Scan]:
    """`org_id=None` is a trusted-internal, unscoped read (no such caller is left in the API; every
    client-facing endpoint passes the request's real org). Application-level filtering here is
    belt-and-suspenders alongside Postgres RLS (ADR-0013) — SQLite test runs have no RLS, so this
    is what actually proves isolation in the fast test suite."""
    q = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    return list(s.scalars(q))


def get_scan(s: Session, scan_id: str, *, org_id: str | None = None) -> Scan | None:
    """`org_id=None` is the trusted-internal read the worker uses (it already knows the exact scan
    id it was dispatched for; there is no cross-tenant question to ask). Every client-facing API
    lookup passes the request's real org, so a scan in a different org is invisible, not just
    unauthorized — a 404, never a 403 (ADR-0013)."""
    scan = s.get(Scan, scan_id)
    if scan is None or (org_id is not None and scan.org_id != org_id):
        return None
    return scan


# ---------------------------------------------------------------------------------------------
# Assets as projects (plan §27): the project overview screen (Week 33, §28.1) is built entirely
# from data that already exists -- Asset (ADR-0012), IssueRow's lifecycle timestamps, and the same
# risk-sorted FindingRow query the scan-scoped "Fix first" widget already uses. Nothing here is a
# new source of truth.
# ---------------------------------------------------------------------------------------------

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def list_assets(s: Session, *, org_id: str | None = None, limit: int = 50) -> list[Asset]:
    q = select(Asset).order_by(Asset.last_scanned_at.desc()).limit(limit)
    if org_id is not None:
        q = q.where(Asset.org_id == org_id)
    return list(s.scalars(q))


def get_asset(s: Session, asset_id: str, *, org_id: str | None = None) -> Asset | None:
    asset = s.get(Asset, asset_id)
    if asset is None or (org_id is not None and asset.org_id != org_id):
        return None
    return asset


def latest_scan_for_asset(
    s: Session, asset_id: str, *, org_id: str | None = None, statuses: frozenset[str] = TERMINAL
) -> Scan | None:
    """The most recent scan of this asset that actually finished -- a queued or running scan has
    no findings to build an overview from yet."""
    q = select(Scan).where(Scan.asset_id == asset_id).order_by(Scan.created_at.desc())
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    for scan in s.scalars(q):
        if scan.status in statuses:
            return scan
    return None


def previous_scan_for_asset(
    s: Session,
    asset_id: str,
    before: Scan,
    *,
    org_id: str | None = None,
    statuses: frozenset[str] = TERMINAL,
) -> Scan | None:
    """The completed scan immediately before `before`, for "since previous scan" deltas."""
    q = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.created_at < before.created_at)
        .order_by(Scan.created_at.desc())
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    for scan in s.scalars(q):
        if scan.status in statuses:
            return scan
    return None


def since_previous_scan_counts(
    s: Session, asset_id: str, latest_scan_id: str, previous: Scan | None
) -> dict[str, int]:
    """Fixed/new/returned since the scan before this one. "new" and "returned" come straight from
    `issue_counts` (already computed at sync time, ADR-0012's new/reintroduced states); "fixed"
    isn't in that table (a fixed issue has no row in the *new* scan to count), so it's counted
    directly: issues that flipped to `fixed` after the previous scan finished. `previous=None`
    (this is the asset's first scan) floors the window at the epoch, so every currently-fixed issue
    counts once, not zero."""
    counts = issue_counts(s, latest_scan_id)
    since = previous.finished_at if previous is not None and previous.finished_at else EPOCH
    if since.tzinfo is None:  # SQLite returns naive datetimes even for tz-aware columns
        since = since.replace(tzinfo=timezone.utc)
    fixed = (
        s.scalar(
            select(func.count())
            .select_from(IssueRow)
            .where(
                IssueRow.asset_id == asset_id,
                IssueRow.state == "fixed",
                IssueRow.fixed_at.is_not(None),
                IssueRow.fixed_at > since,
            )
        )
        or 0
    )
    return {"fixed": fixed, "new": counts.get("new", 0), "returned": counts.get("reintroduced", 0)}


def open_issue_trend(
    s: Session, asset_id: str, *, points: int = 7, org_id: str | None = None
) -> list[dict[str, Any]]:
    """Open-issue count at each of the last `points` completed scans, oldest first -- reconstructed
    from IssueRow's first_seen_at/fixed_at rather than stored per-scan, since nothing snapshots that
    today. An issue counts as open as of a scan if it existed by then and wasn't fixed yet (or was
    fixed later)."""
    q = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.status.in_(TERMINAL), Scan.finished_at.is_not(None))
        .order_by(Scan.created_at.desc())
        .limit(points)
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    scans = list(reversed(list(s.scalars(q))))
    out: list[dict[str, Any]] = []
    for scan in scans:
        finished = scan.finished_at
        assert finished is not None
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        open_count = (
            s.scalar(
                select(func.count())
                .select_from(IssueRow)
                .where(
                    IssueRow.asset_id == asset_id,
                    IssueRow.first_seen_at <= finished,
                    or_(IssueRow.fixed_at.is_(None), IssueRow.fixed_at > finished),
                )
            )
            or 0
        )
        out.append({"scan_id": scan.id, "finished_at": scan.finished_at, "open_count": open_count})
    return out


# ---------------------------------------------------------------------------------------------
# Issues (Week 34, plan §28.3): the asset-level, cross-scan view of currently-open findings.
# "Currently open" for an asset's *latest* scan is exactly that scan's FindingRows carrying an
# issue_id -- any Issue not found there was necessarily marked `fixed` when that scan synced
# (core/issues.py), so there's no separate "is this issue still live" query to write. The only new
# thing this section adds is triage: a human decision layered on top of that.
# ---------------------------------------------------------------------------------------------

ACTIVE_TRIAGE_STATUSES = ("open",)  # the default queue: everything not deliberately set aside


def _active_triage_clause(now: datetime) -> ColumnElement[bool]:
    """An issue counts as "still in the active queue" if it's untouched, OR it was accepted but
    that acceptance has since expired (§28.3: accepted risk "reappears automatically")."""
    return or_(
        IssueRow.triage_status == "open",
        and_(
            IssueRow.triage_status == "accepted",
            IssueRow.triage_expires_at.is_not(None),
            IssueRow.triage_expires_at <= now,
        ),
    )


def list_asset_issues(
    s: Session,
    asset_id: str,
    latest_scan_id: str,
    *,
    severities: list[str] | None = None,
    categories: list[str] | None = None,
    triage: list[str] | None = None,
    sort: str = "risk",
    limit: int = 100,
    offset: int = 0,
) -> FindingPage:
    """Findings from the asset's latest scan, each annotated with its Issue's triage state.
    `triage=None` (the default) is the active triage queue: untouched issues, plus any accepted
    issue whose expiry has passed. Pass an explicit list (e.g. `["accepted", "not_a_risk"]`) to see
    triaged-away issues instead."""
    conds = [FindingRow.scan_id == latest_scan_id, FindingRow.issue_id.is_not(None)]
    if severities:
        conds.append(FindingRow.severity.in_([x.upper() for x in severities]))
    if categories:
        conds.append(FindingRow.category.in_([x.lower() for x in categories]))

    issue_ids_q = select(IssueRow.id).where(IssueRow.asset_id == asset_id)
    if triage:
        issue_ids_q = issue_ids_q.where(IssueRow.triage_status.in_(triage))
    else:
        issue_ids_q = issue_ids_q.where(_active_triage_clause(_now()))
    conds.append(FindingRow.issue_id.in_(issue_ids_q))

    total = s.scalar(select(func.count()).select_from(FindingRow).where(*conds)) or 0
    order: list[Any]
    if sort == "path":
        order = [FindingRow.path, FindingRow.start_line]
    elif sort == "risk":
        order = [case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc()]
    else:
        order = [
            FindingRow.severity_rank.desc(),
            case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc(),
            FindingRow.path,
            FindingRow.start_line,
        ]
    rows = list(
        s.scalars(
            select(FindingRow)
            .where(*conds)
            .order_by(*order, FindingRow.pk)
            .limit(limit)
            .offset(offset)
        )
    )
    issue_ids = [r.issue_id for r in rows if r.issue_id]
    triage_by_id = (
        {i.id: i for i in s.scalars(select(IssueRow).where(IssueRow.id.in_(issue_ids)))}
        if issue_ids
        else {}
    )
    items = []
    for r in rows:
        d = {**r.data, "scan_id": latest_scan_id}
        issue_row = triage_by_id.get(r.issue_id) if r.issue_id else None
        d["issue"] = (
            {
                "id": r.issue_id,
                "state": r.issue_state,
                "triage_status": issue_row.triage_status if issue_row else "open",
                "triage_reason": issue_row.triage_reason if issue_row else None,
                "triage_expires_at": issue_row.triage_expires_at if issue_row else None,
                "first_seen_at": issue_row.first_seen_at if issue_row else None,
            }
            if r.issue_id
            else None
        )
        items.append(d)
    return FindingPage(total, items)


def get_issue(s: Session, issue_id: str, *, org_id: str | None = None) -> IssueRow | None:
    """App-level org check (belt-and-suspenders alongside Postgres RLS, ADR-0013) -- `issues` has
    no `org_id` column of its own, so this joins through `assets`, exactly like the RLS policy
    itself does (migration 0005)."""
    q = select(IssueRow).where(IssueRow.id == issue_id)
    if org_id is not None:
        q = q.join(Asset, Asset.id == IssueRow.asset_id).where(Asset.org_id == org_id)
    return s.scalars(q).one_or_none()


def get_issue_finding(s: Session, issue_id: str, latest_scan_id: str) -> dict[str, Any] | None:
    """The full canonical Finding for one issue's detail screen (plan §28.3) -- its occurrence in
    the asset's latest scan, the same source `list_asset_issues` reads, just for one issue instead
    of a page of them."""
    row = s.scalar(
        select(FindingRow).where(
            FindingRow.scan_id == latest_scan_id, FindingRow.issue_id == issue_id
        )
    )
    if row is None:
        return None
    issue_row = s.get(IssueRow, issue_id)
    d = {**row.data, "scan_id": latest_scan_id}
    d["issue"] = {
        "id": issue_id,
        "state": row.issue_state,
        "triage_status": issue_row.triage_status if issue_row else "open",
        "triage_reason": issue_row.triage_reason if issue_row else None,
        "triage_expires_at": issue_row.triage_expires_at if issue_row else None,
        "first_seen_at": issue_row.first_seen_at if issue_row else None,
    }
    return d


def triage_issue(
    s: Session,
    issue_id: str,
    *,
    org_id: str,
    action: str,
    reason: str | None = None,
    expires_at: datetime | None = None,
    actor: str,
) -> IssueRow:
    """Mark an issue `not_a_risk` (requires `reason`) or `accepted` (requires `expires_at`), or
    `reopen` it back to the active queue. Writes an audit entry either way (plan §28.3: "Both write
    to the audit log (§19.3)") -- `reopen` too, since undoing a triage decision is itself a
    security-relevant action worth a durable record."""
    if action not in ("not_a_risk", "accepted", "reopen"):
        raise ValueError(f"unknown triage action: {action}")
    row = get_issue(s, issue_id, org_id=org_id)
    if row is None:
        raise LookupError("issue not found")
    now = _now()
    if action == "not_a_risk":
        if not reason or not reason.strip():
            raise ValueError("a reason is required to mark an issue as not a risk")
        row.triage_status, row.triage_reason, row.triage_expires_at = (
            "not_a_risk",
            reason.strip(),
            None,
        )
    elif action == "accepted":
        if expires_at is None:
            raise ValueError("an expiry date is required to accept a risk")
        row.triage_status, row.triage_reason, row.triage_expires_at = (
            "accepted",
            reason.strip() if reason else None,
            expires_at,
        )
    else:  # reopen
        row.triage_status, row.triage_reason, row.triage_expires_at = "open", None, None
    row.triaged_at, row.triaged_by = now, actor
    payload = {
        "action": action,
        "reason": reason,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    # append_audit_entry() commits -- the same flush also persists this row's pending changes above,
    # so the triage decision and its audit entry land together, in one transaction.
    append_audit_entry(
        s, actor=actor, action=f"issue.triage.{action}", target=issue_id, payload=payload
    )
    return row


def issue_history(s: Session, issue_id: str) -> list[dict[str, Any]]:
    """A real event timeline for one issue (plan §28.3), built from what's actually recorded: when
    it was first seen, every triage decision made about it since (the tamper-evident audit log,
    ADR-0019 -- `target` is the issue id), and when it was fixed, if it has been. Nothing here is
    synthesized; an issue with no triage history just has one or two entries."""
    issue = s.get(IssueRow, issue_id)
    events: list[dict[str, Any]] = []
    if issue is not None:
        events.append({"at": issue.first_seen_at, "label": "First seen"})
        if issue.fixed_at is not None:
            events.append({"at": issue.fixed_at, "label": "Fixed"})
    entries = s.scalars(
        select(AuditEntry).where(AuditEntry.target == issue_id).order_by(AuditEntry.seq)
    )
    for e in entries:
        events.append({"at": e.timestamp, "label": _audit_action_label(e.action)})
    events.sort(key=lambda ev: ev["at"])
    return events


def _audit_action_label(action: str) -> str:
    return {
        "issue.triage.not_a_risk": "Marked as not a risk",
        "issue.triage.accepted": "Risk accepted",
        "issue.triage.reopen": "Reopened",
    }.get(action, action)


def reset_scan_results(s: Session, scan_id: str) -> None:
    """Make a (re)started scan idempotent: a redelivered task must not duplicate rows."""
    s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
    s.execute(delete(ToolRun).where(ToolRun.scan_id == scan_id))
    s.commit()


def mark_running(s: Session, scan_id: str) -> None:
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.status, scan.started_at, scan.error = "running", _now(), None
    s.commit()


def finish_scan(s: Session, scan_id: str, status: str, error: str | None = None) -> None:
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.status, scan.finished_at, scan.error = status, _now(), error
    s.commit()


def add_tool_run(s: Session, scan_id: str, tool: str, block: dict[str, Any]) -> None:
    s.add(
        ToolRun(
            scan_id=scan_id,
            tool=tool,
            status=block["status"],
            findings_count=block.get("findings", 0),
            exit_code=block.get("exit_code"),
            duration_seconds=block.get("duration_seconds"),
            error=block.get("error") or block.get("reason"),
        )
    )
    s.commit()


def set_raw_artifact(
    s: Session, scan_id: str, tool: str, key: str | None, withheld: str | None
) -> None:
    run = s.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id, ToolRun.tool == tool)).one()
    run.raw_object_key, run.raw_withheld_reason = key, withheld
    s.commit()


def sync_issues_for_scan(s: Session, scan_id: str, findings: list[Finding]) -> SyncResult:
    """Match this scan's findings against the asset's existing issues (ADR-0012, `core/issues.py`)
    and persist the lifecycle transitions. Returns one `IssueUpdate` per input finding, in the same
    order, so the caller can attach `issue_id`/`state` to each finding's stored row without relying
    on finding ids (which `add_findings` may rename on collision).

    A scan with no asset (there is always one from `create_scan`, but a row could predate this
    column) is a no-op: every finding gets no issue.
    """
    scan = s.get(Scan, scan_id)
    assert scan is not None
    if scan.asset_id is None:
        return SyncResult()
    existing_rows = list(s.scalars(select(IssueRow).where(IssueRow.asset_id == scan.asset_id)))
    existing = [
        ExistingIssue(r.id, r.category, r.fingerprint, r.fallback_fingerprint, cast(State, r.state))
        for r in existing_rows
    ]
    by_id = {r.id: r for r in existing_rows}
    result = sync_issues(findings, existing, new_issue_id=_new_issue_id)

    now = _now()
    for f, u in zip(findings, result.updates, strict=True):
        row = by_id.get(u.issue_id)
        if row is None:  # brand new issue
            row = IssueRow(
                id=u.issue_id,
                asset_id=scan.asset_id,
                fingerprint=u.fingerprint,
                fallback_fingerprint=None,
                state=u.state,
                category=f.taxonomy.category.value,
                severity=f.scoring.normalized_severity.value,
                path=f.location.path,
                title=f.title,
                first_seen_at=now,
                last_seen_at=now,
            )
            s.add(row)
            by_id[u.issue_id] = row
        else:
            row.fingerprint = u.fingerprint
            row.state = u.state
            row.category = f.taxonomy.category.value
            row.severity = f.scoring.normalized_severity.value
            row.path = f.location.path
            row.title = f.title
            row.last_seen_at = now
            row.fixed_at = None
        # A fallback key needs the *original* Finding, not the ExistingIssue snapshot; recompute it
        # here rather than threading it through IssueUpdate, since it's cheap and keeps the pure
        # module focused on identity decisions, not field bookkeeping.
        row.fallback_fingerprint = fallback_key(f)

    for issue_id in result.fixed_issue_ids:
        row = by_id[issue_id]
        row.state, row.fixed_at = "fixed", now
    s.commit()
    return result


def _new_issue_id() -> str:
    return str(uuid.uuid4())


def add_findings(
    s: Session,
    scan_id: str,
    findings: list[Finding],
    issue_updates: list[IssueUpdate] | None = None,
) -> None:
    seen: set[str] = set()
    updates_by_position: list[IssueUpdate | None] = (
        list(issue_updates) if issue_updates else [None] * len(findings)
    )
    for f, upd in zip(findings, updates_by_position, strict=True):
        if f.id in seen:  # never drop a finding silently: disambiguate and say so
            n = 2
            while f"{f.id}#{n}" in seen:
                n += 1
            log.warning("finding id collision in scan %s: %s (kept as #%d)", scan_id, f.id, n)
            f.id = f"{f.id}#{n}"
        seen.add(f.id)
        d = f.to_dict()
        sev = f.scoring.normalized_severity.value
        s.add(
            FindingRow(
                scan_id=scan_id,
                finding_id=f.id,
                fingerprint=f.fingerprint,
                category=f.taxonomy.category.value,
                severity=sev,
                severity_rank=SEVERITY_RANK[sev],
                risk_score=f.scoring.risk_score,
                path=f.location.path,
                start_line=f.location.start_line,
                tools=list(f.evidence.reported_by),
                data=d,
                issue_id=upd.issue_id if upd else None,
                issue_state=upd.state if upd else None,
            )
        )
    s.commit()


def _with_issue(row: FindingRow) -> dict[str, Any]:
    """The stored canonical Finding, plus which Issue (ADR-0012) it belongs to and that issue's
    current lifecycle state — `new` on its first sighting, `open` after, `reintroduced` if it had
    been fixed and came back. `None` for scans with no asset, or scans that never resolved (partial
    or failed scans don't sync issues at all, since absence there wouldn't mean "fixed")."""
    issue = {"id": row.issue_id, "state": row.issue_state} if row.issue_id else None
    return {**row.data, "issue": issue}


@dataclass
class FindingPage:
    total: int
    items: list[dict[str, Any]]


def query_findings(
    s: Session,
    scan_id: str,
    *,
    severities: list[str] | None = None,
    categories: list[str] | None = None,
    tool: str | None = None,
    path_contains: str | None = None,
    sort: str = "severity",
    limit: int = 100,
    offset: int = 0,
) -> FindingPage:
    conds = [FindingRow.scan_id == scan_id]
    if severities:
        conds.append(FindingRow.severity.in_([x.upper() for x in severities]))
    if categories:
        conds.append(FindingRow.category.in_([x.lower() for x in categories]))
    if path_contains:
        escaped = path_contains.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds.append(FindingRow.path.like(f"%{escaped}%", escape="\\"))
    rows_q = select(FindingRow).where(*conds)
    if tool:
        # JSON-array membership is dialect-specific; filter by tool in Python over the scan's rows
        # only when requested (scans are bounded by ingestion limits).
        rows = [r for r in s.scalars(rows_q) if tool in r.tools]
        rows = _sort(rows, sort)
        return FindingPage(len(rows), [_with_issue(r) for r in rows[offset : offset + limit]])
    total = s.scalar(select(func.count()).select_from(FindingRow).where(*conds)) or 0
    order: list[Any]
    if sort == "path":
        order = [FindingRow.path, FindingRow.start_line]
    elif sort == "risk":
        order = [case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc()]
    else:
        order = [
            FindingRow.severity_rank.desc(),
            case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc(),
            FindingRow.path,
            FindingRow.start_line,
        ]
    rows_q = rows_q.order_by(*order, FindingRow.pk).limit(limit).offset(offset)
    return FindingPage(total, [_with_issue(r) for r in s.scalars(rows_q)])


def _sort(rows: list[FindingRow], sort: str) -> list[FindingRow]:
    if sort == "path":
        return sorted(rows, key=lambda r: (r.path, r.start_line, r.pk))
    if sort == "risk":
        return sorted(
            rows, key=lambda r: (-(r.risk_score if r.risk_score is not None else -1), r.pk)
        )
    return sorted(
        rows,
        key=lambda r: (
            -r.severity_rank,
            -(r.risk_score if r.risk_score is not None else -1),
            r.path,
            r.start_line,
            r.pk,
        ),
    )


def severity_counts(s: Session, scan_id: str) -> dict[str, int]:
    rows = s.execute(
        select(FindingRow.severity, func.count())
        .where(FindingRow.scan_id == scan_id)
        .group_by(FindingRow.severity)
    ).all()
    return {sev: n for sev, n in rows}


def issue_counts(s: Session, scan_id: str) -> dict[str, int]:
    """Findings by Issue lifecycle state (ADR-0012). Empty for scans with no synced issues — a
    scan that isn't "completed", or one that predates Week 28 and hasn't been backfilled."""
    rows = s.execute(
        select(FindingRow.issue_state, func.count())
        .where(FindingRow.scan_id == scan_id, FindingRow.issue_state.is_not(None))
        .group_by(FindingRow.issue_state)
    ).all()
    return {state: n for state, n in rows if state is not None}


def get_installation(s: Session, installation_id: str) -> GithubInstallation | None:
    """`github_installations` deliberately carries no Row-Level Security policy (unlike every
    table that holds actual scan data) -- this lookup is *how* a webhook's org context gets
    resolved in the first place, so it cannot itself require org context to already be set. It's
    a directory table,
    like `organizations` itself, not tenant-owned content: knowing "installation X belongs to org Y"
    isn't a cross-tenant data leak the way a scan's findings would be. See `set_session_org`'s and
    `get_or_create_installation`'s docstrings for how the *next* query in the same session gets
    properly org-scoped, right after this one resolves which org that is."""
    return s.get(GithubInstallation, installation_id)


def get_or_create_installation(
    s: Session, *, installation_id: str, account_login: str
) -> GithubInstallation:
    """A GitHub App installation IS a tenant boundary for now (ADR-0013/ADR-0017): installing the
    App on an account creates that account's Organization the first time we hear about it, since
    there is no separate org-management API yet. A `created` webhook redelivered (GitHub retries
    webhooks it isn't sure were received) must not create a second org, hence get-or-create.

    Callers that go on to write anything else in this same session (an `Asset`/`Scan` for a PR
    scan, which DO carry RLS) must call `core.tenancy.set_session_org(s, row.org_id)` first -- this
    function only resolves *which* org, it doesn't set the session's org context, since a plain
    lookup (the common case: an already-installed app) shouldn't have the side effect of changing
    it.
    """
    row = s.get(GithubInstallation, installation_id)
    if row is not None:
        return row
    org = Organization(name=f"GitHub: {account_login}")
    s.add(org)
    s.flush()  # `org.id`'s default (core.persistence.models._uuid) is only assigned on flush, not
    # at construction -- reading it beforehand (as the FK value below needs to) would insert NULL.
    row = GithubInstallation(id=installation_id, account_login=account_login, org_id=org.id)
    s.add(row)
    s.commit()
    return row


def delete_installation(s: Session, installation_id: str) -> None:
    """Uninstalling the App only removes the installation mapping -- never the Organization or its
    scan/issue history, which stays exactly as durable as any other org's (ADR-0013). Reinstalling
    later (a new installation id, GitHub never reuses one) starts a *new* org rather than resuming
    the old one; there's no way to prove it's the same account asking, so this doesn't try to guess.
    """
    row = s.get(GithubInstallation, installation_id)
    if row is not None:
        s.delete(row)
        s.commit()


def create_api_token(
    s: Session, *, org_id: str, name: str, scopes: list[str], expires_at: datetime | None = None
) -> tuple[ApiToken, str]:
    """Returns `(row, raw_token)` -- the raw secret is generated here and returned exactly once;
    only its hash is ever persisted (`core/tokens.py`). Callers (the `bulwark token create` CLI)
    must show `raw_token` to the operator and never log or store it themselves."""
    from core.tokens import generate_token

    generated = generate_token()
    row = ApiToken(
        org_id=org_id, name=name, token_hash=generated.token_hash,
        display_prefix=generated.display_prefix, scopes=sorted(scopes), expires_at=expires_at,
    )  # fmt: skip
    s.add(row)
    s.commit()
    return row, generated.raw


def get_api_token_by_hash(s: Session, token_hash: str) -> ApiToken | None:
    """No org filter, deliberately -- see `ApiToken`'s docstring. Authenticating a request with a
    token is what *resolves* its org context; this lookup can't be gated by org context that
    doesn't exist yet at this point in the request."""
    return s.scalar(select(ApiToken).where(ApiToken.token_hash == token_hash))


def touch_api_token(s: Session, token_id: str) -> None:
    row = s.get(ApiToken, token_id)
    if row is not None:
        row.last_used_at = _now()
        s.commit()


def list_api_tokens(s: Session, org_id: str) -> list[ApiToken]:
    return list(
        s.scalars(
            select(ApiToken).where(ApiToken.org_id == org_id).order_by(ApiToken.created_at.desc())
        )
    )


def revoke_api_token(s: Session, token_id: str) -> bool:
    row = s.get(ApiToken, token_id)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = _now()
    s.commit()
    return True


def append_audit_entry(
    s: Session, *, actor: str, action: str, target: str, payload: dict[str, Any]
) -> AuditEntry:
    """A bounded optimistic-concurrency retry, not a database lock -- see `AuditEntry`'s docstring
    for why that's an accepted, documented simplification at this project's current scale (one API
    process, one worker), not a claim that a concurrent-write race is impossible."""
    digest = audit.payload_digest(payload)
    for _ in range(5):
        last = s.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
        seq = (last.seq + 1) if last else 1
        prev_hash = last.entry_hash if last else audit.GENESIS_HASH
        now = _now()
        entry_hash = audit.compute_hash(
            seq=seq, prev_hash=prev_hash, timestamp=now, actor=actor, action=action,
            target=target, payload_digest=digest,
        )  # fmt: skip
        row = AuditEntry(
            seq=seq, prev_hash=prev_hash, entry_hash=entry_hash, timestamp=now, actor=actor,
            action=action, target=target, payload_digest=digest,
        )  # fmt: skip
        s.add(row)
        try:
            s.commit()
            return row
        except IntegrityError:
            s.rollback()
    raise RuntimeError("could not append an audit entry after 5 attempts (high write contention)")


def list_audit_entries(s: Session, *, since_seq: int = 0) -> list[AuditEntry]:
    return list(
        s.scalars(select(AuditEntry).where(AuditEntry.seq > since_seq).order_by(AuditEntry.seq))
    )


def latest_checkpoint(s: Session) -> AuditCheckpoint | None:
    return s.scalar(select(AuditCheckpoint).order_by(AuditCheckpoint.seq_end.desc()).limit(1))


def record_checkpoint(
    s: Session, *, seq_end: int, chain_hash: str, signature_bundle: str, rekor_log_index: int | None
) -> AuditCheckpoint:
    row = AuditCheckpoint(
        seq_end=seq_end, chain_hash=chain_hash, signature_bundle=signature_bundle,
        rekor_log_index=rekor_log_index,
    )  # fmt: skip
    s.add(row)
    s.commit()
    return row


def list_checkpoints(s: Session) -> list[AuditCheckpoint]:
    return list(s.scalars(select(AuditCheckpoint).order_by(AuditCheckpoint.seq_end)))
