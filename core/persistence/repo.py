"""Data access for scans, tool runs and findings."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import case, delete, func, select
from sqlalchemy.orm import Session

from core.assets import asset_key
from core.issues import ExistingIssue, IssueUpdate, State, SyncResult, fallback_key
from core.issues import sync as sync_issues
from core.models import Finding
from core.persistence.models import SEVERITY_RANK, Asset, FindingRow, IssueRow, Scan, ToolRun
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
    return {state: n for state, n in rows}
