"""Data access for scans, tool runs and findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, delete, func, select
from sqlalchemy.orm import Session

from core.models import Finding
from core.persistence.models import SEVERITY_RANK, FindingRow, Scan, ToolRun

log = logging.getLogger(__name__)

TERMINAL = frozenset({"completed", "partial", "failed"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_scan(
    s: Session, *, source_type: str, source_ref: str, source_label: str, tools: list[str]
) -> Scan:
    scan = Scan(
        source_type=source_type, source_ref=source_ref, source_label=source_label, tools=tools
    )
    s.add(scan)
    s.commit()
    return scan


def list_scans(s: Session, limit: int = 20) -> list[Scan]:
    return list(s.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)))


def get_scan(s: Session, scan_id: str) -> Scan | None:
    return s.get(Scan, scan_id)


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


def add_findings(s: Session, scan_id: str, findings: list[Finding]) -> None:
    seen: set[str] = set()
    for f in findings:
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
            )
        )
    s.commit()


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
        return FindingPage(len(rows), [r.data for r in rows[offset : offset + limit]])
    total = s.scalar(select(func.count()).select_from(FindingRow).where(*conds)) or 0
    order: list[Any]
    if sort == "path":
        order = [FindingRow.path, FindingRow.start_line]
    elif sort == "risk":
        order = [case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc()]
    else:
        order = [FindingRow.severity_rank.desc(), FindingRow.path, FindingRow.start_line]
    rows_q = rows_q.order_by(*order, FindingRow.pk).limit(limit).offset(offset)
    return FindingPage(total, [r.data for r in s.scalars(rows_q)])


def _sort(rows: list[FindingRow], sort: str) -> list[FindingRow]:
    if sort == "path":
        return sorted(rows, key=lambda r: (r.path, r.start_line, r.pk))
    if sort == "risk":
        return sorted(
            rows, key=lambda r: (-(r.risk_score if r.risk_score is not None else -1), r.pk)
        )
    return sorted(rows, key=lambda r: (-r.severity_rank, r.path, r.start_line, r.pk))


def severity_counts(s: Session, scan_id: str) -> dict[str, int]:
    rows = s.execute(
        select(FindingRow.severity, func.count())
        .where(FindingRow.scan_id == scan_id)
        .group_by(FindingRow.severity)
    ).all()
    return {sev: n for sev, n in rows}
