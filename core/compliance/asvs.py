"""The ASVS benchmark of one project (plan §47): every ASVS 4.0.3 requirement up to a level, with a
status and links to the evidence.

A person sets a requirement met, not met or not applicable, with a note and links. Without that,
the status is what the evidence shows, never more: "not met" when an assessment of the project
failed it, "Issues open" when the project has open Issues of the requirement's CWE, "tested" when
an assessment passed it, else "not assessed". Bulwark never marks a requirement met by itself --
the absence of findings is not evidence that a control works.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.compliance import get
from core.issues import LIVE_STATES
from core.persistence import repo
from core.persistence.models import (
    ComplianceStatus,
    Engagement,
    EngagementChecklistItem,
    FindingRow,
    IssueRow,
)

FRAMEWORK = "asvs-4.0.3"
PERSON = ("met", "not_met", "not_applicable")
MAX_LINKS = 10


class ComplianceError(ValueError):
    pass


def _active(i: IssueRow, now: datetime) -> bool:
    return _active_row(i.triage_status, i.triage_expires_at, now)


def _active_row(triage_status: str, expires: datetime | None, now: datetime) -> bool:
    if triage_status == "not_a_risk":
        return False
    if triage_status == "accepted":
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires is not None and expires <= now
    return True


def open_issues_by_cwe(s: Session, asset_id: str) -> dict[str, list[str]]:
    """CWE -> the project's open Issues of it (from each Issue's latest occurrence). Reads only the
    occurrence's CWEs, not the whole stored finding."""
    now = datetime.now(timezone.utc)
    ids = sorted(
        iid
        for iid, status, expires in s.execute(
            select(IssueRow.id, IssueRow.triage_status, IssueRow.triage_expires_at).where(
                IssueRow.asset_id == asset_id, IssueRow.state.in_(sorted(LIVE_STATES))
            )
        )
        if _active_row(status, expires, now)
    )
    out: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    cwe_of = FindingRow.data["taxonomy"]["cwe"]
    for k in range(0, len(ids), 1000):
        for issue_id, cwes in s.execute(
            select(FindingRow.issue_id, cwe_of)
            .where(FindingRow.issue_id.in_(ids[k : k + 1000]))
            .order_by(FindingRow.pk.desc())
        ):
            if issue_id in seen or issue_id is None:
                continue
            seen.add(issue_id)
            for cwe in cwes if isinstance(cwes, list) else []:
                out[str(cwe).upper()].append(issue_id)
    return dict(out)


def _assessments(s: Session, org_id: str, asset_id: str) -> dict[str, dict[str, Any]]:
    """Requirement -> the latest result of it in an assessment of this project."""
    out: dict[str, dict[str, Any]] = {}
    for item, eng in s.execute(
        select(EngagementChecklistItem, Engagement)
        .join(Engagement, Engagement.id == EngagementChecklistItem.engagement_id)
        .where(
            Engagement.org_id == org_id,
            Engagement.asset_id == asset_id,
            Engagement.checklist.like("asvs-%"),
        )
        .order_by(EngagementChecklistItem.updated_at)
    ):
        if item.status in ("pass", "fail", "not_applicable"):
            out[item.item_id] = {
                "status": item.status, "engagement_id": eng.id, "engagement": eng.name,
                "at": item.updated_at, "by": item.updated_by,
            }  # fmt: skip
    return out


def benchmark(
    s: Session,
    org_id: str,
    asset_id: str,
    level: int = 2,
    by_cwe: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    fw = get(FRAMEWORK)
    assert fw is not None
    person = {
        c.requirement: c
        for c in s.scalars(
            select(ComplianceStatus).where(
                ComplianceStatus.org_id == org_id,
                ComplianceStatus.asset_id == asset_id,
                ComplianceStatus.framework == FRAMEWORK,
            )
        )
    }
    by_cwe = open_issues_by_cwe(s, asset_id) if by_cwe is None else by_cwe
    tested = _assessments(s, org_id, asset_id)
    rows = []
    counts: dict[str, int] = defaultdict(int)
    for c in fw.controls:
        if (c.level or 0) > level:
            continue
        issues = sorted(set(by_cwe.get(c.cwes[0], []))) if c.cwes else []
        test = tested.get(c.id)
        p = person.get(c.id)
        if p is not None:
            status, source = p.status, "person"
        elif test and test["status"] == "fail":
            status, source = "not_met", "assessment"
        elif issues:
            status, source = "issues_open", "issues"
        elif test and test["status"] == "pass":
            status, source = "tested", "assessment"
        elif test and test["status"] == "not_applicable":
            status, source = "not_applicable", "assessment"
        else:
            status, source = "not_assessed", ""
        counts[status] += 1
        failed = bool(test and test["status"] == "fail")
        rows.append({
            "id": c.id, "group": c.group, "title": c.title, "level": c.level,
            "cwe": c.cwes[0] if c.cwes else None, "status": status, "source": source,
            "issues": len(issues), "issue_ids": issues[:5], "assessment": test,
            "note": p.note if p else "", "links": list(p.links) if p else [],
            "set_by": p.set_by if p else None, "set_at": p.set_at if p else None,
            "conflict": bool(p and p.status == "met" and (issues or failed)),
        })  # fmt: skip
    return {
        "framework": fw.summary(), "level": level, "counts": dict(counts), "requirements": rows,
        "disclaimer": (
            "A requirement is met only when a person says so. Open Issues and assessment results "
            "are shown as evidence; the absence of findings is not."
        ),
    }  # fmt: skip


def _links(links: list[str]) -> list[str]:
    out = []
    for raw in links[:MAX_LINKS]:
        link = raw.strip()
        if not link:
            continue
        if not (link.startswith(("https://", "http://")) or link.startswith("/app/")):
            raise ComplianceError("links must be http(s) addresses or Bulwark pages (/app/...)")
        out.append(link[:1000])
    return out


def set_status(
    s: Session,
    org_id: str,
    asset_id: str,
    requirement: str,
    *,
    status: str | None,
    note: str,
    links: list[str],
    actor: str,
) -> ComplianceStatus | None:
    """Set (or, with `status=None`, clear) a person's status for one requirement."""
    fw = get(FRAMEWORK)
    assert fw is not None
    if not any(c.id == requirement for c in fw.controls):
        raise ComplianceError(f"{requirement} is not an ASVS 4.0.3 requirement")
    row = s.scalars(
        select(ComplianceStatus).where(
            ComplianceStatus.org_id == org_id,
            ComplianceStatus.asset_id == asset_id,
            ComplianceStatus.framework == FRAMEWORK,
            ComplianceStatus.requirement == requirement,
        )
    ).first()
    if status is None:
        if row is not None:
            s.delete(row)
        repo.append_audit_entry(
            s, actor=actor, action="compliance.status_cleared", target=f"{asset_id}:{requirement}",
            org_id=org_id, payload={"framework": FRAMEWORK},
        )  # fmt: skip
        return None
    if status not in PERSON:
        raise ComplianceError(f"status must be one of {', '.join(PERSON)}")
    if status in ("met", "not_applicable") and not note.strip():
        raise ComplianceError(
            "say why: a note is required to mark a requirement met or not applicable"
        )
    clean = _links(links)
    if row is None:
        row = ComplianceStatus(
            org_id=org_id, asset_id=asset_id, framework=FRAMEWORK, requirement=requirement
        )
        s.add(row)
    row.status, row.note, row.links = status, note.strip()[:4000], clean
    row.set_by, row.set_at = actor, datetime.now(timezone.utc)
    repo.append_audit_entry(  # commits, with the status
        s, actor=actor, action="compliance.status_set", target=f"{asset_id}:{requirement}",
        org_id=org_id,
        payload={"framework": FRAMEWORK, "status": status, "note": row.note, "links": clean},
    )  # fmt: skip
    return row
