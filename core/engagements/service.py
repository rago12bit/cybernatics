"""Assessment engagements (plan §43.1, §55.2, Week 64).

An assessment -- a pen test, an audit -- is an `Engagement` of any type but the standing "ci" and
"import" ones. It has a scope (targets, routes, what is out of scope), a lead and testers (names, or
API token names, until user accounts exist), dates, a status, and optionally an OWASP checklist.

- **Lifecycle.** planned -> in progress -> reporting -> closed; reporting can go back to in
  progress, and a closed one can be reopened (to in progress). Closing is its own action
  (`close`): it writes the report. Every change is a hash-chained audit entry.
- **Findings** are every Issue reported by any upload into the engagement's Tests that has not been
  reverted -- manual findings and imported tool reports alike -- shown with what they are now
  (open, fixed, retest requested), so findings fixed during the test stay in its report. Where
  another source reports the same Issue (a scan, another engagement), it says so: cross-source
  correlation where the tester works (§55.2).
- **The report** is a snapshot taken on closing (`core.engagements.report`): a later change to an
  Issue never rewrites what was reported. The full report builder is Week 72; this is its fixed
  engagement template.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.engagements import checklists
from core.persistence import repo
from core.persistence.models import (
    Asset,
    Engagement,
    EngagementChecklistItem,
    EngagementTest,
    FindingRow,
    ImportRecord,
    IssueRow,
    ManualFinding,
    Scan,
)

STANDING = ("ci", "import")
TYPES = ("pentest", "audit", "assessment", "adhoc")
STATUSES = ("planned", "in_progress", "reporting", "closed")
TRANSITIONS = {
    "planned": {"in_progress"},
    "in_progress": {"planned", "reporting"},
    "reporting": {"in_progress"},
    "closed": {"in_progress"},  # reopen
}
CHECK_STATUSES = ("in_progress", "pass", "fail", "not_applicable")
DONE = frozenset({"pass", "fail", "not_applicable"})
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
MAX_LIST = 50
MAX_ITEM = 300
MAX_TEXT = 5000


class EngagementError(ValueError):
    """The change cannot be made as given; `field` names what to fix."""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_assessment(e: Engagement) -> bool:
    return e.engagement_type not in STANDING


def _text(raw: Any, field: str, *, required: bool = False, limit: int = MAX_TEXT) -> str | None:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        if required:
            raise EngagementError(field, f"{field.replace('_', ' ').capitalize()} is required.")
        return None
    if not isinstance(raw, str):
        raise EngagementError(field, f"{field.replace('_', ' ').capitalize()} is text.")
    value = " ".join(raw.split()) if limit <= MAX_ITEM else raw.strip()
    if len(value) > limit:
        raise EngagementError(
            field, f"{field.replace('_', ' ').capitalize()} is at most {limit} characters."
        )
    return value


def _list(raw: Any, field: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise EngagementError(field, "A list of text entries.")
    out: list[str] = []
    for x in raw:
        v = " ".join(x.split())
        if not v or v in out:
            continue
        if len(v) > MAX_ITEM:
            raise EngagementError(field, f"Each entry is at most {MAX_ITEM} characters.")
        out.append(v)
    if len(out) > MAX_LIST:
        raise EngagementError(field, f"At most {MAX_LIST} entries.")
    return out


def _date(raw: Any, field: str) -> datetime | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        return _aware(raw)
    try:
        return _aware(datetime.fromisoformat(str(raw).replace("Z", "+00:00")))
    except ValueError as exc:
        raise EngagementError(field, "A date, like 2026-10-02.") from exc


def _checklist(raw: Any) -> str | None:
    if raw is None or raw == "":
        return None
    if checklists.get(str(raw)) is None:
        raise EngagementError("checklist", f"One of: {', '.join(checklists.catalogue())}, or none.")
    return str(raw)


EDITABLE = ("name", "scope_targets", "scope_routes", "out_of_scope", "lead", "testers",
            "starts_at", "ends_at", "checklist")  # fmt: skip


def _apply(e: Engagement, data: dict[str, Any]) -> list[str]:
    """Validate and set the editable fields present in `data`; returns the names that changed."""
    changed: list[str] = []

    def put(attr: str, value: Any, key: str) -> None:
        if getattr(e, attr) != value:
            setattr(e, attr, value)
            changed.append(key)

    if "name" in data:
        put("name", _text(data["name"], "name", required=True, limit=MAX_ITEM), "name")
    for key in ("scope_targets", "scope_routes", "testers"):
        if key in data:
            put(key, _list(data[key], key), key)
    if "out_of_scope" in data:
        put("out_of_scope", _text(data["out_of_scope"], "out_of_scope"), "out_of_scope")
    if "lead" in data:
        put("lead", _text(data["lead"], "lead", limit=200), "lead")
    if "starts_at" in data:
        start = _date(data["starts_at"], "starts_at")
        put("started_at", start or e.started_at or _now(), "starts_at")
    if "ends_at" in data:
        put("target_end_at", _date(data["ends_at"], "ends_at"), "ends_at")
    if "checklist" in data:
        put("checklist", _checklist(data["checklist"]), "checklist")
    if e.target_end_at is not None and e.started_at is not None:
        if _aware(e.target_end_at) < _aware(e.started_at):  # type: ignore[operator]
            raise EngagementError("ends_at", "The end date is after the start date.")
    return changed


def _audit(s: Session, e: Engagement, actor: str, action: str, **payload: Any) -> None:
    repo.append_audit_entry(  # commits
        s, actor=actor, action=action, target=f"engagement:{e.id}",
        payload={"org_id": e.org_id, "asset_id": e.asset_id, **payload},
    )  # fmt: skip


def create(
    s: Session, *, org_id: str, asset_id: str, data: dict[str, Any], actor: str
) -> Engagement:
    kind = data.get("engagement_type") or "pentest"
    if kind not in TYPES:
        raise EngagementError("engagement_type", f"One of: {', '.join(TYPES)}.")
    status = data.get("status") or "planned"
    if status not in ("planned", "in_progress"):
        raise EngagementError("status", "A new engagement is planned or in progress.")
    e = Engagement(
        org_id=org_id, asset_id=asset_id, name="", engagement_type=kind, status=status,
        scope_targets=[], scope_routes=[], testers=[], created_by=actor, started_at=_now(),
    )  # fmt: skip
    _apply(e, {**data, "name": data.get("name")})
    s.add(e)
    s.flush()
    repo.add_outbox_event(
        s, org_id=org_id, event_type="engagement.created",
        payload={"engagement_id": e.id, "asset_id": asset_id},
    )  # fmt: skip
    _audit(s, e, actor, "engagement.created", name=e.name, status=e.status)
    return e


def update(s: Session, e: Engagement, data: dict[str, Any], *, actor: str) -> Engagement:
    """Edit fields, or move along the lifecycle (`status`). A closed engagement is read-only until
    it is reopened; closing itself is `close`."""
    new_status = data.get("status")
    fields = {k: v for k, v in data.items() if k in EDITABLE}
    if e.status == "closed" and fields:
        raise EngagementError("status", "A closed engagement is read-only. Reopen it to edit.")
    changed = _apply(e, fields)
    if new_status is not None and new_status != e.status:
        if new_status == "closed":
            raise EngagementError("status", "Close it with 'Close and write the report'.")
        if new_status not in TRANSITIONS.get(e.status, set()):
            raise EngagementError(
                "status", f"An engagement {e.status.replace('_', ' ')} cannot become "
                f"{str(new_status).replace('_', ' ')}."
            )  # fmt: skip
        old, e.status = e.status, new_status
        if old == "closed":
            e.closed_at = None
        repo.add_outbox_event(
            s, org_id=e.org_id, event_type="engagement.status_changed",
            payload={"engagement_id": e.id, "from": old, "to": new_status},
        )  # fmt: skip
        s.flush()
        _audit(s, e, actor, "engagement.reopened" if old == "closed" else "engagement.status",
               to=new_status, **{"from": old})  # fmt: skip
    if changed:
        s.flush()
        _audit(s, e, actor, "engagement.updated", fields=changed)
    if not changed and new_status in (None, e.status):
        s.commit()
    return e


def list_for_project(s: Session, asset_id: str, org_id: str) -> list[Engagement]:
    return [e for e in repo.list_engagements_for_asset(s, asset_id, org_id) if is_assessment(e)]


def get(s: Session, engagement_id: str, org_id: str) -> Engagement | None:
    e = repo.get_engagement(s, engagement_id, org_id)
    return e if e is not None and is_assessment(e) else None


# --- tests and findings ---------------------------------------------------------------------------


def _applied(s: Session, test_ids: list[str]) -> list[ImportRecord]:
    if not test_ids:
        return []
    return list(
        s.scalars(
            select(ImportRecord)
            .where(ImportRecord.test_id.in_(test_ids), ImportRecord.status == "applied")
            .order_by(ImportRecord.created_at)
        )
    )


def tests(s: Session, e: Engagement) -> list[dict[str, Any]]:
    """Each Test with how many Issues its uploads reported and when it last received one."""
    ts = repo.list_engagement_tests(s, e.id, e.org_id)
    imports = _applied(s, [t.id for t in ts])
    by_test: dict[str, list[ImportRecord]] = defaultdict(list)
    for r in imports:
        by_test[r.test_id].append(r)
    scan_test = {r.scan_id: r.test_id for r in imports if r.scan_id}
    issues: dict[str, set[str]] = defaultdict(set)
    if scan_test:
        for scan_id, issue_id in s.execute(
            select(FindingRow.scan_id, FindingRow.issue_id).where(
                FindingRow.scan_id.in_(list(scan_test)), FindingRow.issue_id.is_not(None)
            )
        ):
            issues[scan_test[scan_id]].add(issue_id)
    return [
        {
            "id": t.id,
            "name": t.name,
            "parser": t.parser,
            "findings": len(issues[t.id]),
            "uploads": len(by_test[t.id]),
            "last_upload_at": by_test[t.id][-1].created_at if by_test[t.id] else None,
        }
        for t in ts
    ]


def findings(s: Session, e: Engagement) -> list[dict[str, Any]]:
    """Every Issue the engagement's uploads reported, most severe first, as it stands now."""
    ts = repo.list_engagement_tests(s, e.id, e.org_id)
    name_of = {t.id: t.name for t in ts}
    imports = _applied(s, list(name_of))
    own_scans = {r.scan_id: r.test_id for r in imports if r.scan_id}
    if not own_scans:
        return []
    test_of: dict[str, str] = {}
    for scan_id, issue_id in s.execute(
        select(FindingRow.scan_id, FindingRow.issue_id).where(
            FindingRow.scan_id.in_(list(own_scans)), FindingRow.issue_id.is_not(None)
        )
    ):
        test_of.setdefault(issue_id, name_of[own_scans[scan_id]])
    rows = {i.id: i for i in s.scalars(select(IssueRow).where(IssueRow.id.in_(list(test_of))))}
    # Who else reports each Issue: scanners (their tool names), other Tests (their names).
    also: dict[str, set[str]] = defaultdict(set)
    for issue_id, tools, source_type, label in s.execute(
        select(FindingRow.issue_id, FindingRow.tools, Scan.source_type, Scan.source_label)
        .join(Scan, Scan.id == FindingRow.scan_id)
        .where(FindingRow.issue_id.in_(list(rows)), FindingRow.scan_id.notin_(list(own_scans)))
    ):
        if source_type == "import":  # another Test: its name ("Nessus: scan.xml" -> "Nessus")
            also[issue_id].add(str(label).split(": ", 1)[0])
        else:
            also[issue_id].update(n for n in (tools or []) if n != "manual")
    manual = {
        mf.issue_id: mf
        for mf in s.scalars(select(ManualFinding).where(ManualFinding.issue_id.in_(list(rows))))
    }
    for mf in manual.values():
        if mf.related_source:
            also[mf.issue_id].add(f"{mf.related_source} taint")
    out: list[dict[str, Any]] = []
    ordered = sorted(
        rows.values(),
        key=lambda i: (-SEVERITY_RANK.get(i.severity, 0), i.state == "fixed", i.title),
    )
    for issue in ordered:
        m = manual.get(issue.id)
        out.append(
            {
                "issue_id": issue.id,
                "title": issue.title,
                "severity": issue.severity,
                "path": issue.path,
                "state": issue.state,
                "triage_status": issue.triage_status,
                "retest_status": issue.retest_status,
                "retest_requested_by": issue.retest_requested_by,
                "priority_band": issue.priority_band,
                "test": test_of[issue.id],
                "manual_finding_id": m.id if m else None,
                "also_found_by": sorted(also[issue.id]),
                "first_seen_at": issue.first_seen_at,
                "fixed_at": issue.fixed_at,
            }
        )
    return out


# --- checklist ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChecklistState:
    checklist: checklists.Checklist
    rows: dict[str, EngagementChecklistItem]

    def summary(self) -> dict[str, Any]:
        counts = dict.fromkeys(CHECK_STATUSES, 0)
        for r in self.rows.values():
            if r.status in counts and self.checklist.has(r.item_id):
                counts[r.status] += 1
        total = len(self.checklist.items)
        done = sum(counts[k] for k in DONE)
        return {"id": self.checklist.id, "name": self.checklist.name, "total": total, "done": done,
                **counts, "attribution": checklists.ATTRIBUTION}  # fmt: skip


def checklist_state(s: Session, e: Engagement) -> ChecklistState | None:
    c = checklists.get(e.checklist)
    if c is None:
        return None
    rows = {
        r.item_id: r
        for r in s.scalars(
            select(EngagementChecklistItem).where(EngagementChecklistItem.engagement_id == e.id)
        )
    }
    return ChecklistState(c, rows)


def set_item(
    s: Session, e: Engagement, item_id: str, status: str | None, note: str | None, *, actor: str
) -> EngagementChecklistItem | None:
    """Record one checklist entry's result; `status=None` clears it back to not started."""
    c = checklists.get(e.checklist)
    if c is None:
        raise EngagementError("checklist", "This engagement has no checklist.")
    if e.status == "closed":
        raise EngagementError("status", "A closed engagement is read-only. Reopen it to edit.")
    if not c.has(item_id):
        raise EngagementError("item_id", f"{item_id} is not in {c.name}.")
    if status is not None and status not in CHECK_STATUSES:
        raise EngagementError("status", f"One of: {', '.join(CHECK_STATUSES)}, or none.")
    note = _text(note, "note")
    row = s.scalars(
        select(EngagementChecklistItem).where(
            EngagementChecklistItem.engagement_id == e.id,
            EngagementChecklistItem.item_id == item_id,
        )
    ).one_or_none()
    if status is None:
        if row is not None:
            s.delete(row)
        row = None
    else:
        if row is None:
            row = EngagementChecklistItem(org_id=e.org_id, engagement_id=e.id, item_id=item_id,
                                          status=status)  # fmt: skip
            s.add(row)
        row.status, row.note, row.updated_by, row.updated_at = status, note, actor, _now()
    s.flush()
    _audit(s, e, actor, "engagement.checklist", item=item_id, status=status)
    return row


# --- closing --------------------------------------------------------------------------------------


def close(s: Session, e: Engagement, *, actor: str, summary: str | None = None) -> Engagement:
    """Close the engagement and write its report: a snapshot of scope, people, checklist, findings
    and tests as they are now."""
    if e.status not in ("in_progress", "reporting"):
        raise EngagementError(
            "status", "Only an engagement in progress or in reporting can be closed."
        )
    from core.engagements.report import snapshot

    now = _now()
    e.report = snapshot(s, e, generated_at=now, generated_by=actor,
                        summary=_text(summary, "summary"))  # fmt: skip
    e.report_generated_at, e.closed_at, old, e.status = now, now, e.status, "closed"
    repo.add_outbox_event(
        s, org_id=e.org_id, event_type="engagement.closed",
        payload={"engagement_id": e.id, "asset_id": e.asset_id,
                 "findings": len(e.report["findings"])},
    )  # fmt: skip
    s.flush()
    _audit(s, e, actor, "engagement.closed", **{"from": old},
           findings=len(e.report["findings"]))  # fmt: skip
    return e


def project_label(s: Session, e: Engagement) -> str:
    a = s.get(Asset, e.asset_id)
    return a.label if a is not None else e.asset_id


def test_by_id(s: Session, test_id: str, org_id: str) -> EngagementTest | None:
    return repo.get_engagement_test(s, test_id, org_id)
