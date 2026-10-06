"""The retest workflow (plan §43.3, Week 64).

    open --> developer marks "ready for retest" --> retest requested
                                                         |
                       tester confirms fixed <-----------+-----------> tester reproduces it
                       -> Issue fixed ("passed")                       -> back to open ("failed"),
                                                                          with the tester's note

- **People decide** with `request`, `confirm_fixed` and `reproduced` (a note is required: what was
  seen), or `cancel` a request. Each is a hash-chained audit entry and an outbox event, and appears
  in the Issue's history.
- **For a scanner's Issue, the next scan is the retest** (`on_ingest`): an Issue with a retest
  requested that the next scan or upload no longer reports passes, and one it still reports fails,
  with the source named. Both are staged in the same transaction as the scan's results (an outbox
  event each); they are the scan's outcome, not a person's decision, so they are not audit entries.
- **A targeted retest** re-runs only the one check against the one location (`core.retest.targeted`)
  and decides the same way.

A confirmed fix is not final: if a later scan or upload reports the Issue again, it is reopened as
"reintroduced", as any fixed Issue would be.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import Asset, IssueRow
from core.sla.policy import OPEN_STATES

ACTIONS = ("request", "confirm_fixed", "reproduced", "cancel")
MAX_NOTE = 5000


class RetestError(ValueError):
    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _org(s: Session, issue: IssueRow) -> str:
    asset = s.get(Asset, issue.asset_id)
    assert asset is not None
    return asset.org_id


def _note(note: str | None, *, required: bool = False) -> str | None:
    value = (note or "").strip()
    if required and not value:
        raise RetestError("note", "Say what you saw: the note is required.")
    if len(value) > MAX_NOTE:
        raise RetestError("note", f"The note is at most {MAX_NOTE} characters.")
    return value or None


def _event(s: Session, issue: IssueRow, event: str, **extra: Any) -> None:
    repo.add_outbox_event(
        s, org_id=_org(s, issue), event_type=f"issue.retest_{event}",
        payload={"issue_id": issue.id, "asset_id": issue.asset_id, **extra},
    )  # fmt: skip


def act(
    s: Session,
    issue: IssueRow,
    action: str,
    *,
    actor: str,
    note: str | None = None,
    event_extra: dict[str, Any] | None = None,
) -> IssueRow:
    """One step of the workflow, by a person (or a rule, which passes its chain depth in
    `event_extra`). Audit-logged (commits)."""
    if action not in ACTIONS:
        raise RetestError("action", f"One of: {', '.join(ACTIONS)}.")
    now = _now()
    if action == "request":
        if issue.state not in OPEN_STATES:
            raise RetestError("action", "Only an open issue can be marked ready for retest.")
        if issue.retest_status == "requested":
            raise RetestError("action", "A retest is already requested.")
        issue.retest_status, issue.retest_note = "requested", _note(note)
        issue.retest_requested_at, issue.retest_requested_by = now, actor
        issue.retest_decided_at = issue.retest_decided_by = None
    else:
        if issue.retest_status != "requested":
            raise RetestError("action", "No retest is requested for this issue.")
        if action == "cancel":
            issue.retest_status, issue.retest_note = None, _note(note)
        elif action == "confirm_fixed":
            issue.retest_status, issue.retest_note = "passed", _note(note)
            issue.state, issue.fixed_at = "fixed", now
        else:  # reproduced
            issue.retest_status, issue.retest_note = "failed", _note(note, required=True)
            if issue.state not in OPEN_STATES:
                issue.state = "open"
        if action != "cancel":
            issue.retest_decided_at, issue.retest_decided_by = now, actor
    event = {"request": "requested", "confirm_fixed": "passed", "reproduced": "failed",
             "cancel": "cancelled"}[action]  # fmt: skip
    _event(s, issue, event, by=actor, **(event_extra or {}))
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=actor, action=f"issue.retest.{event}", target=issue.id,
        payload={"asset_id": issue.asset_id, "note": issue.retest_note},
    )  # fmt: skip
    return issue


def decide_automatically(
    s: Session, issue: IssueRow, *, still_reported: bool, by: str, detail: str
) -> bool:
    """A scan, an upload or a targeted retest answered a requested retest. Stages only."""
    if issue.retest_status != "requested":
        return False
    now = _now()
    issue.retest_decided_at, issue.retest_decided_by = now, by
    if still_reported:
        issue.retest_status, issue.retest_note = "failed", detail
        if issue.state not in OPEN_STATES:
            issue.state, issue.fixed_at = "open", None
    else:
        issue.retest_status, issue.retest_note = "passed", detail
        if issue.state in OPEN_STATES:
            issue.state, issue.fixed_at = "fixed", now
    _event(s, issue, "failed" if still_reported else "passed", by=by, detail=detail)
    return True


def on_ingest(
    s: Session, rows: dict[str, IssueRow], *, still: list[str], closed: list[str], source: str
) -> int:
    """After a scan or upload is applied (`repo.apply_reimport_plan`): the next scan is the retest.
    `still` are Issues it reports again; `closed` are Issues it closed. Stages only."""
    decided = 0
    for issue_id in still:
        row = rows.get(issue_id)
        if row is not None and decide_automatically(
            s, row, still_reported=True, by=source, detail=f"Still reported by {source}."
        ):
            decided += 1
    for issue_id in closed:
        row = rows.get(issue_id)
        if row is not None and decide_automatically(
            s, row, still_reported=False, by=source, detail=f"No longer reported by {source}."
        ):
            decided += 1
    return decided


def view(issue: IssueRow) -> dict[str, Any]:
    return {
        "status": issue.retest_status,
        "requested_at": issue.retest_requested_at,
        "requested_by": issue.retest_requested_by,
        "note": issue.retest_note,
        "decided_at": issue.retest_decided_at,
        "decided_by": issue.retest_decided_by,
    }


def requested(s: Session, asset_id: str) -> list[IssueRow]:
    return list(
        s.scalars(
            select(IssueRow).where(
                IssueRow.asset_id == asset_id, IssueRow.retest_status == "requested"
            )
        )
    )
