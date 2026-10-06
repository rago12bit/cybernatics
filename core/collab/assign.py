"""Who owns an Issue's fix (plan §45's "assign to @payments-oncall"), set by a person or a rule.

An assignee is a person: one of the organization's live personal tokens, named by its @handle,
until user accounts exist (Week 75). A handle two tokens share is refused rather than guessed.
Each change is a hash-chained audit entry and an `issue.assigned` outbox event, which rules and
notifications read; assigning someone who already has it changes nothing and announces nothing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from core.collab.people import Person, people
from core.persistence import repo
from core.persistence.models import Asset, IssueRow


class AssignError(ValueError):
    field = "to"


def resolve(s: Session, org_id: str, handle: str) -> Person:
    wanted = handle.strip().lstrip("@").lower()
    if not wanted:
        raise AssignError("Name a person by their @handle.")
    found = [p for p in people(s, org_id) if p.handle == wanted]
    if not found:
        raise AssignError(f"Nobody in this organization is @{wanted}.")
    if len(found) > 1:
        raise AssignError(
            f"@{wanted} is {len(found)} people ({', '.join(p.name for p in found)}); "
            "rename one of their tokens first."
        )
    return found[0]


def assign(
    s: Session,
    issue: IssueRow,
    to: str | None,
    *,
    actor: str,
    event_extra: dict[str, Any] | None = None,
) -> bool:
    """Set (or, with `to=None`, clear) the assignee. Returns False when nothing changed.
    Commits (the audit entry)."""
    asset = s.get(Asset, issue.asset_id)
    assert asset is not None
    target = resolve(s, asset.org_id, to).actor if to else None
    if target == issue.assignee:
        return False
    previous = issue.assignee
    issue.assignee = target
    issue.assigned_at = datetime.now(timezone.utc) if target else None
    repo.add_outbox_event(
        s, org_id=asset.org_id, event_type="issue.assigned" if target else "issue.unassigned",
        payload={"issue_id": issue.id, "asset_id": issue.asset_id, "assignee": target,
                 "previous": previous, "by": actor, **(event_extra or {})},
    )  # fmt: skip
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=actor, action="issue.assigned" if target else "issue.unassigned",
        target=issue.id,
        payload={"asset_id": issue.asset_id, "assignee": target, "previous": previous},
    )  # fmt: skip
    return True
