"""Issue groups (plan §41.2, §49): Issues in one project that one ticket tracks together -- the
same library's five CVEs, or one feature's three findings. An Issue is in at most one group.
Joining or leaving is audit-logged on the Issue; a group that empties stays, so its ticket link
keeps meaning something.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import IssueGroup, IssueRow

MAX_NAME = 120


class GroupError(ValueError):
    field = "group"


def _name(raw: str) -> str:
    name = " ".join(str(raw or "").split())
    if not name:
        raise GroupError("Name the group.")
    if len(name) > MAX_NAME:
        raise GroupError(f"A group's name is at most {MAX_NAME} characters.")
    return name


def get(s: Session, org_id: str, group_id: str) -> IssueGroup | None:
    return s.scalars(
        select(IssueGroup).where(IssueGroup.id == group_id, IssueGroup.org_id == org_id)
    ).one_or_none()


def by_name(s: Session, asset_id: str, name: str) -> IssueGroup | None:
    return s.scalars(
        select(IssueGroup).where(IssueGroup.asset_id == asset_id, IssueGroup.name == _name(name))
    ).one_or_none()


def for_project(s: Session, org_id: str, asset_id: str) -> list[tuple[IssueGroup, int]]:
    rows = s.execute(
        select(IssueGroup, func.count(IssueRow.id))
        .outerjoin(IssueRow, IssueRow.group_id == IssueGroup.id)
        .where(IssueGroup.org_id == org_id, IssueGroup.asset_id == asset_id)
        .group_by(IssueGroup.id)
        .order_by(IssueGroup.name)
    )
    return [(g, int(n)) for g, n in rows]


def members(s: Session, group_id: str) -> list[IssueRow]:
    return list(
        s.scalars(
            select(IssueRow).where(IssueRow.group_id == group_id).order_by(IssueRow.first_seen_at)
        )
    )


def get_or_create(s: Session, org_id: str, asset_id: str, name: str, *, actor: str) -> IssueGroup:
    found = by_name(s, asset_id, name)
    if found is not None:
        return found
    g = IssueGroup(org_id=org_id, asset_id=asset_id, name=_name(name), created_by=actor)
    s.add(g)
    s.flush()
    return g


def set_group(
    s: Session, org_id: str, issue: IssueRow, group: IssueGroup | None, *, actor: str
) -> bool:
    """Put the Issue in `group` (or in none). False when nothing changed. Commits."""
    if group is not None and group.asset_id != issue.asset_id:
        raise GroupError("A group belongs to one project; this issue is in another.")
    new = group.id if group else None
    if issue.group_id == new:
        return False
    previous = issue.group_id
    issue.group_id = new
    s.flush()
    repo.append_audit_entry(  # commits
        s,
        actor=actor,
        action="issue.group.joined" if group else "issue.group.left",
        target=issue.id,
        payload={
            "asset_id": issue.asset_id,
            "group_id": new,
            "previous": previous,
            "name": group.name if group else None,
            "org_id": org_id,
        },
    )
    return True
