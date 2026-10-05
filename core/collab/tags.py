"""Tags (plan §49): "tags inherit downward from portfolio to project to issue."

A tag is set on a portfolio, a project or an Issue. An Issue's tags are its own, plus its
project's, plus the project's portfolio's; a project's are its own plus its portfolio's. Inherited
tags are shown as inherited and changed where they are set, never on the Issue. The issues table
filters by a tag wherever it was set (`issue_clause`), in SQL.

Names are lowercase; spaces become dashes; letters, digits and `: . _ / -` are kept, up to 50
characters, at most 20 per target.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import ColumnElement, and_, delete, or_, select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import Asset, IssueRow, Portfolio, Tag

TARGETS = ("portfolio", "project", "issue")
MAX_TAGS = 20
_NAME = re.compile(r"^[a-z0-9][a-z0-9:._/-]{0,49}$")


class TagError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.field = "tags"


def normalize(raw: str) -> str:
    name = "-".join(str(raw).strip().lower().split())
    if not _NAME.match(name):
        raise TagError(
            f"'{str(raw)[:60]}' is not a tag: up to 50 letters, digits and : . _ / - "
            "starting with a letter or digit."
        )
    return name


def own(s: Session, target_type: str, target_id: str) -> list[str]:
    return sorted(
        s.scalars(
            select(Tag.name).where(Tag.target_type == target_type, Tag.target_id == target_id)
        )
    )


def replace(
    s: Session,
    *,
    org_id: str,
    target_type: str,
    target_id: str,
    names: list[str],
    actor: str,
) -> list[str]:
    """Set the target's own tags to exactly `names`. Audit-logged when anything changed."""
    if target_type not in TARGETS:
        raise ValueError(target_type)
    wanted: list[str] = []
    for n in names:
        tag = normalize(n)
        if tag not in wanted:
            wanted.append(tag)
    if len(wanted) > MAX_TAGS:
        raise TagError(f"At most {MAX_TAGS} tags.")
    before = own(s, target_type, target_id)
    if sorted(wanted) == before:
        return before
    s.execute(delete(Tag).where(Tag.target_type == target_type, Tag.target_id == target_id))
    for name in wanted:
        s.add(Tag(org_id=org_id, target_type=target_type, target_id=target_id, name=name,
                  created_by=actor))  # fmt: skip
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=actor, action="tags.changed",
        target=target_id if target_type == "issue" else f"{target_type}:{target_id}",
        payload={"org_id": org_id, "type": target_type,
                 "added": sorted(set(wanted) - set(before)),
                 "removed": sorted(set(before) - set(wanted))},
    )  # fmt: skip
    return sorted(wanted)


def for_project(s: Session, asset: Asset) -> dict[str, Any]:
    portfolio = s.get(Portfolio, asset.portfolio_id) if asset.portfolio_id else None
    inherited = own(s, "portfolio", portfolio.id) if portfolio else []
    mine = own(s, "project", asset.id)
    return {
        "own": mine,
        "inherited": [{"name": n, "from": "portfolio", "source": portfolio.name}
                      for n in inherited if n not in mine] if portfolio else [],  # fmt: skip
         "portfolio": {"id": portfolio.id, "name": portfolio.name} if portfolio else None,
    }


def for_issue(s: Session, issue: IssueRow) -> dict[str, Any]:
    asset = s.get(Asset, issue.asset_id)
    assert asset is not None
    project = for_project(s, asset)
    mine = own(s, "issue", issue.id)
    inherited = [{"name": n, "from": "project", "source": asset.label}
                 for n in project["own"] if n not in mine]  # fmt: skip
    inherited += [t for t in project["inherited"] if t["name"] not in mine
                  and t["name"] not in project["own"]]  # fmt: skip
    return {"own": mine, "inherited": inherited,
            "all": sorted({*mine, *(t["name"] for t in inherited)})}  # fmt: skip


def issue_clause(names: list[str]) -> ColumnElement[bool]:
    """SQL for "the Issue has one of these tags, set on it, its project or its portfolio"."""
    wanted = [normalize(n) for n in names]

    def targets(kind: str) -> Any:
        return select(Tag.target_id).where(Tag.target_type == kind, Tag.name.in_(wanted))

    return or_(
        IssueRow.id.in_(targets("issue")),
        IssueRow.asset_id.in_(targets("project")),
        IssueRow.asset_id.in_(
            select(Asset.id).where(
                and_(Asset.portfolio_id.is_not(None), Asset.portfolio_id.in_(targets("portfolio")))
            )
        ),
    )


def set_portfolio(
    s: Session, asset: Asset, portfolio_id: str | None, *, org_id: str, actor: str
) -> Asset:
    if portfolio_id is not None and repo.get_portfolio(s, portfolio_id, org_id) is None:
        raise TagError("That portfolio does not exist.")
    if asset.portfolio_id == portfolio_id:
        return asset
    old, asset.portfolio_id = asset.portfolio_id, portfolio_id
    s.flush()
    repo.append_audit_entry(
        s, actor=actor, action="project.portfolio", target=f"project:{asset.id}",
        payload={"org_id": org_id, "from": old, "to": portfolio_id},
    )  # fmt: skip
    return asset
