"""Who can be mentioned or named (plan §49), until user accounts exist (Week 75): the
organization's live personal API tokens, by name. A token named "Priya N." is mentioned as
`@priyan` -- its name lowercased with everything but letters, digits, dots, dashes and underscores
removed, and no punctuation at either end. Two tokens with the same handle are both mentioned:
Bulwark cannot tell them apart, and says so by listing both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence.models import ApiToken

_HANDLE_DROP = re.compile(r"[^a-z0-9._-]")


@dataclass(frozen=True)
class Person:
    actor: str  # "token:<display prefix>", as the audit log records it
    name: str
    handle: str


def handle_of(name: str) -> str:
    return _HANDLE_DROP.sub("", name.lower()).strip("._-")[:64]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def people(s: Session, org_id: str) -> list[Person]:
    now = datetime.now(timezone.utc)
    out = []
    for t in s.scalars(
        select(ApiToken).where(ApiToken.org_id == org_id, ApiToken.revoked_at.is_(None))
    ):
        if t.expires_at is not None and _aware(t.expires_at) <= now:
            continue
        handle = handle_of(t.name)
        if handle:
            out.append(Person(f"token:{t.display_prefix}", t.name, handle))
    return sorted(out, key=lambda p: (p.handle, p.actor))


def names(s: Session, org_id: str, actors: set[str]) -> dict[str, str]:
    """Display names for actors that are personal tokens; anything else shows as itself."""
    prefixes = [a.split(":", 1)[1] for a in actors if a.startswith("token:")]
    if not prefixes:
        return {}
    rows = s.execute(
        select(ApiToken.display_prefix, ApiToken.name).where(
            ApiToken.org_id == org_id, ApiToken.display_prefix.in_(prefixes)
        )
    )
    return {f"token:{p}": n for p, n in rows}
