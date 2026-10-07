"""Who can be mentioned or named (plan §49): the organization's active user accounts (Week 75)
and, from before accounts, its live personal API tokens that belong to no account. A person named
"Priya N." is mentioned as `@priyan` -- the name lowercased with everything but letters, digits,
dots, dashes and underscores removed, and no punctuation at either end. Two people with the same
handle are both mentioned: Bulwark cannot tell them apart, and says so by listing both.

An actor is a person when it is `user:<id>` or `token:<prefix>`; the shared token, rules and
tickets are not people.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.identity.roles import SCOPES as ROLE_SCOPES
from core.persistence.models import ApiToken, User

_HANDLE_DROP = re.compile(r"[^a-z0-9._-]")


@dataclass(frozen=True)
class Person:
    actor: str  # "user:<id>" or "token:<display prefix>", as the audit log records it
    name: str
    handle: str


def is_person(actor: str | None) -> bool:
    return bool(actor) and (str(actor).startswith("user:") or str(actor).startswith("token:"))


def handle_of(name: str) -> str:
    return _HANDLE_DROP.sub("", name.lower()).strip("._-")[:64]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _live_tokens(s: Session, org_id: str) -> list[ApiToken]:
    """Personal tokens from before accounts: live, and belonging to no account (a token a person
    made acts as that person, so it is not a person of its own)."""
    now = datetime.now(timezone.utc)
    return [
        t
        for t in s.scalars(select(ApiToken).where(
            ApiToken.org_id == org_id, ApiToken.revoked_at.is_(None), ApiToken.user_id.is_(None)))
        if (t.expires_at is None or _aware(t.expires_at) > now) and list(t.scopes) != ["scim"]
    ]  # fmt: skip


def people(s: Session, org_id: str) -> list[Person]:
    out = []
    for u in s.scalars(select(User).where(User.org_id == org_id, User.active.is_(True))):
        handle = handle_of(u.name) or handle_of(u.email.split("@", 1)[0])
        if handle:
            out.append(Person(f"user:{u.id}", u.name, handle))
    for t in _live_tokens(s, org_id):
        handle = handle_of(t.name)
        if handle:
            out.append(Person(f"token:{t.display_prefix}", t.name, handle))
    return sorted(out, key=lambda p: (p.handle, p.actor))


def people_who_can(s: Session, org_id: str, scope: str) -> list[Person]:
    """People whose organization role (or, for a token from before accounts, whose scopes)
    allows `scope` -- who could approve a risk acceptance, who runs the rules."""
    out = []
    for u in s.scalars(select(User).where(User.org_id == org_id, User.active.is_(True))):
        if scope in ROLE_SCOPES[u.role]:
            out.append(Person(f"user:{u.id}", u.name, handle_of(u.name)))
    for t in _live_tokens(s, org_id):
        if scope in (t.scopes or []):
            out.append(Person(f"token:{t.display_prefix}", t.name, handle_of(t.name)))
    return sorted(out, key=lambda p: (p.name.lower(), p.actor))


def names(s: Session, org_id: str, actors: set[str]) -> dict[str, str]:
    """Display names for actors that are people; anything else shows as itself."""
    out: dict[str, str] = {}
    prefixes = [a.split(":", 1)[1] for a in actors if a.startswith("token:")]
    if prefixes:
        rows = s.execute(select(ApiToken.display_prefix, ApiToken.name).where(
            ApiToken.org_id == org_id, ApiToken.display_prefix.in_(prefixes)))  # fmt: skip
        out.update({f"token:{p}": n for p, n in rows})
    ids = [a.split(":", 1)[1] for a in actors if a.startswith("user:")]
    if ids:
        rows = s.execute(select(User.id, User.name).where(User.org_id == org_id,
                                                          User.id.in_(ids)))  # fmt: skip
        out.update({f"user:{i}": n for i, n in rows})
    return out
