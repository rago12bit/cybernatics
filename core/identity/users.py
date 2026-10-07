"""People in an organization, their roles, and turning one off (Week 75, plan §51).

A user is created by an admin, by the identity provider over SCIM, or on a first sign-in when the
provider allows it (core.identity.sso). Turning a user off -- by an admin or by SCIM, "so someone
leaving the company loses access within minutes, not whenever someone remembers" -- revokes every
session and every API token they made, in the same transaction: the next request they make is
refused. Every change is audit-logged.

People are named by an @handle made from their name, as personal tokens were (core.collab.people).
A user's actor in the audit log, on assignments and on everything they own is `user:<id>`.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from core.identity.roles import ORG_ROLES, OVERRIDE_ROLES, Access
from core.persistence import repo
from core.persistence.models import ApiToken, Asset, Portfolio, RoleOverride, User, UserSession

SOURCES = ("admin", "oidc", "saml", "scim", "cli")
_EMAIL = re.compile(r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$")
# GitHub's own rule: letters, digits and single hyphens, not at either end, at most 39 characters.
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")


class UserError(ValueError):
    def __init__(self, field: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.field, self.message, self.status = field, message, status


def actor_of(user_id: str) -> str:
    return f"user:{user_id}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def clean_email(raw: Any) -> str:
    email = raw.strip().lower() if isinstance(raw, str) else ""
    if not _EMAIL.match(email) or len(email) > 320:
        raise UserError("email", "An email address, please.")
    return email


def _name(raw: Any, email: str) -> str:
    name = raw.strip() if isinstance(raw, str) else ""
    return (name or email.split("@", 1)[0])[:200]


def _role(raw: Any, field: str = "role", allowed: tuple[str, ...] = ORG_ROLES) -> str:
    if raw not in allowed:
        raise UserError(field, f"One of: {', '.join(allowed)}.")
    return str(raw)


def view(u: User) -> dict[str, Any]:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "active": u.active,
            "source": u.source, "external_id": u.external_id, "created_at": u.created_at,
            "last_login_at": u.last_login_at, "disabled_at": u.disabled_at,
            "deprovisioned_at": u.deprovisioned_at, "github_login": u.github_login,
            "actor": actor_of(u.id)}  # fmt: skip


def get(s: Session, org_id: str, user_id: str) -> User:
    u = s.get(User, user_id) if len(user_id) <= 36 else None
    if u is None or u.org_id != org_id:
        raise UserError("id", "No such person.", 404)
    return u


def by_email(s: Session, org_id: str, email: str) -> User | None:
    return s.scalar(select(User).where(User.org_id == org_id, User.email == email.lower()))


def listing(s: Session, org_id: str) -> list[User]:
    return list(s.scalars(select(User).where(User.org_id == org_id).order_by(User.email)))


def _audit(s: Session, actor: str, action: str, u: User, **payload: Any) -> None:
    repo.append_audit_entry(  # commits
        s, actor=actor, action=action, target=actor_of(u.id),
        payload={"org_id": u.org_id, "email": u.email, **payload},
    )  # fmt: skip


def create(
    s: Session, org_id: str, actor: str, *, email: Any, name: Any = None, role: Any = "member",
    source: str = "admin", external_id: str | None = None, commit: bool = True,
) -> User:  # fmt: skip
    email = clean_email(email)
    if by_email(s, org_id, email) is not None:
        raise UserError("email", f"{email} already has an account here.", 409)
    now = _now()
    u = User(org_id=org_id, email=email, name=_name(name, email), role=_role(role), active=True,
             external_id=external_id, source=source, created_at=now, updated_at=now)  # fmt: skip
    s.add(u)
    s.flush()
    if commit:
        _audit(s, actor, "user.created", u, role=u.role, source=source)
    return u


def update_user(s: Session, org_id: str, actor: str, user_id: str, raw: dict[str, Any]) -> User:
    u = get(s, org_id, user_id)
    changed: dict[str, Any] = {}
    if "name" in raw:
        u.name = _name(raw["name"], u.email)
        changed["name"] = u.name
    if "role" in raw and raw["role"] != u.role:
        role = _role(raw["role"])
        if u.role == "admin" and role != "admin":
            _keep_an_admin(s, org_id, u.id)
        changed["role"] = {"from": u.role, "to": role}
        u.role = role
    if "github_login" in raw:
        login = _github_login(s, u, raw["github_login"])
        if login != u.github_login:
            changed["github_login"] = {"from": u.github_login, "to": login}
            u.github_login = login
    if "active" in raw and bool(raw["active"]) != u.active:
        if not raw["active"]:
            return disable(s, org_id, actor, user_id, reason="by an admin")
        u.active, u.disabled_at = True, None
        changed["active"] = True
    if changed:
        u.updated_at = _now()
        s.flush()
        _audit(s, actor, "user.updated", u, **changed)
    return u


def _github_login(s: Session, u: User, raw: Any) -> str | None:
    """Who a `/fix` comment on a pull request is from (Week 76). Only an admin sets it: a person
    naming their own login could name someone else's. Empty unlinks."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    login = raw.strip().removeprefix("@") if isinstance(raw, str) else ""
    if not _GITHUB_LOGIN.match(login):
        raise UserError("github_login", "A GitHub username: letters, digits and hyphens.")
    taken = s.scalar(
        select(User.email).where(
            User.org_id == u.org_id, User.id != u.id,
            func.lower(User.github_login) == login.lower(),
        )
    )  # fmt: skip
    if taken is not None:
        raise UserError("github_login", f"{login} is already linked to {taken}.", 409)
    return login


def _keep_an_admin(s: Session, org_id: str, user_id: str) -> None:
    others = s.scalar(
        select(User.id)
        .where(User.org_id == org_id, User.role == "admin", User.active.is_(True),
               User.id != user_id)
        .limit(1)
    )  # fmt: skip
    if others is None:
        raise UserError("role", "The organization needs at least one active admin.", 409)


def revoke_access(s: Session, u: User, now: datetime) -> tuple[int, int]:
    """End every session and revoke every token the person made. Not committed."""
    sessions = s.execute(  # type: ignore[attr-defined]  # a CursorResult for an UPDATE
        update(UserSession).where(UserSession.user_id == u.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    ).rowcount  # fmt: skip
    tokens = s.execute(  # type: ignore[attr-defined]
        update(ApiToken).where(ApiToken.user_id == u.id, ApiToken.revoked_at.is_(None))
        .values(revoked_at=now)
    ).rowcount  # fmt: skip
    return int(sessions or 0), int(tokens or 0)


def disable(s: Session, org_id: str, actor: str, user_id: str, *, reason: str) -> User:
    """Turn a person off: they can no longer sign in, and every session and token they had ends
    now."""
    u = get(s, org_id, user_id)
    if u.role == "admin" and u.active:
        _keep_an_admin(s, org_id, u.id)
    now = _now()
    u.active, u.disabled_at, u.updated_at = False, now, now
    sessions, tokens = revoke_access(s, u, now)
    s.flush()
    _audit(s, actor, "user.disabled", u, reason=reason, sessions_ended=sessions,
           tokens_revoked=tokens)  # fmt: skip
    return u


# --- roles on business units and projects ----------------------------------------------------


def _target(s: Session, org_id: str, target_type: Any, target_id: Any) -> str:
    if target_type == "project":
        a = s.get(Asset, target_id) if isinstance(target_id, str) and len(target_id) <= 36 else None
        if a is None or a.org_id != org_id:
            raise UserError("target_id", "No such project.", 404)
        return a.id
    if target_type == "portfolio":
        p = (
            s.get(Portfolio, target_id)
            if isinstance(target_id, str) and len(target_id) <= 36
            else None
        )
        if p is None or p.org_id != org_id:
            raise UserError("target_id", "No such business unit.", 404)
        return p.id
    raise UserError("target_type", "One of: portfolio, project.")


def overrides(s: Session, user_id: str) -> list[RoleOverride]:
    q = select(RoleOverride).where(RoleOverride.user_id == user_id)
    return list(s.scalars(q.order_by(RoleOverride.target_type, RoleOverride.created_at)))


def set_override(
    s: Session, org_id: str, actor: str, user_id: str, target_type: Any, target_id: Any, role: Any
) -> RoleOverride:
    u = get(s, org_id, user_id)
    tid = _target(s, org_id, target_type, target_id)
    role = _role(role, allowed=OVERRIDE_ROLES)
    row = s.scalar(select(RoleOverride).where(RoleOverride.user_id == u.id,
                                              RoleOverride.target_type == target_type,
                                              RoleOverride.target_id == tid))  # fmt: skip
    if row is None:
        row = RoleOverride(
            org_id=org_id, user_id=u.id, target_type=str(target_type), target_id=tid, role=role,
            created_by=actor, created_at=_now(),
        )  # fmt: skip
        s.add(row)
    else:
        row.role = role
    s.flush()
    _audit(s, actor, "user.role_override.set", u, target_type=target_type, target_id=tid,
           role=role)  # fmt: skip
    return row


def remove_override(s: Session, org_id: str, actor: str, user_id: str, override_id: str) -> None:
    u = get(s, org_id, user_id)
    row = s.get(RoleOverride, override_id) if len(override_id) <= 36 else None
    if row is None or row.user_id != u.id:
        raise UserError("id", "No such role.", 404)
    s.delete(row)
    s.flush()
    _audit(s, actor, "user.role_override.removed", u, target_type=row.target_type,
           target_id=row.target_id)  # fmt: skip


def access_for(s: Session, u: User, token_scopes: frozenset[str] | None = None) -> Access:
    """What `u` may do, with their overrides resolved: a business unit's role reaches each of its
    projects. Read under the organization's RLS (the caller has set it)."""
    rows = overrides(s, u.id)
    portfolios = {r.target_id: r.role for r in rows if r.target_type == "portfolio"}
    projects = {r.target_id: r.role for r in rows if r.target_type == "project"}
    in_portfolios: dict[str, str] = {}
    if portfolios:
        for aid, pid in s.execute(select(Asset.id, Asset.portfolio_id).where(
                Asset.org_id == u.org_id, Asset.portfolio_id.in_(list(portfolios)))):  # fmt: skip
            in_portfolios[aid] = portfolios[pid]
    return Access(u.id, u.role, portfolios, projects, in_portfolios, token_scopes)
