"""SCIM 2.0 provisioning (Week 75, plan §51: "SCIM 2.0 provisioning and deprovisioning, so
someone leaving the company loses access within minutes, not whenever someone remembers").

The identity provider (Okta, Entra ID, ...) calls Bulwark's `/scim/v2/Users` with a token made
for it -- a token whose only scope is `scim`, belonging to no person -- to create people, change
them, and turn them off. Turning someone off (`active: false`, or `DELETE`) ends every session and
revokes every token they had in the same request: the next thing they try is refused, seconds
after the provider says so, not minutes.

What is supported, deliberately small (RFC 7643/7644):

- Users: list (with `filter` on `userName`, `externalId` or `emails.value`, `eq` only; paging),
  get, create, replace (PUT), PATCH (`replace`/`add` of `active`, `name`, `displayName`, `emails`,
  `externalId`, `roles`, both with and without a `path`, as Okta and Entra ID send them), delete.
- `userName` is the email. `roles[].value` may set the organization role (admin, member, viewer,
  none); without it a new person is a `viewer` -- an admin can give more.
- No Groups, no bulk, no sorting: the provider's own discovery endpoints say so.

A deleted user is turned off and unlinked from the provider (kept, for the audit trail and their
history); the provider no longer sees them. Provisioned again later, they get the same account back.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.identity import users as people
from core.identity.roles import ORG_ROLES
from core.persistence.models import User

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
ACTOR = "scim"
DEFAULT_ROLE = "viewer"
MAX_COUNT = 200
_FILTER = re.compile(r'^\s*(userName|externalId|emails\.value|emails)\s+eq\s+"([^"]*)"\s*$', re.I)


class ScimError(ValueError):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schemas": [ERROR],
            "status": str(self.status),
            "detail": self.detail,
        }
        if self.scim_type:
            out["scimType"] = self.scim_type
        return out


def resource(u: User, base: str) -> dict[str, Any]:
    first, _, last = u.name.partition(" ")
    return {
        "schemas": [USER],
        "id": u.id,
        "externalId": u.external_id,
        "userName": u.email,
        "displayName": u.name,
        "name": {"formatted": u.name, "givenName": first, "familyName": last},
        "emails": [{"value": u.email, "primary": True, "type": "work"}],
        "active": u.active,
        "roles": [{"value": u.role, "primary": True}],
        "meta": {"resourceType": "User", "created": u.created_at.isoformat(),
                 "lastModified": u.updated_at.isoformat(), "location": f"{base}/Users/{u.id}"},
    }  # fmt: skip


def _visible(s: Session, org_id: str) -> Any:
    """The people the provider manages here: everyone but those it deleted."""
    return select(User).where(User.org_id == org_id, User.deprovisioned_at.is_(None))


def get(s: Session, org_id: str, user_id: str) -> User:
    u = s.get(User, user_id) if len(user_id) <= 36 else None
    if u is None or u.org_id != org_id or u.deprovisioned_at is not None:
        raise ScimError(404, "No such user.")
    return u


def listing(
    s: Session, org_id: str, filt: str | None, start: int, count: int, base: str
) -> dict[str, Any]:
    q = _visible(s, org_id)
    if filt:
        m = _FILTER.match(filt)
        if not m:
            raise ScimError(400, "Only `userName`, `externalId` or `emails.value` eq \"...\".",
                            "invalidFilter")  # fmt: skip
        attr, value = m.group(1).lower(), m.group(2)
        if attr == "externalid":
            q = q.where(User.external_id == value)
        else:
            q = q.where(User.email == value.lower())
    total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
    start, count = max(1, start), max(0, min(count, MAX_COUNT))
    rows = list(s.scalars(q.order_by(User.created_at, User.id).offset(start - 1).limit(count)))
    return {"schemas": [LIST], "totalResults": total, "startIndex": start,
            "itemsPerPage": len(rows), "Resources": [resource(u, base) for u in rows]}  # fmt: skip


def _email(body: dict[str, Any]) -> Any:
    if body.get("userName"):
        return body["userName"]
    emails = body.get("emails") or []
    primary = [e for e in emails if isinstance(e, dict) and e.get("primary")] or emails
    return primary[0].get("value") if primary and isinstance(primary[0], dict) else None


def _name(body: dict[str, Any]) -> str | None:
    if isinstance(body.get("displayName"), str) and body["displayName"].strip():
        return str(body["displayName"])
    raw = body.get("name")
    n: dict[str, Any] = raw if isinstance(raw, dict) else {}
    if n.get("formatted"):
        return str(n["formatted"])
    joined = " ".join(str(n.get(k, "")).strip() for k in ("givenName", "familyName")).strip()
    return joined or None


def _role(value: Any) -> str | None:
    roles = value if isinstance(value, list) else [value] if value else []
    for r in roles:
        v = r.get("value") if isinstance(r, dict) else r
        if v in ORG_ROLES:
            return str(v)
        if v:
            raise ScimError(400, f"A role is one of: {', '.join(ORG_ROLES)}.", "invalidValue")
    return None


def create(s: Session, org_id: str, body: dict[str, Any]) -> User:
    try:
        email = people.clean_email(_email(body))
    except people.UserError as exc:
        raise ScimError(400, "userName must be the person's email.", "invalidValue") from exc
    existing = people.by_email(s, org_id, email)
    if existing is not None and existing.deprovisioned_at is not None:
        # Someone the provider deleted, back again: the same account (their history stays theirs).
        existing.deprovisioned_at = None
        existing.external_id = str(body["externalId"]) if body.get("externalId") else None
        back: dict[str, Any] = {k: body[k] for k in ("displayName", "name", "roles") if k in body}
        return _apply(s, org_id, existing, {**back, "active": body.get("active", True)})
    if existing is not None:
        raise ScimError(409, f"{email} already exists.", "uniqueness")
    external = str(body["externalId"]) if body.get("externalId") else None
    u = people.create(s, org_id, ACTOR, email=email, name=_name(body),
                      role=_role(body.get("roles")) or DEFAULT_ROLE, source="scim",
                      external_id=external)  # fmt: skip
    if body.get("active") is False:
        people.disable(s, org_id, ACTOR, u.id, reason="provisioned turned off")
    return u


def _apply(s: Session, org_id: str, u: User, changes: dict[str, Any]) -> User:
    """Set the attributes SCIM may change; turning off goes through `people.disable`, which ends
    sessions and revokes tokens now."""
    raw: dict[str, Any] = {}
    if "displayName" in changes or "name" in changes:
        name = _name(changes)
        if name:
            raw["name"] = name
    if "roles" in changes:
        role = _role(changes["roles"])
        if role:
            raw["role"] = role
    if "externalId" in changes:
        u.external_id = str(changes["externalId"]) if changes["externalId"] else None
    for key in ("userName", "emails"):
        if key in changes:
            try:
                email = people.clean_email(_email({key: changes[key]}))
            except people.UserError as exc:
                raise ScimError(400, "userName must be an email.", "invalidValue") from exc
            other = people.by_email(s, org_id, email)
            if other is not None and other.id != u.id:
                raise ScimError(409, f"{email} already exists.", "uniqueness")
            u.email = email
    if raw:
        try:
            u = people.update_user(s, org_id, ACTOR, u.id, raw)
        except people.UserError as exc:
            raise ScimError(400 if exc.status == 422 else exc.status, exc.message) from exc
    if "active" in changes:
        active = changes["active"]
        if isinstance(active, str):
            active = active.lower() == "true"
        if bool(active) != u.active:
            try:
                if active:
                    u = people.update_user(s, org_id, ACTOR, u.id, {"active": True})
                else:
                    u = people.disable(s, org_id, ACTOR, u.id, reason="deprovisioned over SCIM")
            except people.UserError as exc:
                raise ScimError(409, exc.message) from exc
    s.commit()
    return u


def replace(s: Session, org_id: str, user_id: str, body: dict[str, Any]) -> User:
    u = get(s, org_id, user_id)
    keys = ("userName", "displayName", "name", "externalId", "roles", "active")
    changes: dict[str, Any] = {k: body[k] for k in keys if k in body}
    changes.setdefault("active", True)  # PUT is the whole resource: absent means active
    return _apply(s, org_id, u, changes)


def patch(s: Session, org_id: str, user_id: str, body: dict[str, Any]) -> User:
    u = get(s, org_id, user_id)
    ops = body.get("Operations")
    if PATCH not in (body.get("schemas") or []) or not isinstance(ops, list) or not ops:
        raise ScimError(400, "A PatchOp with Operations, please.", "invalidSyntax")
    changes: dict[str, Any] = {}
    for op in ops:
        kind = str(op.get("op", "")).lower() if isinstance(op, dict) else ""
        if kind not in ("replace", "add"):
            raise ScimError(
                400, f"Only replace and add are supported, not {kind!r}.", "invalidSyntax"
            )
        path, value = op.get("path"), op.get("value")
        if path:
            key = str(path)
            if key.startswith("name."):
                changes.setdefault("name", {})[key.split(".", 1)[1]] = value
            elif key.lower().startswith("emails"):
                changes["emails"] = value if isinstance(value, list) else [{"value": value}]
            else:
                changes[key] = value
        elif isinstance(value, dict):
            changes.update(value)
        else:
            raise ScimError(400, "A replace without a path needs an object value.", "invalidSyntax")
    return _apply(s, org_id, u, changes)


def delete(s: Session, org_id: str, user_id: str) -> None:
    u = get(s, org_id, user_id)
    if u.active:
        try:
            people.disable(s, org_id, ACTOR, u.id, reason="deleted over SCIM")
        except people.UserError as exc:
            raise ScimError(409, exc.message) from exc
    u.external_id, u.deprovisioned_at = None, datetime.now(timezone.utc)
    s.commit()


def service_provider_config(base: str) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": f"{base}/docs",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_COUNT},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                   "description": "A Bulwark token with the scim scope",
                                   "primary": True}],
    }  # fmt: skip


def resource_types(base: str) -> dict[str, Any]:
    return {"schemas": [LIST], "totalResults": 1, "Resources": [{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User",
        "name": "User", "endpoint": "/Users", "schema": USER,
        "meta": {"resourceType": "ResourceType",
                 "location": f"{base}/ResourceTypes/User"}}]}  # fmt: skip
