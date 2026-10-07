"""Accounts, sessions and roles (Week 75, plan §51).

    GET    /auth/session                      the signed-in person and the CSRF token (cookie only)
    POST   /auth/logout                       end this browser's session

    GET    /v2/users                          the organization's people            (org:admin)
    POST   /v2/users                          {email, name?, role}                  (org:admin)
    GET    /v2/users/{user_id}                one person, with their roles          (org:admin)
    PATCH  /v2/users/{user_id}                {name?, role?, active?}; turning someone off ends
                                              their sessions and revokes their tokens (org:admin)
    PUT    /v2/users/{user_id}/roles          {target_type, target_id, role}: a higher role on a
                                              business unit or a project            (org:admin)
    DELETE /v2/users/{user_id}/roles/{override_id}                                  (org:admin)

    GET    /v2/me/tokens                      my API tokens
    POST   /v2/me/tokens                      {name, scopes, days?}: shown once; it acts as me,
                                              within its scopes and my role at the time it is used
    DELETE /v2/me/tokens/{token_id}

Every change is audit-logged. Sign-in itself (OIDC, SAML) and SCIM are in api/sso.py and
api/scim.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.identity import sessions as web_sessions
from core.identity import users as svc
from core.identity.roles import ORG_ROLES, SCOPES
from core.persistence import repo
from core.persistence.models import ApiToken
from core.tokens import TokenError, parse_scopes


class UserIn(BaseModel):
    email: Any = None
    name: Any = None
    role: Any = None
    active: Any = None


class OverrideIn(BaseModel):
    target_type: Any = None
    target_id: Any = None
    role: Any = None


class TokenIn(BaseModel):
    name: Any = None
    scopes: Any = None
    days: Any = None


def _fail(s: Session, exc: svc.UserError) -> HTTPException:
    s.rollback()
    return HTTPException(exc.status, {"field": exc.field, "message": exc.message})


def clear_cookie(response: Response, st: AppState) -> None:
    response.delete_cookie(web_sessions.COOKIE, path="/", secure=st.settings.session_cookie_secure,
                           httponly=True, samesite="lax")  # fmt: skip


def set_cookie(response: Response, st: AppState, secret: str) -> None:
    response.set_cookie(
        web_sessions.COOKIE, secret, max_age=int(web_sessions.ABSOLUTE.total_seconds()), path="/",
        secure=st.settings.session_cookie_secure, httponly=True, samesite="lax",
    )  # fmt: skip


def _user_view(s: Session, u: Any) -> dict[str, Any]:
    out = svc.view(u)
    out["roles"] = [{"id": r.id, "target_type": r.target_type, "target_id": r.target_id,
                     "role": r.role} for r in svc.overrides(s, u.id)]  # fmt: skip
    return out


def _person(auth: AuthContext) -> str:
    if auth.access is None:
        raise HTTPException(409, "Sign in as yourself first: the shared token and tokens from "
                                 "before accounts are nobody in particular.")  # fmt: skip
    return auth.access.user_id


def register_identity_routes(app: FastAPI) -> None:
    admin = [Depends(require_scope("org:admin"))]

    @app.get("/auth/session", tags=["identity"])
    def session(request: Request, st: AppState = Depends(state)) -> dict[str, Any]:
        secret = request.cookies.get(web_sessions.COOKIE)
        with st.sessions() as s:
            row = web_sessions.resolve(s, secret)
            if row is None:
                raise HTTPException(401, "not signed in")
            from core.persistence.models import User
            from core.tenancy import set_session_org

            set_session_org(s, row.org_id)
            u = s.get(User, row.user_id)
            if u is None or not u.active:
                raise HTTPException(401, "not signed in")
            return {"user": svc.view(u), "csrf": row.csrf, "method": row.method,
                    "expires_at": row.expires_at, "org_id": row.org_id}  # fmt: skip

    @app.post("/auth/logout", tags=["identity"], status_code=204)
    def logout(request: Request, response: Response, st: AppState = Depends(state)) -> None:
        with st.sessions() as s:
            web_sessions.end(s, request.cookies.get(web_sessions.COOKIE))
        clear_cookie(response, st)

    @app.get("/v2/users", tags=["identity"], dependencies=admin)
    def list_users(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[dict[str, Any]]:
        return [_user_view(s, u) for u in svc.listing(s, org)]

    @app.post("/v2/users", tags=["identity"], dependencies=admin, status_code=201)
    def create_user(
        body: UserIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            u = svc.create(s, org, auth.actor, email=body.email, name=body.name,
                           role=body.role or "member", source="admin")  # fmt: skip
        except svc.UserError as exc:
            raise _fail(s, exc) from exc
        return _user_view(s, u)

    @app.get("/v2/users/{user_id}", tags=["identity"], dependencies=admin)
    def get_user(
        user_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        try:
            return _user_view(s, svc.get(s, org, user_id))
        except svc.UserError as exc:
            raise _fail(s, exc) from exc

    @app.patch("/v2/users/{user_id}", tags=["identity"], dependencies=admin)
    def update_user(
        user_id: str,
        body: UserIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            u = svc.update_user(s, org, auth.actor, user_id, body.model_dump(exclude_unset=True))
        except svc.UserError as exc:
            raise _fail(s, exc) from exc
        return _user_view(s, u)

    @app.put("/v2/users/{user_id}/roles", tags=["identity"], dependencies=admin)
    def set_role(
        user_id: str,
        body: OverrideIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            svc.set_override(s, org, auth.actor, user_id, body.target_type, body.target_id,
                             body.role)  # fmt: skip
            return _user_view(s, svc.get(s, org, user_id))
        except svc.UserError as exc:
            raise _fail(s, exc) from exc

    @app.delete("/v2/users/{user_id}/roles/{override_id}", tags=["identity"], dependencies=admin)
    def remove_role(
        user_id: str,
        override_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            svc.remove_override(s, org, auth.actor, user_id, override_id)
            return _user_view(s, svc.get(s, org, user_id))
        except svc.UserError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/roles", tags=["identity"])
    def roles(_: AuthContext = Depends(require_auth)) -> dict[str, Any]:
        return {"roles": list(ORG_ROLES),
                "scopes": {r: sorted(SCOPES[r]) for r in ORG_ROLES}}  # fmt: skip

    # --- a person's own API tokens ------------------------------------------------------------

    def _token_view(t: ApiToken) -> dict[str, Any]:
        return {"id": t.id, "name": t.name, "prefix": t.display_prefix, "scopes": list(t.scopes),
                "created_at": t.created_at, "expires_at": t.expires_at,
                "last_used_at": t.last_used_at, "revoked_at": t.revoked_at}  # fmt: skip

    @app.get("/v2/me/tokens", tags=["identity"])
    def my_tokens(
        auth: AuthContext = Depends(require_auth), st: AppState = Depends(state)
    ) -> list[dict[str, Any]]:
        uid = _person(auth)
        with st.sessions() as s:  # api_tokens has no RLS (ADR-0018)
            rows = s.scalars(select(ApiToken).where(ApiToken.user_id == uid)
                             .order_by(ApiToken.created_at.desc()))  # fmt: skip
            return [_token_view(t) for t in rows]

    @app.post("/v2/me/tokens", tags=["identity"], status_code=201)
    def make_token(
        body: TokenIn,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, Any]:
        uid = _person(auth)
        if auth.access is not None and auth.access.token_scopes is not None:
            raise HTTPException(403, "A token cannot make tokens; sign in to make one.")
        name = body.name.strip() if isinstance(body.name, str) else ""
        if not 1 <= len(name) <= 200:
            raise HTTPException(422, {"field": "name", "message": "A name of 1 to 200 characters."})
        try:
            scopes = parse_scopes(list(body.scopes or []))
        except (TokenError, TypeError) as exc:
            raise HTTPException(422, {"field": "scopes", "message": str(exc)}) from exc
        if not scopes:
            raise HTTPException(422, {"field": "scopes", "message": "Choose at least one scope."})
        days = body.days if isinstance(body.days, int) and not isinstance(body.days, bool) else 90
        if not 1 <= days <= 365:
            raise HTTPException(422, {"field": "days", "message": "From 1 to 365 days."})
        row, raw = repo.create_api_token(
            s, org_id=org, name=name, scopes=sorted(scopes),
            expires_at=datetime.now(timezone.utc) + timedelta(days=days), user_id=uid,
        )  # fmt: skip
        repo.append_audit_entry(
            s, actor=auth.actor, action="token.created", target=f"token:{row.display_prefix}",
            payload={"org_id": org, "scopes": sorted(scopes), "days": days},
        )  # fmt: skip
        return {**_token_view(row), "token": raw}

    @app.delete("/v2/me/tokens/{token_id}", tags=["identity"], status_code=204)
    def revoke_token(
        token_id: str,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> None:
        uid = _person(auth)
        row = s.get(ApiToken, token_id) if len(token_id) <= 36 else None
        if row is None or row.user_id != uid:
            raise HTTPException(404, "no such token")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(timezone.utc)
            s.commit()
            repo.append_audit_entry(s, actor=auth.actor, action="token.revoked",
                                    target=f"token:{row.display_prefix}",
                                    payload={"org_id": org})  # fmt: skip
