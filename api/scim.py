"""SCIM 2.0 for identity providers, and the tokens they call it with (Week 75, plan §51).

    GET    /scim/v2/ServiceProviderConfig
    GET    /scim/v2/ResourceTypes
    GET    /scim/v2/Users?filter=&startIndex=&count=
    POST   /scim/v2/Users
    GET    /scim/v2/Users/{user_id}
    PUT    /scim/v2/Users/{user_id}
    PATCH  /scim/v2/Users/{user_id}            e.g. {"Operations": [{"op": "replace",
                                               "path": "active", "value": false}]}: turned off now
    DELETE /scim/v2/Users/{user_id}

    GET    /v2/scim/tokens                      the organization's SCIM tokens          (org:admin)
    POST   /v2/scim/tokens                      {name, days?}: shown once               (org:admin)
    DELETE /v2/scim/tokens/{token_id}                                                   (org:admin)

The `/scim/v2` routes take only a token with the `scim` scope, which belongs to no person and can
do nothing else. Errors are SCIM's own error documents (RFC 7644 §3.12).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.identity import scim
from core.persistence import repo
from core.persistence.models import ApiToken

MEDIA = "application/scim+json"


class TokenIn(BaseModel):
    name: Any = None
    days: Any = None


def _json(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=MEDIA, headers=headers)


def _error(s: Session, exc: scim.ScimError) -> JSONResponse:
    s.rollback()
    return _json(exc.body(), exc.status)


async def _body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError as exc:
        raise scim.ScimError(400, "The body is not JSON.", "invalidSyntax") from exc
    if not isinstance(body, dict):
        raise scim.ScimError(400, "The body is a JSON object.", "invalidSyntax")
    return body


def register_scim_routes(app: FastAPI) -> None:
    provider = [Depends(require_scope("scim"))]
    admin = [Depends(require_scope("org:admin"))]

    def base(st: AppState) -> str:
        return f"{st.settings.api_public_url}/scim/v2"

    @app.get("/scim/v2/ServiceProviderConfig", tags=["scim"], dependencies=provider)
    def config(st: AppState = Depends(state)) -> JSONResponse:
        return _json(scim.service_provider_config(base(st)))

    @app.get("/scim/v2/ResourceTypes", tags=["scim"], dependencies=provider)
    def types(st: AppState = Depends(state)) -> JSONResponse:
        return _json(scim.resource_types(base(st)))

    @app.get("/scim/v2/Users", tags=["scim"], dependencies=provider)
    def list_users(
        filter: str | None = Query(default=None, max_length=500),  # noqa: A002 - SCIM's name
        startIndex: int = Query(default=1, ge=1),  # noqa: N803 - SCIM's name
        count: int = Query(default=100, ge=0),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> JSONResponse:
        try:
            return _json(scim.listing(s, org, filter, startIndex, count, base(st)))
        except scim.ScimError as exc:
            return _error(s, exc)

    @app.post("/scim/v2/Users", tags=["scim"], dependencies=provider)
    async def create_user(
        request: Request,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> JSONResponse:
        try:
            u = scim.create(s, org, await _body(request))
            s.commit()
            out = scim.resource(u, base(st))
            return _json(out, 201, {"Location": out["meta"]["location"]})
        except scim.ScimError as exc:
            return _error(s, exc)

    @app.get("/scim/v2/Users/{user_id}", tags=["scim"], dependencies=provider)
    def get_user(
        user_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> JSONResponse:
        try:
            return _json(scim.resource(scim.get(s, org, user_id), base(st)))
        except scim.ScimError as exc:
            return _error(s, exc)

    @app.put("/scim/v2/Users/{user_id}", tags=["scim"], dependencies=provider)
    async def replace_user(
        user_id: str,
        request: Request,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> JSONResponse:
        try:
            return _json(
                scim.resource(scim.replace(s, org, user_id, await _body(request)), base(st))
            )
        except scim.ScimError as exc:
            return _error(s, exc)

    @app.patch("/scim/v2/Users/{user_id}", tags=["scim"], dependencies=provider)
    async def patch_user(
        user_id: str,
        request: Request,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> JSONResponse:
        try:
            return _json(scim.resource(scim.patch(s, org, user_id, await _body(request)), base(st)))
        except scim.ScimError as exc:
            return _error(s, exc)

    @app.delete("/scim/v2/Users/{user_id}", tags=["scim"], dependencies=provider)
    def delete_user(
        user_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> Response:
        try:
            scim.delete(s, org, user_id)
        except scim.ScimError as exc:
            return _error(s, exc)
        return Response(status_code=204)

    # --- the provider's tokens --------------------------------------------------------------

    def _view(t: ApiToken) -> dict[str, Any]:
        return {"id": t.id, "name": t.name, "prefix": t.display_prefix, "created_at": t.created_at,
                "expires_at": t.expires_at, "last_used_at": t.last_used_at,
                "revoked_at": t.revoked_at}  # fmt: skip

    @app.get("/v2/scim/tokens", tags=["scim"], dependencies=admin)
    def tokens(org: str = Depends(current_org), st: AppState = Depends(state)) -> dict[str, Any]:
        with st.sessions() as s:  # api_tokens has no RLS (ADR-0018): filtered by org here
            rows = [t for t in s.scalars(select(ApiToken).where(ApiToken.org_id == org)
                                         .order_by(ApiToken.created_at.desc()))
                    if list(t.scopes) == ["scim"]]  # fmt: skip
            return {"base_url": base(st), "tokens": [_view(t) for t in rows]}

    @app.post("/v2/scim/tokens", tags=["scim"], dependencies=admin, status_code=201)
    def make_token(
        body: TokenIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
        st: AppState = Depends(state),
    ) -> dict[str, Any]:
        name = body.name.strip() if isinstance(body.name, str) else ""
        if not 1 <= len(name) <= 200:
            raise HTTPException(422, {"field": "name", "message": "A name of 1 to 200 characters."})
        days = body.days if isinstance(body.days, int) and not isinstance(body.days, bool) else 365
        if not 1 <= days <= 730:
            raise HTTPException(422, {"field": "days", "message": "From 1 to 730 days."})
        row, raw = repo.create_api_token(
            s, org_id=org, name=name, scopes=["scim"],
            expires_at=datetime.now(timezone.utc) + timedelta(days=days),
        )  # fmt: skip
        repo.append_audit_entry(
            s, actor=auth.actor, action="scim.token.created", target=f"token:{row.display_prefix}",
            payload={"org_id": org, "name": name, "days": days},
        )  # fmt: skip
        return {**_view(row), "token": raw, "base_url": base(st)}

    @app.delete("/v2/scim/tokens/{token_id}", tags=["scim"], dependencies=admin, status_code=204)
    def revoke_token(
        token_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        row = s.get(ApiToken, token_id) if len(token_id) <= 36 else None
        if row is None or row.org_id != org or list(row.scopes) != ["scim"]:
            raise HTTPException(404, "no such SCIM token")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(timezone.utc)
            s.commit()
            repo.append_audit_entry(
                s, actor=auth.actor, action="scim.token.revoked",
                target=f"token:{row.display_prefix}", payload={"org_id": org},
            )  # fmt: skip
