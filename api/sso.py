"""Single sign-on (Week 75, plan §51).

    GET  /auth/sso/discover?email=             the provider an email's domain signs in with
    GET  /auth/sso/{provider_id}/start?next=   start a sign-in: to the provider
    GET  /auth/oidc/callback?code=&state=      back from an OIDC provider: signed in, to the app
    GET  /auth/saml/{provider_id}/metadata     our SAML service provider description
    POST /auth/saml/{provider_id}/acs          back from a SAML provider: signed in, to the app

    GET    /v2/sso/providers                   the organization's providers           (org:admin)
    POST   /v2/sso/providers                   {kind, name, email_domains, ...}         (org:admin)
    GET    /v2/sso/providers/{provider_id}                                              (org:admin)
    PATCH  /v2/sso/providers/{provider_id}                                              (org:admin)
    DELETE /v2/sso/providers/{provider_id}                                              (org:admin)
    POST   /v2/sso/providers/{provider_id}/test   read its description and keys now     (org:admin)

A failed sign-in lands on the web app's sign-in page with `?error=<code>` and nothing else: the
reason is in the API's log, not in the address bar.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from api.identity import set_cookie
from core.identity import sso

log = logging.getLogger(__name__)


class ProviderIn(BaseModel):
    """Checked by core.identity.sso field by field."""

    kind: Any = None
    name: Any = None
    email_domains: Any = None
    auto_create: Any = None
    default_role: Any = None
    enabled: Any = None
    issuer: Any = None
    client_id: Any = None
    client_secret: Any = None
    trust_email: Any = None
    refresh: Any = None
    idp_metadata_xml: Any = None
    idp_entity_id: Any = None
    sso_url: Any = None
    idp_cert: Any = None


def _fail(s: Session, exc: sso.SsoError) -> HTTPException:
    s.rollback()
    return HTTPException(exc.status, {"field": exc.field, "message": exc.message})


def signin_error(st: AppState, code: str) -> RedirectResponse:
    return RedirectResponse(f"{st.settings.web_url}/signin?error={quote(code)}", status_code=303)


def signed_in(st: AppState, secret: str, next_path: str) -> RedirectResponse:
    r = RedirectResponse(f"{st.settings.web_url}{next_path}", status_code=303)
    set_cookie(r, st, secret)
    return r


def register_sso_routes(app: FastAPI) -> None:
    admin = [Depends(require_scope("org:admin"))]

    @app.get("/auth/sso/discover", tags=["identity"])
    def discover(
        email: str = Query(..., max_length=320), st: AppState = Depends(state)
    ) -> dict[str, Any]:
        with st.sessions() as s:
            return {"providers": sso.providers_for_email(s, email)}

    @app.get("/auth/sso/{provider_id}/start", tags=["identity"])
    def start(
        provider_id: str,
        next: str = Query(default="/app", max_length=500),  # noqa: A002 - the parameter's name
        login_hint: str | None = Query(default=None, max_length=320),
        st: AppState = Depends(state),
    ) -> RedirectResponse:
        with st.sessions() as s:
            try:
                p = sso.provider_for_attempt(s, provider_id)
                if p.kind == "saml":
                    from core.identity import saml

                    url = saml.begin(s, p, next, st.settings)
                else:
                    url = sso.begin_oidc(s, provider_id, next, st.settings, login_hint)
            except sso.SsoError as exc:
                log.info("sign-in could not start: %s", exc.message)
                return signin_error(st, exc.code)
        return RedirectResponse(url, status_code=303)

    @app.get("/auth/oidc/callback", tags=["identity"])
    def oidc_callback(
        request: Request,
        code: str | None = Query(default=None, max_length=4000),
        state_: str | None = Query(default=None, alias="state", max_length=200),
        error: str | None = Query(default=None, max_length=200),
        st: AppState = Depends(state),
    ) -> RedirectResponse:
        with st.sessions() as s:
            try:
                if error:
                    sso.take_attempt(s, state=state_)  # used up, even when refused
                    raise sso.SsoError("denied", f"The provider said: {error}")
                secret, next_path = sso.finish_oidc(
                    s, code, state_, st.settings, st.sso_http, request.headers.get("user-agent")
                )
            except sso.SsoError as exc:
                log.info("OIDC sign-in refused (%s): %s", exc.code, exc.message)
                return signin_error(st, exc.code)
        return signed_in(st, secret, next_path)

    @app.get("/auth/saml/{provider_id}/metadata", tags=["identity"])
    def saml_metadata(provider_id: str, st: AppState = Depends(state)) -> Response:
        from core.identity import saml

        with st.sessions() as s:
            try:
                p = sso.provider_for_attempt(s, provider_id)
            except sso.SsoError as exc:
                raise HTTPException(404, exc.message) from exc
            return Response(saml.sp_metadata(p, st.settings), media_type="application/xml")

    @app.post("/auth/saml/{provider_id}/acs", tags=["identity"])
    async def saml_acs(
        provider_id: str, request: Request, st: AppState = Depends(state)
    ) -> Response:
        from core.identity import saml

        form = await request.form()
        response = str(form.get("SAMLResponse") or "")
        relay = str(form.get("RelayState") or "")
        with st.sessions() as s:
            try:
                secret, next_path = saml.finish(
                    s, provider_id, response, relay, st.settings, request.headers.get("user-agent")
                )
            except sso.SsoError as exc:
                log.info("SAML sign-in refused (%s): %s", exc.code, exc.message)
                return signin_error(st, exc.code)
        return signed_in(st, secret, next_path)

    # --- settings ---------------------------------------------------------------------------

    @app.get("/v2/sso/providers", tags=["identity"], dependencies=admin)
    def list_providers(
        s: Session = Depends(db), org: str = Depends(current_org), st: AppState = Depends(state)
    ) -> list[dict[str, Any]]:
        return [sso.view(p, st.settings) for p in sso.listing(s, org)]

    @app.post("/v2/sso/providers", tags=["identity"], dependencies=admin, status_code=201)
    def create_provider(
        body: ProviderIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
        st: AppState = Depends(state),
    ) -> dict[str, Any]:
        try:
            p = sso.save(s, org, auth.actor, body.model_dump(exclude_unset=True), st.settings,
                         http=st.sso_http)  # fmt: skip
        except sso.SsoError as exc:
            raise _fail(s, exc) from exc
        return sso.view(p, st.settings)

    @app.get("/v2/sso/providers/{provider_id}", tags=["identity"], dependencies=admin)
    def get_provider(
        provider_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> dict[str, Any]:
        try:
            return sso.view(sso.get(s, org, provider_id), st.settings)
        except sso.SsoError as exc:
            raise _fail(s, exc) from exc

    @app.patch("/v2/sso/providers/{provider_id}", tags=["identity"], dependencies=admin)
    def update_provider(
        provider_id: str,
        body: ProviderIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
        st: AppState = Depends(state),
    ) -> dict[str, Any]:
        try:
            p = sso.save(s, org, auth.actor, body.model_dump(exclude_unset=True), st.settings,
                         provider_id=provider_id, http=st.sso_http)  # fmt: skip
        except sso.SsoError as exc:
            raise _fail(s, exc) from exc
        return sso.view(p, st.settings)

    @app.delete(
        "/v2/sso/providers/{provider_id}", tags=["identity"], dependencies=admin, status_code=204
    )
    def delete_provider(
        provider_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        try:
            sso.remove(s, org, auth.actor, provider_id)
        except sso.SsoError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/sso/providers/{provider_id}/test", tags=["identity"], dependencies=admin)
    def test_provider(
        provider_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        st: AppState = Depends(state),
    ) -> dict[str, Any]:
        try:
            p = sso.get(s, org, provider_id)
        except sso.SsoError as exc:
            raise _fail(s, exc) from exc
        if p.kind == "saml":
            from core.identity import saml

            t = saml.test(p)
        else:
            t = sso.test_oidc(p, st.sso_http)
        return {"ok": t.ok, "message": t.message}
