"""Week 75 against a REAL identity provider: Keycloak, running locally. A realm with one person,
an OIDC client that requires PKCE and a SAML client that signs its assertions; then, as a browser
would, through Keycloak's own sign-in page, both kinds of sign-in end with a Bulwark session for
that person. A wrong password signs nobody in.

Needs `BULWARK_KEYCLOAK_URL` (e.g. http://localhost:8180) and `BULWARK_KEYCLOAK_ADMIN_PASSWORD`,
and xmlsec1 for SAML:

    docker run -d --name bulwark-keycloak -p 127.0.0.1:8180:8080 \\
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=... \\
      -e KC_HOSTNAME=http://localhost:8180 quay.io/keycloak/keycloak:26.3 start-dev
"""

from __future__ import annotations

import html
import os
import re
import shutil
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    Env,
    env,  # noqa: F401  (the fixture)
)

KC = os.environ.get("BULWARK_KEYCLOAK_URL", "").rstrip("/")
PASSWORD = os.environ.get("BULWARK_KEYCLOAK_ADMIN_PASSWORD", "")
pytestmark = pytest.mark.skipif(not (KC and PASSWORD), reason="no Keycloak to sign in with")
API = "http://localhost:8000"  # Settings' default api_public_url: what Keycloak redirects to


class Keycloak:
    def __init__(self) -> None:
        tok = httpx.post(f"{KC}/realms/master/protocol/openid-connect/token",
                         data={"grant_type": "password", "client_id": "admin-cli",
                               "username": "admin", "password": PASSWORD}).json()["access_token"]  # fmt: skip
        self.admin = httpx.Client(base_url=f"{KC}/admin/realms",
                                  headers={"Authorization": f"Bearer {tok}"})  # fmt: skip
        self.realm = f"acme-{uuid.uuid4().hex[:6]}"
        r = self.admin.post("", json={"realm": self.realm, "enabled": True})
        assert r.status_code == 201, r.text
        r = self.admin.post(f"/{self.realm}/users", json={
            "username": "alice", "email": "alice@acme.test", "emailVerified": True,
            "firstName": "Alice", "lastName": "Ng", "enabled": True,
            "credentials": [{"type": "password", "value": "alice-pass-1", "temporary": False}]})  # fmt: skip
        assert r.status_code == 201, r.text
        self.issuer = f"{KC}/realms/{self.realm}"

    def oidc_client(self) -> str:
        r = self.admin.post(f"/{self.realm}/clients", json={
            "clientId": "bulwark", "protocol": "openid-connect", "publicClient": False,
            "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
            "redirectUris": [f"{API}/auth/oidc/callback"],
            "attributes": {"pkce.code.challenge.method": "S256"}})  # fmt: skip
        assert r.status_code == 201, r.text
        cid = r.headers["location"].rsplit("/", 1)[1]
        return str(self.admin.get(f"/{self.realm}/clients/{cid}/client-secret").json()["value"])

    def saml_client(self, entity_id: str, acs: str) -> str:
        r = self.admin.post(f"/{self.realm}/clients", json={
            "clientId": entity_id, "protocol": "saml", "enabled": True,
            "redirectUris": [acs], "frontchannelLogout": False,
            "attributes": {"saml.assertion.signature": "true", "saml.server.signature": "false",
                           "saml.client.signature": "false", "saml_name_id_format": "email",
                           "saml_force_name_id_format": "true",
                           "saml_assertion_consumer_url_post": acs}})  # fmt: skip
        assert r.status_code == 201, r.text
        return httpx.get(f"{self.issuer}/protocol/saml/descriptor").text

    def close(self) -> None:
        self.admin.delete(f"/{self.realm}")


@pytest.fixture
def kc() -> Any:
    k = Keycloak()
    yield k
    k.close()


def _form(page: str) -> tuple[str, dict[str, str]]:
    action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', page).group(1))  # type: ignore[union-attr]
    fields = {html.unescape(n): html.unescape(v) for n, v in
              re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page)}  # fmt: skip
    return action, fields


def browser_sign_in(api: TestClient, start: str, password: str) -> httpx.Response:
    """Follow redirects across Bulwark (in-process) and Keycloak (over HTTP) as a browser does,
    filling in Keycloak's sign-in form, until Bulwark answers with where to land."""
    kc = httpx.Client(follow_redirects=False)
    jar: dict[str, str] = {}

    def send(method: str, url: str, **kw: Any) -> httpx.Response:
        # Keycloak marks its cookies Secure; a browser still sends them to http://localhost (a
        # secure context), httpx does not (and files them under "localhost.local"). Keep and send
        # them by hand, as a browser would.
        cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
        resp = kc.request(method, url, headers={"Cookie": cookie} if cookie else {}, **kw)
        jar.update({c.name: c.value or "" for c in resp.cookies.jar})
        return resp

    r: Any = api.get(start, follow_redirects=False)
    tried = False
    for _ in range(10):
        loc = r.headers.get("location")
        if loc and loc.startswith(API):
            parts = urlsplit(loc)
            return api.get(f"{parts.path}?{parts.query}", follow_redirects=False)  # type: ignore[return-value]
        if loc:
            r = send("GET", loc)
            continue
        page = r.text
        if 'name="password"' in page:
            if tried:
                return r  # type: ignore[no-any-return]  # the form again: the password was wrong
            tried = True
            action, _ = _form(page)
            r = send("POST", action, data={"username": "alice", "password": password})
            continue
        if "SAMLResponse" in page:  # Keycloak's auto-submitting form back to our ACS
            action, fields = _form(page)
            assert action.startswith(API)
            return api.post(urlsplit(action).path, data=fields, follow_redirects=False)  # type: ignore[return-value]
        return r  # type: ignore[no-any-return]  # e.g. Keycloak's "invalid password" page
    raise AssertionError("too many redirects")


def me(api: TestClient, r: Any) -> dict[str, Any] | None:
    if "set-cookie" not in r.headers:
        return None
    cookie = r.headers["set-cookie"].split(";", 1)[0]
    return api.get("/v2/me", headers={"Cookie": cookie}).json().get("user")  # type: ignore[no-any-return]


def test_oidc_with_keycloak(env: Env, kc: Keycloak) -> None:  # noqa: F811
    secret = kc.oidc_client()
    r = env.client.post("/v2/sso/providers", headers=AUTH, json={
        "kind": "oidc", "name": "Keycloak", "issuer": kc.issuer, "client_id": "bulwark",
        "client_secret": secret, "email_domains": ["acme.test"], "auto_create": True})  # fmt: skip
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    test = env.client.post(f"/v2/sso/providers/{pid}/test", headers=AUTH).json()
    assert test["ok"], test
    wrong = browser_sign_in(env.client, f"/auth/sso/{pid}/start", "not-her-password")
    assert me(env.client, wrong) is None
    r = browser_sign_in(env.client, f"/auth/sso/{pid}/start?next=/app/issues", "alice-pass-1")
    assert r.status_code == 303 and r.headers["location"] == "http://localhost:3000/app/issues"
    user = me(env.client, r)
    assert user is not None and user["email"] == "alice@acme.test" and user["name"] == "Alice Ng"


@pytest.mark.skipif(shutil.which("xmlsec1") is None, reason="xmlsec1 not installed")
def test_saml_with_keycloak(env: Env, kc: Keycloak) -> None:  # noqa: F811
    # The provider first (its id is in our entity id), then Keycloak's client, then its metadata.
    r = env.client.post("/v2/sso/providers", headers=AUTH, json={
        "kind": "saml", "name": "Keycloak SAML", "idp_entity_id": "placeholder",
        "sso_url": "http://localhost:8180/x", "email_domains": ["acme.test"], "auto_create": True,
        "idp_cert": _any_cert()})  # fmt: skip
    assert r.status_code == 201, r.text
    view = r.json()
    descriptor = kc.saml_client(view["saml"]["sp_entity_id"], view["saml"]["acs_url"])
    r = env.client.patch(f"/v2/sso/providers/{view['id']}", headers=AUTH,
                         json={"idp_metadata_xml": descriptor})  # fmt: skip
    assert r.status_code == 200, r.text
    assert r.json()["saml"]["idp_entity_id"] == kc.issuer
    r = browser_sign_in(env.client, f"/auth/sso/{view['id']}/start?next=/app", "alice-pass-1")
    assert r.status_code == 303 and r.headers["location"] == "http://localhost:3000/app", r.headers
    user = me(env.client, r)
    assert user is not None and user["email"] == "alice@acme.test" and user["source"] == "saml"


def _any_cert() -> str:
    import tempfile
    from pathlib import Path

    from tests.unit.test_saml import key_and_cert

    return key_and_cert(Path(tempfile.mkdtemp()), "placeholder")[2]
