"""OIDC sign-in (Week 75, plan §51: "OIDC sign-in with PKCE and strict issuer, audience, and
nonce validation"), against a fake identity provider with its own signing key: a whole sign-in
through the API with PKCE checked by the provider; then every way an ID token or a callback can be
wrong, each refused; who a provider's word makes you; and the settings."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from api.deps import AppState
from api.main import create_app
from core.identity import oidc
from core.identity import users as svc
from core.persistence.models import AuditEntry, LoginAttempt
from core.tenancy import DEFAULT_ORG_ID as ORG
from core.tenancy import set_session_org
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    Env,
    FakeSubscriber,
    env,  # noqa: F401  (the fixture)
)

ISSUER = "https://idp.acme.test/realms/acme"
CLIENT = "bulwark"
SECRET = "client-secret-for-tests"


class FakeIdP:
    """An identity provider in-process: discovery, keys, and a token endpoint that checks the
    client secret and the PKCE verifier against the challenge from the sign-in URL."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwks = {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}
        self.codes: dict[str, dict[str, Any]] = {}
        self.claims: dict[str, Any] = {}
        self.header: dict[str, Any] = {"kid": "k1"}
        self.sign: Any = None  # a function (claims, header) -> token, to forge one
        self.issuer_says = ISSUER
        self.verifiers: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": self.issuer_says, "authorization_endpoint": f"{ISSUER}/auth",
                "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/certs",
                "id_token_signing_alg_values_supported": ["RS256"]})  # fmt: skip
        if url == f"{ISSUER}/certs":
            return httpx.Response(200, json=self.jwks)
        if url == f"{ISSUER}/token":
            form = parse_qs(request.content.decode())
            basic = base64.b64decode(request.headers["authorization"].split()[1]).decode()
            if basic != f"{CLIENT}:{SECRET}":
                return httpx.Response(401, json={"error": "invalid_client"})
            grant = self.codes.pop(form["code"][0], None)
            verifier = form["code_verifier"][0]
            self.verifiers.append(verifier)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            if grant is None or challenge.rstrip(b"=").decode() != grant["challenge"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.token(grant["nonce"])})
        return httpx.Response(404)

    def token(self, nonce: str) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT, "sub": "sub-priya", "iat": now, "exp": now + 300,
                  "nonce": nonce, "email": "priya@acme.test", "email_verified": True,
                  "name": "Priya N.", **self.claims}  # fmt: skip
        claims = {k: v for k, v in claims.items() if v is not None}
        if self.sign:
            return str(self.sign(claims, self.header))
        return jwt.encode(claims, self.key, algorithm="RS256", headers=self.header)

    def authorize(self, url: str) -> str:
        """The person signs in at the provider: it issues a code bound to the request."""
        q = parse_qs(urlsplit(url).query)
        assert q["code_challenge_method"] == ["S256"] and q["response_type"] == ["code"]
        code = f"code-{len(self.codes)}-{q['state'][0][:6]}"
        self.codes[code] = {"challenge": q["code_challenge"][0], "nonce": q["nonce"][0]}
        return f"/auth/oidc/callback?code={code}&state={q['state'][0]}"


@pytest.fixture
def idp(env: Env) -> FakeIdP:  # noqa: F811
    fake = FakeIdP()
    oidc._JWKS.clear()
    http = httpx.Client(transport=httpx.MockTransport(fake.handler))
    env.settings = env.settings.__class__(
        **{**env.settings.__dict__, "web_url": "https://app.acme.test"}
    )
    env.client = TestClient(create_app(AppState(env.settings, env.sessions, lambda *_: None,
                                                FakeSubscriber(), sso_http=http)))  # fmt: skip
    r = env.client.post("/v2/sso/providers", headers=AUTH, json={
        "kind": "oidc", "name": "Acme SSO", "issuer": ISSUER, "client_id": CLIENT,
        "client_secret": SECRET, "email_domains": ["acme.test"], "auto_create": True,
        "default_role": "viewer"})  # fmt: skip
    assert r.status_code == 201, r.text
    fake.provider = r.json()  # type: ignore[attr-defined]
    return fake


def sign_in(env: Env, idp: FakeIdP, next_path: str = "/app/issues") -> httpx.Response:  # noqa: F811
    pid = idp.provider["id"]  # type: ignore[attr-defined]
    start = env.client.get(f"/auth/sso/{pid}/start", params={"next": next_path},
                           follow_redirects=False)  # fmt: skip
    assert start.status_code == 303 and start.headers["location"].startswith(f"{ISSUER}/auth?")
    return env.client.get(idp.authorize(start.headers["location"]), follow_redirects=False)


def cookie_of(r: httpx.Response) -> str:
    raw = r.headers["set-cookie"]
    assert "HttpOnly" in raw and "SameSite=lax" in raw and "Secure" in raw
    return raw.split(";", 1)[0]


def test_a_whole_sign_in_with_pkce(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    found = env.client.get("/auth/sso/discover", params={"email": "Priya@ACME.test"}).json()
    assert found == {"providers": [{"id": idp.provider["id"], "name": "Acme SSO", "kind": "oidc"}]}  # type: ignore[attr-defined]  # noqa: E501
    assert env.client.get("/auth/sso/discover", params={"email": "x@other.test"}).json() == {
        "providers": []
    }  # noqa: E501
    r = sign_in(env, idp)
    assert r.status_code == 303 and r.headers["location"] == "https://app.acme.test/app/issues"
    me = env.client.get("/v2/me", headers={"Cookie": cookie_of(r)}).json()
    assert me["user"]["email"] == "priya@acme.test" and me["org_role"] == "viewer"
    assert me["user"]["name"] == "Priya N." and me["user"]["source"] == "oidc"
    assert len(idp.verifiers) == 1 and len(idp.verifiers[0]) >= 43  # PKCE, checked by the IdP
    # The same person again is the same account, by their subject.
    r2 = sign_in(env, idp)
    assert (
        env.client.get("/v2/me", headers={"Cookie": cookie_of(r2)}).json()["user"]["id"]
        == me["user"]["id"]
    )  # noqa: E501
    with env.sessions() as s:
        assert [
            e.action for e in s.query(AuditEntry).filter(AuditEntry.action == "user.signed_in")
        ].count(
            "user.signed_in"
        ) == 2  # noqa: E501


def _forge_none(claims: dict[str, Any], header: dict[str, Any]) -> str:
    def b64(d: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(claims)}."


def _forge_hs256(idp: FakeIdP) -> Any:
    """The key-confusion forgery: HMAC "signed" with the provider's public key."""

    def sign(claims: dict[str, Any], header: dict[str, Any]) -> str:
        import hmac

        def b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

        head = b64(json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode())
        body = b64(json.dumps(claims).encode())
        mac = hmac.new(idp.pub_pem, f"{head}.{body}".encode(), hashlib.sha256).digest()
        return f"{head}.{body}.{b64(mac)}"

    return sign


def _other_key(claims: dict[str, Any], header: dict[str, Any]) -> str:
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return jwt.encode(claims, stranger, algorithm="RS256", headers={"kid": "k1"})


CASES = [
    ("wrong issuer", {"iss": "https://evil.test/realms/acme"}, None, "invalid"),
    ("wrong audience", {"aud": "someone-else"}, None, "invalid"),
    ("several audiences, not authorized for us", {"aud": [CLIENT, "other"], "azp": "other"}, None, "invalid"),
    ("expired", {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}, None, "expired"),
    ("issued in the future", {"iat": int(time.time()) + 3600, "exp": int(time.time()) + 7200}, None, "invalid"),
    ("wrong nonce", {"nonce": "not-this-sign-in"}, None, "invalid"),
    ("no subject", {"sub": None}, None, "invalid"),
    ("alg none", {}, _forge_none, "invalid"),
    ("signed by someone else", {}, _other_key, "invalid"),
    ("email not verified", {"email_verified": False}, None, "invalid"),
    ("email of a domain the provider does not vouch for", {"email": "priya@gmail.com"}, None, "domain"),
]  # fmt: skip


@pytest.mark.parametrize("name,claims,sign,code", CASES, ids=[c[0] for c in CASES])
def test_every_wrong_token_is_refused(
    env: Env, idp: FakeIdP, name: str, claims: dict[str, Any], sign: Any, code: str  # noqa: F811
) -> None:
    idp.claims, idp.sign = claims, sign
    r = sign_in(env, idp)
    assert (
        r.status_code == 303
        and r.headers["location"] == f"https://app.acme.test/signin?error={code}"
    )
    assert "set-cookie" not in r.headers


def test_hmac_with_the_public_key_is_refused(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    idp.sign = _forge_hs256(idp)
    r = sign_in(env, idp)
    assert r.headers["location"].endswith("error=invalid") and "set-cookie" not in r.headers


def test_a_rotated_key_is_fetched_once_more(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    assert sign_in(env, idp).headers["location"].endswith("/app/issues")  # keys now cached
    idp.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(idp.key.public_key()))
    idp.jwks = {"keys": [{**jwk, "kid": "k2", "use": "sig"}]}
    idp.header = {"kid": "k2"}
    assert sign_in(env, idp).headers["location"].endswith("/app/issues")


def test_callbacks_that_are_not_ours_or_replayed(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    pid = idp.provider["id"]  # type: ignore[attr-defined]
    start = env.client.get(f"/auth/sso/{pid}/start", follow_redirects=False)
    back = idp.authorize(start.headers["location"])
    first = env.client.get(back, follow_redirects=False)
    assert first.headers["location"] == "https://app.acme.test/app"  # the default landing
    again = env.client.get(back, follow_redirects=False)  # the same state twice
    assert again.headers["location"].endswith("error=invalid")
    made_up = env.client.get("/auth/oidc/callback?code=x&state=made-up", follow_redirects=False)
    assert made_up.headers["location"].endswith("error=invalid")
    # The provider said no.
    start = env.client.get(f"/auth/sso/{pid}/start", follow_redirects=False)
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    r = env.client.get(
        f"/auth/oidc/callback?error=access_denied&state={state}", follow_redirects=False
    )
    assert r.headers["location"].endswith("error=denied")
    # Too slow.
    start = env.client.get(f"/auth/sso/{pid}/start", follow_redirects=False)
    back = idp.authorize(start.headers["location"])
    with env.sessions() as s:
        for a in s.query(LoginAttempt).filter(LoginAttempt.used_at.is_(None)):
            a.expires_at = a.created_at
        s.commit()
    assert (
        env.client.get(back, follow_redirects=False).headers["location"].endswith("error=expired")
    )


@pytest.mark.parametrize("next_path", ["//evil.test/x", "https://evil.test", "/\\evil.test", "app"])
def test_never_lands_on_another_site(env: Env, idp: FakeIdP, next_path: str) -> None:  # noqa: F811
    assert sign_in(env, idp, next_path).headers["location"] == "https://app.acme.test/app"


def test_who_the_providers_word_makes_you(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    pid = idp.provider["id"]  # type: ignore[attr-defined]
    # Without automatic accounts, only people who exist may sign in.
    env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH, json={"auto_create": False})
    idp.claims = {"email": "new@acme.test", "sub": "sub-new"}
    assert sign_in(env, idp).headers["location"].endswith("error=no_account")
    with env.sessions() as s:
        set_session_org(s, ORG)
        meera = svc.create(s, ORG, "t", email="meera@acme.test", role="member")
        s.commit()
        meera_id = meera.id
    idp.claims = {"email": "meera@acme.test", "sub": "sub-meera"}
    r = sign_in(env, idp)
    assert (
        env.client.get("/v2/me", headers={"Cookie": cookie_of(r)}).json()["user"]["id"] == meera_id
    )
    # Another account at the provider with Meera's email cannot take her place.
    idp.claims = {"email": "meera@acme.test", "sub": "sub-impostor"}
    assert sign_in(env, idp).headers["location"].endswith("error=invalid")
    # Her email changing at the provider does not move her: her subject decides.
    idp.claims = {"email": "meera.s@acme.test", "sub": "sub-meera"}
    r = sign_in(env, idp)
    assert (
        env.client.get("/v2/me", headers={"Cookie": cookie_of(r)}).json()["user"]["id"] == meera_id
    )
    # Turned off, she cannot sign in.
    with env.sessions() as s:
        set_session_org(s, ORG)
        svc.create(s, ORG, "t", email="boss@acme.test", role="admin")
        svc.disable(s, ORG, "t", meera_id, reason="left")
    idp.claims = {"email": "meera@acme.test", "sub": "sub-meera"}
    assert sign_in(env, idp).headers["location"].endswith("error=disabled")


def test_entra_style_emails_need_the_provider_to_be_trusted(
    env: Env, idp: FakeIdP
) -> None:  # noqa: F811
    idp.claims = {"email_verified": None}  # Entra ID sends no email_verified claim
    assert sign_in(env, idp).headers["location"].endswith("error=invalid")
    pid = idp.provider["id"]  # type: ignore[attr-defined]
    env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH, json={"trust_email": True})
    assert sign_in(env, idp).headers["location"].endswith("/app/issues")
    idp.claims = {"email_verified": False}  # but an explicit "no" is still no
    assert sign_in(env, idp).headers["location"].endswith("error=invalid")


def test_settings_are_checked_against_the_provider(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    view = idp.provider  # type: ignore[attr-defined]
    assert view["oidc"]["redirect_uri"] == "http://localhost:8000/auth/oidc/callback"
    assert view["secret_store"] == "database" and "client_secret" not in json.dumps(view)
    t = env.client.post(f"/v2/sso/providers/{view['id']}/test", headers=AUTH).json()
    assert t == {"ok": True, "message": "The provider answers, and lists 1 signing key(s)."}
    base = {"kind": "oidc", "name": "x", "client_id": "c", "email_domains": ["other.test"]}
    for issuer, field in (("http://idp.example.com", "issuer"), ("ftp://idp.acme.test", "issuer")):
        r = env.client.post("/v2/sso/providers", headers=AUTH, json={**base, "issuer": issuer})
        assert r.status_code == 422 and r.json()["detail"]["field"] == field
    idp.issuer_says = "https://evil.test"  # the description names another issuer
    oidc._JWKS.clear()
    r = env.client.post("/v2/sso/providers", headers=AUTH,
                        json={**base, "issuer": ISSUER, "email_domains": ["x.test"]})  # fmt: skip
    assert r.status_code == 422 and "says its issuer is" in r.json()["detail"]["message"]
    idp.issuer_says = ISSUER
    r = env.client.post("/v2/sso/providers", headers=AUTH,
                        json={**base, "issuer": ISSUER, "email_domains": ["acme.test"]})  # fmt: skip
    assert r.status_code == 409 and "already signs in" in r.json()["detail"]["message"]
    for bad, field in (({"email_domains": []}, "email_domains"), ({"email_domains": ["not a domain"]}, "email_domains"),
                       ({"default_role": "admin!"}, "default_role"), ({"kind": "ldap"}, "kind")):  # fmt: skip
        r = env.client.post(
            "/v2/sso/providers", headers=AUTH, json={**base, "issuer": ISSUER, **bad}
        )
        assert r.status_code == 422 and r.json()["detail"]["field"] == field, bad
    # Admins only.
    from tests.unit.test_accounts import Person

    member = Person(env, "m@acme.test", "member")
    assert member.get("/v2/sso/providers").status_code == 403
    # A turned-off provider signs nobody in, and is not offered.
    env.client.patch(f"/v2/sso/providers/{view['id']}", headers=AUTH, json={"enabled": False})
    assert env.client.get("/auth/sso/discover", params={"email": "a@acme.test"}).json() == {
        "providers": []
    }
    r = env.client.get(f"/auth/sso/{view['id']}/start", follow_redirects=False)
    assert r.headers["location"].endswith("error=provider")


def test_pkce_values() -> None:
    verifier, challenge = oidc.pkce()
    assert 43 <= len(verifier) <= 128
    assert (
        challenge
        == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )  # noqa: E501


def test_one_provider_for_every_domain_signs_in_only_people_already_added(
    env: Env, idp: FakeIdP  # noqa: F811
) -> None:
    """`*`: e.g. Google for any Google account -- Gmail, a university, a company on Google --
    but only for people an admin has added; never a new account for a stranger."""
    pid = idp.provider["id"]  # type: ignore[attr-defined]
    # Every domain, with first sign-ins creating accounts, would let anyone in: refused.
    r = env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH, json={"email_domains": ["*"]})
    assert r.status_code == 422 and r.json()["detail"]["field"] == "auto_create"
    r = env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH,
                         json={"email_domains": ["*", "acme.test"]})  # fmt: skip
    assert r.status_code == 422 and r.json()["detail"]["field"] == "email_domains"
    r = env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH,
                         json={"email_domains": ["*"], "auto_create": False})  # fmt: skip
    assert r.status_code == 200, r.text
    # ...and it cannot be turned back on while the provider signs in every domain.
    r = env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH, json={"auto_create": True})
    assert r.status_code == 422 and r.json()["detail"]["field"] == "auto_create"

    # Any domain finds it on the sign-in page.
    for email in ("someone@gmail.com", "raghav@college.ac.in"):
        found = env.client.get("/auth/sso/discover", params={"email": email}).json()
        assert found == {"providers": [{"id": pid, "name": "Acme SSO", "kind": "oidc"}]}

    # A stranger with a verified Google account is refused, and no account is made.
    idp.claims = {"email": "stranger@gmail.com", "sub": "sub-stranger"}
    assert sign_in(env, idp).headers["location"].endswith("error=no_account")
    with env.sessions() as s:
        set_session_org(s, ORG)
        assert svc.by_email(s, ORG, "stranger@gmail.com") is None
        svc.create(s, ORG, "t", email="raghav@college.ac.in", role="member")
        s.commit()
    # Someone an admin added signs in, whatever their domain.
    idp.claims = {"email": "raghav@college.ac.in", "sub": "sub-raghav"}
    r = sign_in(env, idp)
    me = env.client.get("/v2/me", headers={"Cookie": cookie_of(r)}).json()["user"]
    assert me["email"] == "raghav@college.ac.in"
    # An unverified email is still refused.
    idp.claims = {"email": "raghav@college.ac.in", "sub": "sub-raghav", "email_verified": False}
    assert sign_in(env, idp).headers["location"].endswith("error=invalid")


def test_a_domains_own_provider_comes_before_the_one_for_every_domain(
    env: Env, idp: FakeIdP  # noqa: F811
) -> None:
    pid = idp.provider["id"]  # type: ignore[attr-defined]
    env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH,
                     json={"email_domains": ["*"], "auto_create": False})  # fmt: skip
    r = env.client.post("/v2/sso/providers", headers=AUTH, json={
        "kind": "oidc", "name": "Acme's own", "issuer": ISSUER, "client_id": CLIENT,
        "email_domains": ["acme.test"]})  # fmt: skip
    assert r.status_code == 201, r.text
    own = env.client.get("/auth/sso/discover", params={"email": "a@acme.test"}).json()
    assert own["providers"][0]["id"] == r.json()["id"]
    other = env.client.get("/auth/sso/discover", params={"email": "a@gmail.com"}).json()
    assert other["providers"][0]["id"] == pid
    # Only one provider can sign in every domain.
    r = env.client.post("/v2/sso/providers", headers=AUTH, json={
        "kind": "oidc", "name": "Another", "issuer": ISSUER, "client_id": CLIENT,
        "email_domains": ["*"], "auto_create": False})  # fmt: skip
    assert r.status_code == 409


def test_every_domain_is_refused_in_hosted_mode(env: Env, idp: FakeIdP) -> None:  # noqa: F811
    from core.identity import sso

    pid = idp.provider["id"]  # type: ignore[attr-defined]
    hosted = env.settings.__class__(**{**env.settings.__dict__, "hosted_mode": True})
    with env.sessions() as s, pytest.raises(sso.SsoError) as err:
        set_session_org(s, ORG)
        sso.save(s, ORG, "t", {"email_domains": ["*"], "auto_create": False}, hosted, pid)
    assert err.value.field == "email_domains" and "hosted mode" in err.value.message


def test_in_hosted_mode_a_provider_is_a_public_address(
    env: Env, idp: FakeIdP, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """The issuer an admin types is fetched by the server. Where admins are customers, it was a
    way to make the server ask its own network (and plain http://localhost was accepted)."""
    from core.identity import sso

    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(str(request.url))
        base = str(request.url).split("/.well-known")[0]
        keys = "https://keys.internal.test/jwks" if "split" in base else f"{base}/keys"
        return httpx.Response(200, json={
            "issuer": base, "authorization_endpoint": f"{base}/auth",
            "token_endpoint": f"{base}/token", "jwks_uri": keys})  # fmt: skip

    http = httpx.Client(transport=httpx.MockTransport(handler))
    private = {"idp.internal.test": "10.0.0.8", "keys.internal.test": "10.0.0.9",
               "localhost": "127.0.0.1"}  # fmt: skip
    monkeypatch.setattr(sso, "RESOLVER", lambda host: [private.get(host, "93.184.216.34")])
    hosted = env.settings.__class__(**{**env.settings.__dict__, "hosted_mode": True})

    def save(issuer: str, domain: str, settings: Any = hosted) -> Any:
        with env.sessions() as s:
            set_session_org(s, ORG)
            raw = {"kind": "oidc", "name": "x", "client_id": "c", "issuer": issuer,
                   "email_domains": [domain]}  # fmt: skip
            try:
                return sso.save(s, ORG, "t", raw, settings, http=http)
            finally:
                s.rollback()

    for issuer in ("https://idp.internal.test", "http://localhost:8080"):
        with pytest.raises(sso.SsoError) as err:
            save(issuer, "a.test")
        assert err.value.field == "issuer" and "cannot be used here" in err.value.message
    assert asked == []  # refused before anything was fetched
    with pytest.raises(sso.SsoError) as err:  # a public issuer that names keys on a private host
        save("https://split.example.com", "b.test")
    assert "key set URL" in err.value.message
    assert save("https://login.example.com", "c.test").config["issuer"] == (
        "https://login.example.com"
    )
    # Self-hosted, the admin runs the server: a provider on their own network is theirs to use.
    assert save("https://idp.internal.test", "d.test", env.settings).kind == "oidc"
