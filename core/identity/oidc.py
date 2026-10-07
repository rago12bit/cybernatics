"""OpenID Connect sign-in, authorization code flow with PKCE (Week 75, plan §51: "OIDC sign-in
(Google Workspace, Microsoft Entra ID, Okta) with PKCE and strict issuer, audience, and nonce
validation").

What is checked, and refused otherwise:

- **The provider's own description** (`/.well-known/openid-configuration`) must name exactly the
  issuer configured, and every URL in it must be HTTPS -- plain HTTP only for a provider on this
  machine (localhost, `*.localhost`, `*.test`), for development.
- **PKCE (S256)** on every sign-in, and a `state` that is used once.
- **The ID token's signature**, with a key from the provider's JWKS, by an asymmetric algorithm
  only (RS*, PS*, ES*): never `none`, never HS* -- an HMAC "signed" with the provider's public key
  is the classic key-confusion forgery.
- **Its claims:** `iss` exactly the issuer; `aud` contains our client id, and when it names others
  too, `azp` is ours; not expired, not issued in the future (a minute of clock skew either way);
  `nonce` the one this sign-in sent; a `sub`.

The caller (core.identity.sso) then decides who the person is from `sub` and the email.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
LEEWAY = 60
JWKS_TTL = 600
_LOCAL = ("localhost", "127.0.0.1", "::1", "[::1]")


class OidcError(ValueError):
    """`code` says what kind of failure it was, for the sign-in page; `message` is for logs and
    the admin's test."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def _local(host: str) -> bool:
    return host in _LOCAL or host.endswith(".localhost") or host.endswith(".test")


def check_url(url: Any, what: str) -> str:
    if not isinstance(url, str) or not url:
        raise OidcError("provider", f"The provider did not give its {what}.")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https" or (parts.scheme == "http" and _local(host)):
        return url
    raise OidcError("provider", f"The provider's {what} must be HTTPS: {url[:200]}")


def client(http: httpx.Client | None = None) -> httpx.Client:
    return http or httpx.Client(timeout=10.0, follow_redirects=False)


def discover(issuer: str, http: httpx.Client | None = None) -> dict[str, Any]:
    """The provider's endpoints, from its own description, checked against the issuer."""
    issuer = check_url(issuer.rstrip("/"), "issuer")
    try:
        r = client(http).get(f"{issuer}/.well-known/openid-configuration")
        doc = r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise OidcError("provider", f"Could not read the provider's description: {exc}") from exc
    if not isinstance(doc, dict):
        raise OidcError("provider", "The provider's description is not there.")
    if str(doc.get("issuer", "")).rstrip("/") != issuer:
        raise OidcError(
            "provider",
            f"The provider says its issuer is {str(doc.get('issuer'))[:200]!r}, not {issuer!r}.",
        )
    algs = doc.get("id_token_signing_alg_values_supported") or list(ALGORITHMS)
    return {
        "issuer": str(doc["issuer"]),
        "authorization_endpoint": check_url(doc.get("authorization_endpoint"), "sign-in URL"),
        "token_endpoint": check_url(doc.get("token_endpoint"), "token URL"),
        "jwks_uri": check_url(doc.get("jwks_uri"), "key set URL"),
        "algorithms": [a for a in algs if a in ALGORITHMS] or ["RS256"],
    }


def pkce() -> tuple[str, str]:
    """A PKCE verifier and its S256 challenge (RFC 7636)."""
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def authorize_url(
    config: dict[str, Any], client_id: str, redirect_uri: str, state: str, nonce: str,
    challenge: str, login_hint: str | None = None,
) -> str:  # fmt: skip
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
              "scope": "openid email profile", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}  # fmt: skip
    if login_hint:
        params["login_hint"] = login_hint
    sep = "&" if "?" in config["authorization_endpoint"] else "?"
    return f"{config['authorization_endpoint']}{sep}{urlencode(params)}"


def exchange(
    config: dict[str, Any], client_id: str, secret: str | None, code: str, redirect_uri: str,
    verifier: str, http: httpx.Client | None = None,
) -> str:  # fmt: skip
    """Trade the code for tokens; returns the ID token."""
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "code_verifier": verifier, "client_id": client_id}  # fmt: skip
    try:
        if secret:  # client_secret_basic
            r = client(http).post(config["token_endpoint"], data=data, auth=(client_id, secret),
                                  headers={"Accept": "application/json"})  # fmt: skip
        else:  # a public client: PKCE alone
            r = client(http).post(config["token_endpoint"], data=data,
                                  headers={"Accept": "application/json"})  # fmt: skip
        body = r.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise OidcError("provider", f"The provider's token endpoint failed: {exc}") from exc
    if r.status_code != 200 or not isinstance(body, dict) or "id_token" not in body:
        err = body.get("error") if isinstance(body, dict) else None
        raise OidcError("denied", f"The provider refused the sign-in ({err or r.status_code}).")
    return str(body["id_token"])


@dataclass
class _Keys:
    fetched: float
    keys: dict[str, Any]


_JWKS: dict[str, _Keys] = {}


def _keys(jwks_uri: str, http: httpx.Client | None, refresh: bool = False) -> dict[str, Any]:
    cached = _JWKS.get(jwks_uri)
    if cached and not refresh and time.time() - cached.fetched < JWKS_TTL:
        return cached.keys
    try:
        r = client(http).get(jwks_uri)
        doc = r.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise OidcError("provider", f"Could not read the provider's keys: {exc}") from exc
    keys: dict[str, Any] = {}
    for jwk in doc.get("keys", []) if isinstance(doc, dict) else []:
        if not isinstance(jwk, dict) or jwk.get("use", "sig") != "sig":
            continue
        try:
            keys[str(jwk.get("kid", ""))] = jwt.PyJWK(jwk)
        except (jwt.PyJWKError, jwt.InvalidKeyError):
            continue  # a key of a kind we do not use (or cannot read) is skipped, not fatal
    _JWKS[jwks_uri] = _Keys(time.time(), keys)
    return keys


def verify_id_token(
    token: str, config: dict[str, Any], client_id: str, nonce: str,
    http: httpx.Client | None = None, now: float | None = None,
) -> dict[str, Any]:  # fmt: skip
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OidcError("invalid", "The ID token is not a JWT.") from exc
    alg = header.get("alg")
    allowed = [a for a in config.get("algorithms", ALGORITHMS) if a in ALGORITHMS]
    if alg not in allowed:
        raise OidcError("invalid", f"The ID token is signed with {alg!r}, which is not accepted.")
    kid = str(header.get("kid", ""))
    keys = _keys(config["jwks_uri"], http)
    key = keys.get(kid) or (keys.get("") if len(keys) == 1 and not kid else None)
    if key is None:  # rotated: look once more
        keys = _keys(config["jwks_uri"], http, refresh=True)
        key = keys.get(kid)
    if key is None:
        raise OidcError("invalid", "The ID token was signed with a key the provider does not list.")
    try:
        claims: dict[str, Any] = jwt.decode(
            token, key.key, algorithms=[str(alg)], audience=client_id, issuer=config["issuer"],
            leeway=LEEWAY, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )  # fmt: skip
    except jwt.ExpiredSignatureError as exc:
        raise OidcError("expired", "The ID token has expired.") from exc
    except jwt.PyJWTError as exc:
        raise OidcError("invalid", f"The ID token is not valid: {exc}") from exc
    t = now if now is not None else time.time()
    if float(claims["iat"]) > t + LEEWAY:
        raise OidcError("invalid", "The ID token was issued in the future.")
    aud = claims["aud"]
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != client_id:
        raise OidcError(
            "invalid", "The ID token is for several clients, and not authorized for us."
        )
    if not nonce or not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("invalid", "The ID token's nonce does not match this sign-in.")
    return claims
