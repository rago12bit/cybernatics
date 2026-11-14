"""Single sign-on: an organization's identity providers, and turning a provider's word into a
signed-in person (Week 75, plan §51).

**Providers.** An admin adds an OIDC provider (its issuer, our client id and secret) or a SAML one
(core.identity.saml), says which email domains it vouches for, and whether a first sign-in creates
the account (with which role) or the person must exist already (added by an admin, or by SCIM). A
domain belongs to one provider: the sign-in page asks for an email and sends the person to it.
One provider may instead sign in every domain (`*`, e.g. Google for any Google account): it only
signs in people already added, never creates an account, and is the fallback for an email whose
domain has no provider of its own. It is refused in hosted mode, where it would catch the sign-ins
of every other organization's people.
The client secret goes to OpenBao when it is configured, else into the row, and the settings
screen says which.

**Who signs in.** The provider's stable id for the person (OIDC `sub`, SAML NameID) is linked to
their account the first time. After that it is what decides who they are: a second account at the
provider with the same email cannot take their place, and an email changed at the provider does
not move them to someone else's account. The email must be in one of the provider's domains, and
verified (OIDC `email_verified`) unless the provider is set to trust its emails -- Entra ID sends
no such claim. A person turned off cannot sign in.

**Sign-ins in flight** (`login_attempts`) are used once and last ten minutes. The page to return to
afterwards must be a path on this site, never another site.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from core.config import Settings
from core.identity import oidc
from core.identity import users as people
from core.identity.roles import OVERRIDE_ROLES
from core.integrations.ssrf import WebhookUrlError, validate_webhook_url
from core.netsafety import Resolver, default_resolver
from core.persistence import repo
from core.persistence.models import (
    IdentityProvider,
    LoginAttempt,
    SsoDomain,
    User,
    UserIdentity,
)
from core.tenancy import set_session_org

KINDS = ("oidc", "saml")
# Swapped by tests for a fixed resolver, as in core.tickets.sync.
RESOLVER: Resolver = default_resolver
ATTEMPT_TTL = timedelta(minutes=10)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class SsoError(ValueError):
    """`code` is what the sign-in page shows (expired, denied, invalid, no_account, disabled,
    domain, provider); `field` is set for a settings error."""

    def __init__(self, code: str, message: str, status: int = 422, field: str = "") -> None:
        super().__init__(message)
        self.code, self.message, self.status, self.field = code, message, status, field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def oidc_redirect_uri(settings: Settings) -> str:
    return f"{settings.api_public_url}/auth/oidc/callback"


def saml_acs_url(settings: Settings, provider_id: str) -> str:
    return f"{settings.api_public_url}/auth/saml/{provider_id}/acs"


def saml_entity_id(settings: Settings, provider_id: str) -> str:
    return f"{settings.api_public_url}/auth/saml/{provider_id}/metadata"


# --- the secret ----------------------------------------------------------------------------------


def _openbao(settings: Settings) -> Any:
    from core.secrets.openbao import OpenBaoClient

    if settings.openbao_addr and settings.openbao_token:
        return OpenBaoClient(addr=settings.openbao_addr, token=settings.openbao_token)
    return None


def _kv_path(p: IdentityProvider) -> str:
    return f"bulwark/identity-providers/{p.org_id}/{p.id}"


def set_secret(p: IdentityProvider, value: str | None, settings: Settings) -> None:
    if not value:
        p.secret_store, p.secret = "none", None
        return
    bao = _openbao(settings)
    if bao is not None:
        bao.ensure_kv_engine_enabled()
        bao.put_secret(_kv_path(p), value)
        p.secret_store, p.secret = "openbao", None
    else:
        p.secret_store, p.secret = "database", value


def get_secret(p: IdentityProvider, settings: Settings) -> str | None:
    if p.secret_store == "database":
        return p.secret
    if p.secret_store == "openbao":
        bao = _openbao(settings)
        if bao is None:
            raise SsoError("provider", "The provider's secret is in OpenBao, which is not set up.")
        return str(bao.get_secret(_kv_path(p)) or "") or None
    return None


# --- providers -----------------------------------------------------------------------------------


ANY_DOMAIN = "*"


def _domains(raw: Any) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise SsoError("invalid", "Name at least one email domain.", field="email_domains")
    if [str(d).strip() for d in raw] == [ANY_DOMAIN]:
        return [ANY_DOMAIN]
    if any(str(d).strip() == ANY_DOMAIN for d in raw):
        raise SsoError("invalid", "Use * on its own: it already means every domain.",
                       field="email_domains")  # fmt: skip
    out = []
    for d in raw:
        d = str(d).strip().lower().lstrip("@")
        if not _DOMAIN.match(d):
            raise SsoError("invalid", f"{d[:80]!r} is not a domain.", field="email_domains")
        if d not in out:
            out.append(d)
    return out


def view(p: IdentityProvider, settings: Settings) -> dict[str, Any]:
    cfg = dict(p.config or {})
    out = {"id": p.id, "kind": p.kind, "name": p.name, "enabled": p.enabled,
           "email_domains": list(p.email_domains or []), "auto_create": p.auto_create,
           "default_role": p.default_role, "secret_store": p.secret_store,
           "has_secret": p.secret_store != "none", "updated_at": p.updated_at,
           "updated_by": p.updated_by}  # fmt: skip
    if p.kind == "oidc":
        out["oidc"] = {"issuer": cfg.get("issuer"), "client_id": cfg.get("client_id"),
                       "trust_email": bool(cfg.get("trust_email")),
                       "redirect_uri": oidc_redirect_uri(settings)}  # fmt: skip
    else:
        out["saml"] = {"idp_entity_id": cfg.get("idp_entity_id"), "sso_url": cfg.get("sso_url"),
                       "has_certificate": bool(cfg.get("idp_cert")),
                       "sp_entity_id": saml_entity_id(settings, p.id),
                       "acs_url": saml_acs_url(settings, p.id)}  # fmt: skip
    return out


def listing(s: Session, org_id: str) -> list[IdentityProvider]:
    return list(s.scalars(select(IdentityProvider).where(IdentityProvider.org_id == org_id)
                          .order_by(IdentityProvider.name)))  # fmt: skip


def get(s: Session, org_id: str, provider_id: str) -> IdentityProvider:
    p = s.get(IdentityProvider, provider_id) if len(provider_id) <= 36 else None
    if p is None or p.org_id != org_id:
        raise SsoError("invalid", "No such identity provider.", 404)
    return p


def _public_in_hosted_mode(url: str, what: str, settings: Settings) -> None:
    """In hosted mode an organization's admin is a customer, and the issuer they type is an
    address this server then fetches (the provider's description, its keys, its token endpoint).
    It must be a public one there, as a webhook's or a connector's must: otherwise it is a way to
    make the server ask its own network. Self-hosted, the admin runs the server, and a provider on
    a private network (or on this machine, for development) is their own to point at."""
    if not settings.hosted_mode:
        return
    try:
        validate_webhook_url(url, RESOLVER)
    except WebhookUrlError as exc:
        raise SsoError("provider", f"The provider's {what} cannot be used here: {exc}.",
                       field="issuer") from exc  # fmt: skip


def _claim_domains(s: Session, p: IdentityProvider, domains: list[str]) -> None:
    for d in domains:
        taken = s.get(SsoDomain, d)
        if taken is not None and taken.provider_id != p.id:
            raise SsoError("invalid", f"{d} already signs in with another provider.", 409,
                           field="email_domains")  # fmt: skip
    s.execute(delete(SsoDomain).where(SsoDomain.provider_id == p.id))
    s.flush()
    for d in domains:
        s.add(SsoDomain(domain=d, org_id=p.org_id, provider_id=p.id))


def save(
    s: Session, org_id: str, actor: str, raw: dict[str, Any], settings: Settings,
    provider_id: str | None = None, http: httpx.Client | None = None,
) -> IdentityProvider:  # fmt: skip
    """Create or change a provider. OIDC settings are checked against the provider's own
    description before they are kept; SAML ones by core.identity.saml."""
    p = get(s, org_id, provider_id) if provider_id else None
    kind = p.kind if p else raw.get("kind")
    if kind not in KINDS:
        raise SsoError("invalid", "One of: oidc, saml.", field="kind")
    name = str(raw.get("name", p.name if p else "")).strip()
    if not 1 <= len(name) <= 80:
        raise SsoError("invalid", "A name of 1 to 80 characters.", field="name")
    role = raw.get("default_role", p.default_role if p else "member")
    if role not in OVERRIDE_ROLES:
        raise SsoError("invalid", f"One of: {', '.join(OVERRIDE_ROLES)}.", field="default_role")
    now = _now()
    if p is None:
        p = IdentityProvider(org_id=org_id, kind=kind, name=name, enabled=True, config={},
                             secret_store="none", email_domains=[], auto_create=False,
                             default_role=role, created_at=now, updated_at=now,
                             updated_by=actor)  # fmt: skip
        s.add(p)
        s.flush()
    cfg = dict(p.config or {})
    if kind == "oidc":
        issuer = str(raw.get("issuer", cfg.get("issuer", ""))).strip().rstrip("/")
        client_id = str(raw.get("client_id", cfg.get("client_id", ""))).strip()
        if not client_id:
            raise SsoError("invalid", "The client id the provider gave you.", field="client_id")
        try:
            fresh = issuer != cfg.get("issuer") or not cfg.get("jwks_uri") or raw.get("refresh")
            if fresh:
                _public_in_hosted_mode(issuer, "issuer", settings)  # before anything is fetched
            endpoints = oidc.discover(issuer, http) if fresh else {}
        except oidc.OidcError as exc:
            raise SsoError("provider", exc.message, field="issuer") from exc
        for key, what in (("token_endpoint", "token URL"), ("jwks_uri", "key set URL")):
            if key in endpoints:  # the addresses the server itself will call
                _public_in_hosted_mode(endpoints[key], what, settings)
        cfg.update(endpoints)
        trust = bool(raw.get("trust_email", cfg.get("trust_email")))
        cfg.update({"issuer": endpoints.get("issuer", issuer), "client_id": client_id,
                    "trust_email": trust})  # fmt: skip
        if "client_secret" in raw:
            set_secret(p, str(raw["client_secret"] or "") or None, settings)
    else:
        from core.identity import saml

        cfg = saml.clean_config(raw, cfg)
    p.config, p.name, p.default_role = cfg, name, str(role)
    if "enabled" in raw:
        p.enabled = bool(raw["enabled"])
    if "auto_create" in raw:
        p.auto_create = bool(raw["auto_create"])
    if "email_domains" in raw or not p.email_domains:
        p.email_domains = _domains(raw.get("email_domains"))
        if ANY_DOMAIN in p.email_domains and settings.hosted_mode:
            raise SsoError("invalid", "Every domain (*) is not available in hosted mode: it "
                           "would catch other organizations' sign-ins.",
                           field="email_domains")  # fmt: skip
        _claim_domains(s, p, p.email_domains)
    if ANY_DOMAIN in (p.email_domains or []) and p.auto_create:
        raise SsoError("invalid", "A provider for every domain (*) signs in only people already "
                       "added: turn off 'A first sign-in creates the account'.",
                       field="auto_create")  # fmt: skip
    p.updated_at, p.updated_by = now, actor
    s.flush()
    repo.append_audit_entry(
        s, actor=actor, action="sso.provider.saved", target=f"identity_provider:{p.id}",
        payload={"org_id": org_id, "kind": kind, "name": name, "domains": p.email_domains,
                 "auto_create": p.auto_create, "default_role": p.default_role,
                 "enabled": p.enabled},
    )  # fmt: skip
    return p


def remove(s: Session, org_id: str, actor: str, provider_id: str) -> None:
    p = get(s, org_id, provider_id)
    repo.append_audit_entry(
        s, actor=actor, action="sso.provider.deleted", target=f"identity_provider:{p.id}",
        payload={"org_id": org_id, "name": p.name},
    )  # fmt: skip
    s.delete(p)
    s.commit()


# --- signing in ----------------------------------------------------------------------------------


def providers_for_email(s: Session, email: str) -> list[dict[str, str]]:
    """The provider an email signs in with: its domain's own, else the one for every domain (`*`)
    if there is one. Says nothing else: an unknown domain and a disabled provider both give an
    empty list."""
    domain = email.strip().lower().rsplit("@", 1)[-1]
    if not _DOMAIN.match(domain):
        return []
    row = s.get(SsoDomain, domain) or s.get(SsoDomain, ANY_DOMAIN)
    if row is None:
        return []
    set_session_org(s, row.org_id)
    p = s.get(IdentityProvider, row.provider_id)
    if p is None or not p.enabled:
        return []
    return [{"id": p.id, "name": p.name, "kind": p.kind}]


def safe_next(raw: Any) -> str:
    """A path on this site to land on afterwards; anything else lands on the app's home."""
    if not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//") \
            or "\\" in raw or len(raw) > 500 or any(c in raw for c in "\r\n\t"):  # fmt: skip
        return "/app"
    return raw


def provider_for_attempt(s: Session, provider_id: str) -> IdentityProvider:
    """A provider by id before any organization is known: through its domain row (no RLS), then
    under its organization."""
    row = s.scalar(select(SsoDomain).where(SsoDomain.provider_id == provider_id).limit(1))
    if row is None:
        raise SsoError("provider", "No such identity provider.", 404)
    set_session_org(s, row.org_id)
    p = s.get(IdentityProvider, provider_id)
    if p is None or not p.enabled:
        raise SsoError("provider", "This identity provider is turned off.", 404)
    return p


def begin_oidc(
    s: Session, provider_id: str, next_path: Any, settings: Settings,
    login_hint: str | None = None,
) -> str:  # fmt: skip
    """Start a sign-in; returns the provider's URL to send the browser to."""
    p = provider_for_attempt(s, provider_id)
    if p.kind != "oidc":
        raise SsoError("provider", "This provider signs in with SAML.")
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = oidc.pkce()
    now = _now()
    s.add(LoginAttempt(id=digest(state), org_id=p.org_id, provider_id=p.id, nonce=nonce,
                       verifier=verifier, next_path=safe_next(next_path), created_at=now,
                       expires_at=now + ATTEMPT_TTL))  # fmt: skip
    s.commit()
    return oidc.authorize_url(p.config, p.config["client_id"], oidc_redirect_uri(settings), state,
                              nonce, challenge, login_hint)  # fmt: skip


def take_attempt(
    s: Session, *, state: str | None = None, request_id: str | None = None
) -> LoginAttempt:
    """The sign-in this callback finishes, marked used; refused if unknown, used or expired."""
    row = None
    if state:
        row = s.get(LoginAttempt, digest(state)) if len(state) <= 200 else None
    elif request_id:
        row = s.scalar(select(LoginAttempt).where(LoginAttempt.request_id == request_id))
    if row is None:
        raise SsoError("invalid", "This sign-in is not one Bulwark started.")
    if row.used_at is not None:
        raise SsoError("invalid", "This sign-in was already used.")
    if _utc(row.expires_at) <= _now():
        raise SsoError("expired", "This sign-in took too long; start again.")
    row.used_at = _now()
    s.commit()
    return row


def finish_oidc(
    s: Session, code: str | None, state: str | None, settings: Settings,
    http: httpx.Client | None = None, user_agent: str | None = None,
) -> tuple[str, str]:  # fmt: skip
    """Finish an OIDC sign-in; returns the session secret and the path to land on."""
    attempt = take_attempt(s, state=state)
    if not code:
        raise SsoError("denied", "The provider did not sign you in.")
    set_session_org(s, attempt.org_id)
    p = s.get(IdentityProvider, attempt.provider_id)
    if p is None or not p.enabled or p.kind != "oidc":
        raise SsoError("provider", "This identity provider is turned off.")
    try:
        token = oidc.exchange(p.config, p.config["client_id"], get_secret(p, settings), code,
                              oidc_redirect_uri(settings), attempt.verifier or "",
                              http)  # fmt: skip
        claims = oidc.verify_id_token(token, p.config, p.config["client_id"], attempt.nonce or "",
                                      http)  # fmt: skip
    except oidc.OidcError as exc:
        raise SsoError(exc.code, exc.message) from exc
    verified = claims.get("email_verified")
    if verified is not True and not (verified is None and p.config.get("trust_email")):
        raise SsoError("invalid", "The provider has not verified this email address.")
    u = complete(s, p, str(claims["sub"]), claims.get("email"), claims.get("name"), "oidc")
    return start_session(s, u, "oidc", user_agent), attempt.next_path


def complete(
    s: Session, p: IdentityProvider, subject: str, email: Any, name: Any, source: str
) -> User:
    """The person this provider vouches for: by their linked subject, else by email (linking it),
    else a new account when the provider may create them."""
    if not subject or len(subject) > 255:
        raise SsoError("invalid", "The provider did not say who signed in.")
    try:
        email = people.clean_email(email)
    except people.UserError as exc:
        raise SsoError("invalid", "The provider did not give an email address.") from exc
    domains = p.email_domains or []
    any_domain = ANY_DOMAIN in domains
    if not any_domain and email.rsplit("@", 1)[1] not in domains:
        raise SsoError("domain", f"This provider does not sign in {email.rsplit('@', 1)[1]}.")
    linked = s.scalar(select(UserIdentity).where(UserIdentity.provider_id == p.id,
                                                 UserIdentity.subject == subject))  # fmt: skip
    if linked is not None:
        u = s.get(User, linked.user_id)
    else:
        u = people.by_email(s, p.org_id, email)
        if u is not None:
            other = s.scalar(select(UserIdentity).where(UserIdentity.provider_id == p.id,
                                                        UserIdentity.user_id == u.id))  # fmt: skip
            if other is not None:
                raise SsoError("invalid", "This email belongs to another account at the provider.")
        elif p.auto_create and not any_domain:  # every-domain providers never create accounts
            u = people.create(s, p.org_id, f"sso:{p.id}", email=email, name=name,
                              role=p.default_role, source=source)  # fmt: skip
        else:
            raise SsoError("no_account", "You have no account here yet; ask an admin to add you.")
        s.add(UserIdentity(org_id=p.org_id, provider_id=p.id, subject=subject, user_id=u.id,
                           created_at=_now()))  # fmt: skip
        s.flush()
    if u is None or not u.active:
        raise SsoError("disabled", "Your account is turned off.")
    return u


def start_session(s: Session, u: User, method: str, user_agent: str | None) -> str:
    from core.identity import sessions as web_sessions

    secret, _row = web_sessions.start(s, u, method, user_agent)
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=people.actor_of(u.id), action="user.signed_in", target=people.actor_of(u.id),
        payload={"org_id": u.org_id, "method": method},
    )  # fmt: skip
    return secret


@dataclass(frozen=True)
class Test:
    ok: bool
    message: str


def test_oidc(p: IdentityProvider, http: httpx.Client | None = None) -> Test:
    """Read the provider's description and keys now, for the settings screen."""
    try:
        oidc.discover(str(p.config.get("issuer", "")), http)
        keys = oidc._keys(str(p.config.get("jwks_uri", "")), http, refresh=True)
    except oidc.OidcError as exc:
        return Test(False, exc.message)
    return Test(True, f"The provider answers, and lists {len(keys)} signing key(s).")
