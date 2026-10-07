"""SAML 2.0 sign-in through a maintained library, pysaml2 (Week 75, plan §51: "SAML is where
hand-rolled code goes wrong: XML signature wrapping, comment injection in the NameID, unsigned
assertions accepted"; ADR-0058).

Bulwark is the service provider. It never parses or checks a SAML response itself: pysaml2 does,
with xmlsec1 checking signatures, configured strictly --

- **assertions must be signed** by the certificate the admin gave (`want_assertions_signed`); a
  signed response around an unsigned assertion is not enough;
- **no unsolicited responses** (`allow_unsolicited` off): each must answer a request Bulwark sent,
  by its `InResponseTo`, and that request is used once (`login_attempts`, with `RelayState`);
- **audience and destination** must be this service and its assertion consumer URL;
- **time**: within a minute of clock skew of the assertion's conditions.

What the tests attack (tests/unit/test_saml.py): an unsigned assertion, a response signed by
another key, an assertion wrapped around or beside a signed one, a comment inside the NameID, a
response for another service, an expired one, a replayed one and an unsolicited one.

The person is the NameID (a `persistent` one, ideally: an email NameID changes when the email
does), with their email from the NameID when it is an email, else from the usual attributes.
"""

from __future__ import annotations

import base64
import re
import secrets
import shutil
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from cryptography import x509
from defusedxml import ElementTree as SafeET
from sqlalchemy.orm import Session

from core.config import Settings
from core.identity import sso
from core.identity.oidc import OidcError, check_url
from core.persistence.models import IdentityProvider, LoginAttempt

MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
EMAIL_ATTRIBUTES = (
    "email", "mail", "emailaddress", "urn:oid:0.9.2342.19200300.100.1.3",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
)  # fmt: skip
NAME_ATTRIBUTES = ("displayname", "name", "cn", "urn:oid:2.16.840.1.113730.3.1.241",
                   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")  # fmt: skip
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
_PEM = re.compile(r"-----(BEGIN|END) CERTIFICATE-----|\s")


def xmlsec_binary() -> str:
    found = shutil.which("xmlsec1")
    if not found:
        raise sso.SsoError("provider", "xmlsec1 is not installed on this server; SAML needs it.")
    return found


def _cert(raw: Any) -> str:
    """A certificate as base64 DER (what metadata carries), checked to be one."""
    body = _PEM.sub("", raw or "") if isinstance(raw, str) else ""
    try:
        x509.load_der_x509_certificate(base64.b64decode(body, validate=True))
    except (ValueError, TypeError) as exc:
        raise sso.SsoError("invalid", "The identity provider's signing certificate, please.",
                           field="idp_cert") from exc  # fmt: skip
    return body


def _from_metadata(xml: str) -> dict[str, str]:
    """The IdP's entity id, redirect sign-in URL and signing certificate, from its metadata."""
    try:
        root = SafeET.fromstring(xml.encode())
    except Exception as exc:  # defusedxml raises several kinds, all meaning "not usable"
        raise sso.SsoError(
            "invalid", "That is not SAML metadata.", field="idp_metadata_xml"
        ) from exc
    entity = (
        root if root.tag == f"{{{MD}}}EntityDescriptor" else root.find(f"{{{MD}}}EntityDescriptor")
    )
    idp = entity.find(f"{{{MD}}}IDPSSODescriptor") if entity is not None else None
    if entity is None or idp is None:
        raise sso.SsoError("invalid", "The metadata describes no identity provider.",
                           field="idp_metadata_xml")  # fmt: skip
    sso_url = next((e.get("Location") for e in idp.findall(f"{{{MD}}}SingleSignOnService")
                    if e.get("Binding") == REDIRECT), None)  # fmt: skip
    cert = None
    for kd in idp.findall(f"{{{MD}}}KeyDescriptor"):
        if kd.get("use") in (None, "signing"):
            c = kd.find(f".//{{{DS}}}X509Certificate")
            if c is not None and c.text:
                cert = c.text
                break
    return {"idp_entity_id": entity.get("entityID") or "", "sso_url": sso_url or "",
            "idp_cert": cert or ""}  # fmt: skip


def clean_config(raw: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    out = dict(cfg)
    if raw.get("idp_metadata_xml"):
        out.update(_from_metadata(str(raw["idp_metadata_xml"])))
    for key in ("idp_entity_id", "sso_url", "idp_cert"):
        if raw.get(key):
            out[key] = str(raw[key]).strip()
    if not out.get("idp_entity_id"):
        raise sso.SsoError("invalid", "The identity provider's entity id.", field="idp_entity_id")
    try:
        out["sso_url"] = check_url(out.get("sso_url"), "sign-in URL")
    except OidcError as exc:
        raise sso.SsoError("invalid", exc.message, field="sso_url") from exc
    out["idp_cert"] = _cert(out.get("idp_cert"))
    return out


def _idp_metadata(cfg: dict[str, Any]) -> str:
    return (
        f'<md:EntityDescriptor xmlns:md="{MD}" xmlns:ds="{DS}" '
        f'entityID="{escape(cfg["idp_entity_id"], {chr(34): "&quot;"})}">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
        f"{cfg['idp_cert']}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        f'<md:SingleSignOnService Binding="{REDIRECT}" '
        f'Location="{escape(cfg["sso_url"], {chr(34): "&quot;"})}"/>'
        f"</md:IDPSSODescriptor></md:EntityDescriptor>"
    )


def client(p: IdentityProvider, settings: Settings) -> Any:
    from saml2 import BINDING_HTTP_POST
    from saml2.client import Saml2Client
    from saml2.config import SPConfig

    cfg = p.config
    conf = SPConfig()
    conf.load({
        "entityid": sso.saml_entity_id(settings, p.id),
        "xmlsec_binary": xmlsec_binary(),
        "metadata": {"inline": [_idp_metadata(cfg)]},
        "accepted_time_diff": 60,
        "allow_unknown_attributes": True,
        "service": {"sp": {
            "endpoints": {"assertion_consumer_service": [
                (sso.saml_acs_url(settings, p.id), BINDING_HTTP_POST)]},
            "allow_unsolicited": False,
            "authn_requests_signed": False,
            "want_assertions_signed": True,
            "want_response_signed": False,
            "idp": {cfg["idp_entity_id"]: None},
        }},
    })  # fmt: skip
    return Saml2Client(config=conf)


def sp_metadata(p: IdentityProvider, settings: Settings) -> str:
    from saml2.metadata import create_metadata_string

    if p.kind != "saml":
        raise sso.SsoError("provider", "This provider signs in with OIDC.", 404)
    return str(create_metadata_string(None, client(p, settings).config, 4).decode())


def begin(s: Session, p: IdentityProvider, next_path: Any, settings: Settings) -> str:
    """Start a SAML sign-in; returns the IdP URL (HTTP-Redirect binding) to send the browser to."""
    from saml2 import BINDING_HTTP_REDIRECT

    state = secrets.token_urlsafe(32)
    request_id, info = client(p, settings).prepare_for_authenticate(
        entityid=p.config["idp_entity_id"], relay_state=state, binding=BINDING_HTTP_REDIRECT
    )
    now = datetime.now(timezone.utc)
    s.add(LoginAttempt(id=sso.digest(state), org_id=p.org_id, provider_id=p.id,
                       request_id=str(request_id), next_path=sso.safe_next(next_path),
                       created_at=now, expires_at=now + sso.ATTEMPT_TTL))  # fmt: skip
    s.commit()
    return str(dict(info["headers"])["Location"])


def _first(ava: dict[str, list[Any]], names: tuple[str, ...]) -> str | None:
    lowered = {k.lower(): v for k, v in ava.items()}
    for n in names:
        v = lowered.get(n.lower())
        if v:
            return str(v[0])
    return None


def finish(
    s: Session, provider_id: str, response_b64: str, relay_state: str, settings: Settings,
    user_agent: str | None = None,
) -> tuple[str, str]:  # fmt: skip
    """Check a SAML response with pysaml2 and sign the person in; returns the session secret and
    the path to land on."""
    from saml2 import BINDING_HTTP_POST

    if not response_b64 or len(response_b64) > 1_000_000:
        raise sso.SsoError("invalid", "No SAML response.")
    attempt = sso.take_attempt(s, state=relay_state or None)
    if attempt.provider_id != provider_id or not attempt.request_id:
        raise sso.SsoError("invalid", "This response is for another sign-in.")
    p = sso.provider_for_attempt(s, provider_id)
    try:
        resp = client(p, settings).parse_authn_request_response(
            response_b64, BINDING_HTTP_POST, outstanding={attempt.request_id: attempt.next_path}
        )
    except sso.SsoError:
        raise
    except Exception as exc:  # pysaml2 raises many kinds; each means "not accepted"
        raise sso.SsoError("invalid", f"The SAML response was refused: {type(exc).__name__}: "
                                      f"{str(exc)[:300]}") from exc  # fmt: skip
    if resp is None or getattr(resp, "in_response_to", None) != attempt.request_id:
        raise sso.SsoError("invalid", "The SAML response does not answer this sign-in.")
    name_id = resp.name_id
    subject = (name_id.text or "").strip() if name_id is not None else ""
    ava = resp.ava or {}
    email = subject if name_id is not None and name_id.format == EMAIL_FORMAT else None
    email = email or _first(ava, EMAIL_ATTRIBUTES)
    u = sso.complete(s, p, subject, email, _first(ava, NAME_ATTRIBUTES), "saml")
    return sso.start_session(s, u, "saml", user_agent), attempt.next_path


def test(p: IdentityProvider) -> sso.Test:
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(p.config.get("idp_cert", "")))
        xmlsec_binary()
    except (ValueError, sso.SsoError) as exc:
        return sso.Test(False, str(getattr(exc, "message", exc)))
    until = cert.not_valid_after_utc
    if until <= datetime.now(timezone.utc):
        return sso.Test(False, f"The provider's certificate expired on {until:%Y-%m-%d}.")
    return sso.Test(
        True, f"Settings read; the provider's certificate is valid until {until:%Y-%m-%d}."
    )
