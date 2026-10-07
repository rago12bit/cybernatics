"""SAML 2.0 sign-in through pysaml2 (Week 75, plan §51: "Test against those specific attacks:
XML signature wrapping, comment injection in the NameID, unsigned assertions accepted"; threat T30).

A real identity provider -- pysaml2's own IdP, with its own key, signing through xmlsec1 -- issues
responses; Bulwark's service provider must accept a properly signed one and refuse every forgery.
Needs the xmlsec1 binary (skipped without it, as CI's unit job has none)."""

from __future__ import annotations

import base64
import logging
import re
import shutil
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core.identity import users as svc
from core.tenancy import DEFAULT_ORG_ID as ORG
from core.tenancy import set_session_org
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    Env,
    env,  # noqa: F401  (the fixture)
)

pytestmark = pytest.mark.skipif(shutil.which("xmlsec1") is None, reason="xmlsec1 not installed")


@pytest.fixture(autouse=True)
def _reasons(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="api.sso")


IDP = "https://idp.acme.test/saml"
SSO_URL = "https://idp.acme.test/saml/sso"


def key_and_cert(tmp: Path, name: str) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256()))  # fmt: skip
    kp, cp = tmp / f"{name}.key", tmp / f"{name}.crt"
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))  # fmt: skip
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cp.write_bytes(pem)
    return kp, cp, pem.decode()


class FakeIdP:
    def __init__(self, tmp: Path, sp_metadata: str, name: str = "idp") -> None:
        from saml2 import BINDING_HTTP_REDIRECT
        from saml2.config import IdPConfig
        from saml2.server import Server

        self.key, self.cert, self.pem = key_and_cert(tmp, name)
        md = tmp / f"sp-{name}.xml"
        md.write_text(sp_metadata)
        conf = IdPConfig()
        conf.load({
            "entityid": IDP, "xmlsec_binary": shutil.which("xmlsec1"),
            "key_file": str(self.key), "cert_file": str(self.cert),
            "metadata": {"local": [str(md)]},
            "service": {"idp": {"endpoints": {"single_sign_on_service": [(SSO_URL, BINDING_HTTP_REDIRECT)]},
                                "policy": {"default": {"lifetime": {"minutes": 15},
                                                       "attribute_restrictions": None}}}},
        })  # fmt: skip
        self.server = Server(config=conf)

    def request_id(self, redirect_url: str) -> str:
        from saml2 import BINDING_HTTP_REDIRECT

        q = parse_qs(urlsplit(redirect_url).query)
        req = self.server.parse_authn_request(q["SAMLRequest"][0], BINDING_HTTP_REDIRECT)
        return str(req.message.id)

    def response(self, in_response_to: str | None, acs: str, sp: str, *, name_id: str = "p-123",
                 email: str = "priya@acme.test", sign_assertion: bool = True,
                 email_format: bool = False) -> str:  # fmt: skip
        from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_PERSISTENT, NameID

        fmt = NAMEID_FORMAT_EMAILADDRESS if email_format else NAMEID_FORMAT_PERSISTENT
        resp = self.server.create_authn_response(
            identity={"mail": [email], "displayName": ["Priya N."]}, in_response_to=in_response_to,
            destination=acs, sp_entity_id=sp, name_id=NameID(format=fmt, text=name_id),
            userid=name_id, sign_assertion=sign_assertion, sign_response=False,
            authn={"class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
        )  # fmt: skip
        return str(resp)


@pytest.fixture
def saml(env: Env, tmp_path: Path) -> dict[str, Any]:  # noqa: F811
    _, _, pem = key_and_cert(tmp_path, "boot")
    r = env.client.post("/v2/sso/providers", headers=AUTH, json={
        "kind": "saml", "name": "Acme SAML", "idp_entity_id": IDP, "sso_url": SSO_URL,
        "idp_cert": pem, "email_domains": ["acme.test"], "auto_create": True,
        "default_role": "member"})  # fmt: skip
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    md = env.client.get(f"/auth/saml/{pid}/metadata")
    assert md.status_code == 200 and "AssertionConsumerService" in md.text
    idp = FakeIdP(tmp_path, md.text)
    # The provider's real certificate.
    env.client.patch(f"/v2/sso/providers/{pid}", headers=AUTH, json={"idp_cert": idp.pem})
    view = r.json()["saml"]
    return {"id": pid, "idp": idp, "acs": view["acs_url"], "sp": view["sp_entity_id"],
            "tmp": tmp_path, "metadata": md.text}  # fmt: skip


def start(
    env: Env, saml: dict[str, Any], next_path: str = "/app/issues"
) -> tuple[str, str]:  # noqa: F811
    r = env.client.get(f"/auth/sso/{saml['id']}/start", params={"next": next_path},
                       follow_redirects=False)  # fmt: skip
    assert r.status_code == 303 and r.headers["location"].startswith(SSO_URL)
    relay = parse_qs(urlsplit(r.headers["location"]).query)["RelayState"][0]
    return saml["idp"].request_id(r.headers["location"]), relay


def post(env: Env, saml: dict[str, Any], xml: str, relay: str) -> Any:  # noqa: F811
    return env.client.post(f"/auth/saml/{saml['id']}/acs", follow_redirects=False,
                           data={"SAMLResponse": base64.b64encode(xml.encode()).decode(),
                                 "RelayState": relay})  # fmt: skip


def signed_in_as(env: Env, r: Any) -> str | None:  # noqa: F811
    if "set-cookie" not in r.headers:
        return None
    cookie = r.headers["set-cookie"].split(";", 1)[0]
    return str(env.client.get("/v2/me", headers={"Cookie": cookie}).json()["user"]["email"])


def test_a_signed_response_signs_the_person_in(
    env: Env, saml: dict[str, Any]
) -> None:  # noqa: F811
    rid, relay = start(env, saml)
    r = post(env, saml, saml["idp"].response(rid, saml["acs"], saml["sp"]), relay)
    assert r.status_code == 303 and r.headers["location"] == "http://localhost:3000/app/issues"
    assert signed_in_as(env, r) == "priya@acme.test"
    # Replayed: refused (the sign-in it answered is used up).
    again = post(env, saml, saml["idp"].response(rid, saml["acs"], saml["sp"]), relay)
    assert again.headers["location"].endswith("error=invalid") and signed_in_as(env, again) is None


def refused(env: Env, r: Any, caplog: pytest.LogCaptureFixture, why: str) -> None:  # noqa: F811
    """Refused, and for the reason the test is about -- not some other failure on the way."""
    assert r.status_code == 303 and "/signin?error=" in r.headers["location"], r.headers
    assert signed_in_as(env, r) is None
    reasons = [m for m in caplog.messages if "sign-in refused" in m]
    assert reasons and why in reasons[-1], reasons


def test_an_unsigned_assertion_is_refused(
    env: Env, saml: dict[str, Any], caplog: pytest.LogCaptureFixture  # noqa: F811
) -> None:
    rid, relay = start(env, saml)
    xml = saml["idp"].response(rid, saml["acs"], saml["sp"], sign_assertion=False)
    refused(env, post(env, saml, xml, relay), caplog, "Signature missing for assertion")


def test_a_response_signed_by_another_key_is_refused(
    env: Env, saml: dict[str, Any], caplog: pytest.LogCaptureFixture  # noqa: F811
) -> None:
    stranger = FakeIdP(saml["tmp"], saml["metadata"], name="stranger")
    rid, relay = start(env, saml)
    xml = stranger.response(rid, saml["acs"], saml["sp"])
    refused(env, post(env, saml, xml, relay), caplog, "Failed to verify signature")


def test_a_tampered_assertion_is_refused(
    env: Env, saml: dict[str, Any], caplog: pytest.LogCaptureFixture  # noqa: F811
) -> None:
    rid, relay = start(env, saml)
    xml = saml["idp"].response(rid, saml["acs"], saml["sp"], email="mallory@acme.test")
    forged = xml.replace("mallory@acme.test", "priya@acme.test")
    refused(env, post(env, saml, forged, relay), caplog, "Failed to verify signature")


def _assertion(xml: str) -> str:
    m = re.search(r"<(\w+:)?Assertion\b.*?</(\w+:)?Assertion>", xml, re.S)
    assert m
    return m.group(0)


def _unsigned_twin(signed: str, email: str, name_id: str) -> str:
    """The signed assertion with its signature removed, a new id, and someone else in it."""
    twin = re.sub(r"<(\w+:)?Signature\b.*?</(\w+:)?Signature>", "", signed, flags=re.S)
    twin = re.sub(r'ID="[^"]+"', 'ID="id-evil-twin"', twin, count=1)
    twin = re.sub(r"(<(?:\w+:)?NameID\b[^>]*>)[^<]+(<)", rf"\g<1>{name_id}\g<2>", twin, count=1)
    return re.sub(r"mallory@acme\.test", email, twin)


@pytest.mark.parametrize("how,why", [
    ("evil before signed", "Invalid number of assertions"),
    ("evil after signed", "Invalid number of assertions"),
    ("signed inside evil", "Signature missing for assertion"),
])  # fmt: skip
def test_signature_wrapping_is_refused(
    env: Env,
    saml: dict[str, Any],
    how: str,
    why: str,
    caplog: pytest.LogCaptureFixture,  # noqa: F811
) -> None:
    """XML signature wrapping (XSW): the signed assertion stays, so the signature still checks; a
    forged one is put where a careless reader takes it from. Bulwark must never sign the forged
    person in."""
    with env.sessions() as s:  # the victim, who must never be signed in as
        set_session_org(s, ORG)
        svc.create(s, ORG, "t", email="ceo@acme.test", role="admin")
        s.commit()
    rid, relay = start(env, saml)
    xml = saml["idp"].response(rid, saml["acs"], saml["sp"], email="mallory@acme.test",
                               name_id="p-mallory")  # fmt: skip
    signed = _assertion(xml)
    evil = _unsigned_twin(signed, "ceo@acme.test", "p-ceo")
    if how == "evil before signed":
        forged = xml.replace(signed, evil + signed)
    elif how == "evil after signed":
        forged = xml.replace(signed, signed + evil)
    else:  # the signed assertion tucked inside the forged one, in its Advice
        end = re.search(r"</(\w+:)?Assertion>$", evil)
        assert end is not None
        prefix = end.group(1) or ""
        conditions_end = re.search(rf"</{re.escape(prefix)}Conditions>", evil)
        assert conditions_end is not None
        cut = conditions_end.end()
        forged = xml.replace(signed, evil[:cut] + f"<{prefix}Advice>{signed}</{prefix}Advice>"
                             + evil[cut:])  # fmt: skip
    from xml.dom.minidom import parseString

    parseString(forged)  # well-formed: the refusal below must come from the signature check
    r = post(env, saml, forged, relay)
    refused(env, r, caplog, why)


def test_a_comment_in_the_name_id_does_not_change_who_signs_in(
    env: Env, saml: dict[str, Any], caplog: pytest.LogCaptureFixture  # noqa: F811
) -> None:
    """The 2018 NameID comment attack: Mallory owns `ceo@acme.test.evil.test` at the IdP, gets a
    signed assertion for it, and puts a comment after `acme.test`. Canonicalization drops comments,
    so the signature still checks; a library that reads only the text before the comment would
    sign her in as ceo@acme.test."""
    with env.sessions() as s:
        set_session_org(s, ORG)
        svc.create(s, ORG, "t", email="ceo@acme.test", role="admin")
        s.commit()
    rid, relay = start(env, saml)
    xml = saml["idp"].response(rid, saml["acs"], saml["sp"], email="ceo@acme.test.evil.test",
                               name_id="ceo@acme.test.evil.test", email_format=True)  # fmt: skip
    forged = xml.replace(">ceo@acme.test.evil.test<", ">ceo@acme.test<!---->.evil.test<", 1)
    assert forged != xml
    r = post(env, saml, forged, relay)
    # The signature still checks; the NameID is read whole, so this is Mallory's own address --
    # which the provider does not vouch for -- never the CEO's.
    refused(env, r, caplog, "does not sign in acme.test.evil.test")


def test_a_response_for_another_service_is_refused(
    env: Env, saml: dict[str, Any], caplog: pytest.LogCaptureFixture  # noqa: F811
) -> None:
    rid, relay = start(env, saml)
    xml = saml["idp"].response(rid, saml["acs"], "https://other.test/sp")
    refused(env, post(env, saml, xml, relay), caplog, "AudienceRestrictions")


def test_unsolicited_and_crossed_responses_are_refused(
    env: Env, saml: dict[str, Any], caplog: pytest.LogCaptureFixture  # noqa: F811
) -> None:
    idp, acs, sp = saml["idp"], saml["acs"], saml["sp"]
    rid, relay = start(env, saml)
    refused(env, post(env, saml, idp.response(None, acs, sp), relay), caplog, "Unsolicited")
    rid_a, _ = start(env, saml)
    _, relay_b = start(env, saml)
    refused(env, post(env, saml, idp.response(rid_a, acs, sp), relay_b), caplog, "Unsolicited")
    refused(env, post(env, saml, idp.response(rid, acs, sp), "made-up"), caplog,
            "not one Bulwark started")  # fmt: skip


def test_an_expired_response_is_refused(
    env: Env,
    saml: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The response arrives two hours after the IdP made it: past its NotOnOrAfter."""
    import saml2.time_util as tu

    rid, relay = start(env, saml)
    xml = saml["idp"].response(rid, saml["acs"], saml["sp"])
    later = int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp())
    monkeypatch.setattr(tu, "utc_now", lambda: later)
    refused(env, post(env, saml, xml, relay), caplog, "ResponseLifetimeExceed")


def test_settings(env: Env, saml: dict[str, Any], tmp_path: Path) -> None:  # noqa: F811
    t = env.client.post(f"/v2/sso/providers/{saml['id']}/test", headers=AUTH).json()
    assert t["ok"] and "valid until" in t["message"]
    base = {"kind": "saml", "name": "x", "email_domains": ["other.test"], "idp_entity_id": IDP,
            "sso_url": SSO_URL, "idp_cert": saml["idp"].pem}  # fmt: skip
    for bad, field in (({"idp_cert": "not a cert"}, "idp_cert"), ({"sso_url": "http://idp.example.com/sso"}, "sso_url"),
                       ({"idp_entity_id": ""}, "idp_entity_id"), ({"idp_metadata_xml": "<nope"}, "idp_metadata_xml")):  # fmt: skip
        r = env.client.post("/v2/sso/providers", headers=AUTH, json={**base, **bad})
        assert r.status_code == 422 and r.json()["detail"]["field"] == field, (bad, r.text)
    # From the IdP's metadata.
    pem = re.sub(r"-----[A-Z ]+-----|\s", "", saml["idp"].pem)
    md = (f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
          f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp2.test/saml">'
          f'<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
          f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{pem}'
          f"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
          f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
          f'Location="https://idp2.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>')  # fmt: skip
    r = env.client.post("/v2/sso/providers", headers=AUTH,
                        json={"kind": "saml", "name": "From metadata", "email_domains": ["idp2.test"],
                              "idp_metadata_xml": md})  # fmt: skip
    assert r.status_code == 201, r.text
    assert r.json()["saml"]["idp_entity_id"] == "https://idp2.test/saml"
    assert r.json()["saml"]["sso_url"] == "https://idp2.test/sso"
    # Billion laughs in the metadata: refused, not expanded.
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
            "<lolz>&lol2;</lolz>")  # fmt: skip
    r = env.client.post("/v2/sso/providers", headers=AUTH,
                        json={**base, "email_domains": ["b.test"], "idp_metadata_xml": bomb})  # fmt: skip
    assert r.status_code == 422


def test_the_request_bulwark_sends(env: Env, saml: dict[str, Any]) -> None:  # noqa: F811
    r = env.client.get(f"/auth/sso/{saml['id']}/start", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15).decode()
    assert f'AssertionConsumerServiceURL="{saml["acs"]}"' in xml
    assert f">{saml['sp']}</" in xml  # our issuer
