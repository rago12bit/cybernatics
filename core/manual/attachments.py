"""Evidence attachments on manual findings (plan §43.2, threat T24: "an HTML or SVG evidence file
that runs script" -> "content sniffing; served from a separate cookieless domain with
Content-Disposition: attachment; never rendered inline").

- **Sniffed, not trusted.** The bytes are classified by what they start with; the uploader's
  claimed type and file name are kept for display only. HTML, SVG and XML are flagged as active
  content -- accepted, because a captured page is real evidence, but labelled as such.
- **Encrypted at rest** with a fresh AES-256-GCM data key per attachment, wrapped by the
  organization's OpenBao key (`core.secrets`), with the attachment's id as associated data, so a
  blob moved onto another row does not decrypt. With no OpenBao configured, attachments are stored
  unencrypted and say so (`encrypted=False`), the same "off means off" posture as scan artifacts.
- **Only ever downloaded.** A short-lived link signed for one attachment and one organization
  (`sign`/`verify`) is served with `Content-Disposition: attachment`, `nosniff`, a sandboxing CSP
  and no caching. The link needs no cookie or bearer token, so it can be served from a separate
  origin (`BULWARK_ATTACHMENTS_ORIGIN`) that has none.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.persistence.models import EvidenceAttachment, ManualFinding, RiskAcceptance
from core.secrets.envelope import decrypt, encrypt
from core.secrets.openbao import OpenBaoClient

MAX_BYTES = 10 * 1024 * 1024
MAX_PER_FINDING = 20
LINK_TTL_SECONDS = 300
_NAME_SAFE = re.compile(r"[^A-Za-z0-9._ ()+-]")


class AttachmentError(ValueError):
    pass


@dataclass(frozen=True)
class Sniffed:
    content_type: str
    active: bool  # can run script if a browser renders it


def sniff(data: bytes) -> Sniffed:
    head = data[:2048]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return Sniffed("image/png", False)
    if head.startswith(b"\xff\xd8\xff"):
        return Sniffed("image/jpeg", False)
    if head.startswith((b"GIF87a", b"GIF89a")):
        return Sniffed("image/gif", False)
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return Sniffed("image/webp", False)
    if head.startswith(b"%PDF-"):
        return Sniffed("application/pdf", True)  # PDFs can carry JavaScript
    if head.startswith(b"PK\x03\x04"):
        return Sniffed("application/zip", False)
    if head.startswith(b"\x1f\x8b"):
        return Sniffed("application/gzip", False)
    if b"\x00" in head:
        return Sniffed("application/octet-stream", False)
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return Sniffed("application/octet-stream", False)
    lowered = text.lstrip("﻿ \t\r\n").lower()
    if "<svg" in lowered[:1024]:
        return Sniffed("image/svg+xml", True)
    if (
        lowered.startswith(("<!doctype html", "<html", "<head", "<body", "<script"))
        or "<script" in lowered
    ):
        return Sniffed("text/html", True)
    if lowered.startswith("<?xml") or lowered.startswith("<"):
        return Sniffed("application/xml", True)
    if lowered.startswith(("{", "[")):
        return Sniffed("application/json", False)  # a HAR file, a JSON response
    if re.match(
        r"^(get|post|put|patch|delete|head|options) \S+ http/\d", lowered
    ) or lowered.startswith("http/"):
        return Sniffed("text/plain; http-capture", False)
    return Sniffed("text/plain", False)


def safe_name(name: str | None) -> str:
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _NAME_SAFE.sub("_", base).strip(" .")[:200]
    return cleaned or "evidence"


def _openbao(addr: str, token: str) -> OpenBaoClient | None:
    return OpenBaoClient(addr=addr, token=token) if addr and token else None


def store(
    s: Session,
    *,
    manual: ManualFinding | None = None,
    acceptance: RiskAcceptance | None = None,
    data: bytes,
    file_name: str | None,
    declared_type: str | None,
    created_by: str | None,
    openbao_addr: str = "",
    openbao_token: str = "",
) -> EvidenceAttachment:
    if not data:
        raise AttachmentError("the file is empty")
    if len(data) > MAX_BYTES:
        raise AttachmentError("an attachment is at most 10 MB")
    owner = manual if manual is not None else acceptance
    if owner is None or (manual is not None and acceptance is not None):
        raise ValueError("an attachment belongs to exactly one manual finding or risk acceptance")
    column = (
        EvidenceAttachment.manual_finding_id
        if manual is not None
        else EvidenceAttachment.risk_acceptance_id
    )
    count = s.scalar(select(func.count()).select_from(EvidenceAttachment).where(column == owner.id))
    if (count or 0) >= MAX_PER_FINDING:
        raise AttachmentError(f"at most {MAX_PER_FINDING} attachments each")
    sniffed = sniff(data)
    row = EvidenceAttachment(
        org_id=owner.org_id,
        manual_finding_id=manual.id if manual is not None else None,
        risk_acceptance_id=acceptance.id if acceptance is not None else None,
        file_name=safe_name(file_name),
        declared_type=(declared_type or "")[:120] or None,
        sniffed_type=sniffed.content_type,
        active_content=sniffed.active,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        data=b"",
        created_by=created_by,
    )
    s.add(row)
    s.flush()  # the id is the associated data the ciphertext is bound to
    client = _openbao(openbao_addr, openbao_token)
    if client is not None:
        client.ensure_org_key(owner.org_id)
        key = client.generate_data_key(owner.org_id)
        row.data = encrypt(key.plaintext, data, associated_data=_aad(row))
        row.wrapped_dek, row.encrypted = key.wrapped, True
    else:
        row.data, row.encrypted = data, False
    s.commit()
    return row


def _aad(row: EvidenceAttachment) -> bytes:
    return f"evidence/{row.org_id}/{row.id}".encode()


def read(row: EvidenceAttachment, *, openbao_addr: str = "", openbao_token: str = "") -> bytes:
    """The attachment's bytes, decrypted when it was encrypted. Raises if it was encrypted and
    OpenBao is not reachable now -- never hands out ciphertext as if it were the file."""
    if not row.encrypted:
        return bytes(row.data)
    client = _openbao(openbao_addr, openbao_token)
    if client is None or not row.wrapped_dek:
        raise AttachmentError("this attachment is encrypted and OpenBao is not configured")
    key = client.unwrap_data_key(row.org_id, row.wrapped_dek)
    plain = decrypt(key, bytes(row.data), associated_data=_aad(row))
    if hashlib.sha256(plain).hexdigest() != row.sha256:  # pragma: no cover - GCM already checked
        raise AttachmentError("the attachment does not match its recorded digest")
    return plain


def list_for(s: Session, manual_id: str, org_id: str) -> list[EvidenceAttachment]:
    return list(
        s.scalars(
            select(EvidenceAttachment)
            .where(
                EvidenceAttachment.manual_finding_id == manual_id,
                EvidenceAttachment.org_id == org_id,
            )
            .order_by(EvidenceAttachment.created_at)
        )
    )


def get(s: Session, attachment_id: str, org_id: str) -> EvidenceAttachment | None:
    return s.scalars(
        select(EvidenceAttachment).where(
            EvidenceAttachment.id == attachment_id, EvidenceAttachment.org_id == org_id
        )
    ).one_or_none()


# --- signed download links ----------------------------------------------------------------------


def link_key(api_token: str) -> bytes:
    """The HMAC key for download links: `BULWARK_LINK_SECRET` when set (share it across API
    replicas), else derived from the deployment's API token -- never the token itself."""
    explicit = os.environ.get("BULWARK_LINK_SECRET", "")
    if explicit:
        return hashlib.sha256(b"bulwark-link-secret|" + explicit.encode()).digest()
    return hashlib.sha256(b"bulwark-attachment-links|" + api_token.encode()).digest()


def _payload(attachment_id: str, org_id: str, expires: int) -> bytes:
    return f"evidence|{attachment_id}|{org_id}|{expires}".encode()


def sign(
    key: bytes, attachment_id: str, org_id: str, *, now: float | None = None
) -> tuple[str, int]:
    """`(token, expires)`: the token carries the org (base64) and a signature over id, org and
    expiry, so the download endpoint can scope its query without a session or a bearer token."""
    expires = int((now if now is not None else time.time()) + LINK_TTL_SECONDS)
    sig = hmac.new(key, _payload(attachment_id, org_id, expires), "sha256").hexdigest()
    org = base64.urlsafe_b64encode(org_id.encode()).decode().rstrip("=")
    return f"{org}.{expires}.{sig}", expires


def verify(key: bytes, attachment_id: str, token: str, *, now: float | None = None) -> str | None:
    """The org the link was signed for, or None if it is malformed, forged or expired."""
    try:
        org_b64, expires_s, sig = token.split(".")
        org_id = base64.urlsafe_b64decode(org_b64 + "=" * (-len(org_b64) % 4)).decode()
        expires = int(expires_s)
    except (ValueError, UnicodeDecodeError):
        return None
    good = hmac.new(key, _payload(attachment_id, org_id, expires), "sha256").hexdigest()
    if not hmac.compare_digest(good, sig):
        return None
    if expires < (now if now is not None else time.time()):
        return None
    return org_id


def download_headers(row: EvidenceAttachment) -> dict[str, str]:
    """Never rendered: an opaque type, a forced download, no sniffing, no script, no caching."""
    ascii_name = row.file_name.encode("ascii", "ignore").decode() or "evidence"
    return {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": f'attachment; filename="{ascii_name}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Resource-Policy": "same-site",
    }
