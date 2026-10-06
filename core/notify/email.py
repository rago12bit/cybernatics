"""Email through the operator's SMTP server (plan §49).

Configured for the deployment, not per organization, because it is a server the operator runs or
rents: `BULWARK_SMTP_HOST`, `BULWARK_SMTP_PORT` (587), `BULWARK_SMTP_FROM`, and optionally
`BULWARK_SMTP_USERNAME`/`BULWARK_SMTP_PASSWORD`, `BULWARK_SMTP_TLS` (`starttls`, the default,
`ssl`, or `none` for a local relay such as Mailpit). No host: email is off, and says so.

Messages are plain text only -- an issue title is untrusted text, and plain text cannot carry a
script or a disguised link. Header values have line breaks removed, so a title cannot add headers.
"""

from __future__ import annotations

import os
import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

TIMEOUT_SECONDS = 20
_BREAKS = re.compile(r"[\r\n\t]+")


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int = 587
    sender: str = "bulwark@localhost"
    username: str | None = None
    password: str | None = None
    tls: str = "starttls"  # starttls | ssl | none

    @staticmethod
    def from_env() -> SmtpConfig | None:
        env = os.environ
        host = env.get("BULWARK_SMTP_HOST", "").strip()
        if not host:
            return None
        tls = env.get("BULWARK_SMTP_TLS", "starttls").strip().lower()
        return SmtpConfig(
            host=host,
            port=int(env.get("BULWARK_SMTP_PORT", "465" if tls == "ssl" else "587")),
            sender=env.get("BULWARK_SMTP_FROM", "bulwark@localhost"),
            username=env.get("BULWARK_SMTP_USERNAME") or None,
            password=env.get("BULWARK_SMTP_PASSWORD") or None,
            tls=tls if tls in ("starttls", "ssl", "none") else "starttls",
        )


def header(value: str, limit: int = 200) -> str:
    return _BREAKS.sub(" ", value).strip()[:limit]


def build(cfg: SmtpConfig, to: str, subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = header(cfg.sender)
    msg["To"] = header(to, 320)
    msg["Subject"] = header(subject)
    msg["Date"] = formatdate(usegmt=True)
    msg["Message-ID"] = make_msgid(domain="bulwark.local")
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body)
    return msg


def send(cfg: SmtpConfig, to: str, subject: str, body: str) -> None:
    msg = build(cfg, to, subject, body)
    context = ssl.create_default_context()
    smtp: smtplib.SMTP
    if cfg.tls == "ssl":
        smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=TIMEOUT_SECONDS, context=context)
    else:
        smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=TIMEOUT_SECONDS)
    with smtp:
        if cfg.tls == "starttls":
            smtp.starttls(context=context)
        if cfg.username and cfg.password:
            smtp.login(cfg.username, cfg.password)
        smtp.send_message(msg)
