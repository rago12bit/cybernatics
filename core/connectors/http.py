"""The one HTTP client every connector uses (plan §42.5, threat T25: "connector URL pointed at
internal services; over-scoped tokens" -> "SSRF guard and egress proxy; credentials in OpenBao;
narrowest scopes").

- **SSRF guard.** A connector's base URL is configured by a person and can be anything, so it is
  checked the way outbound webhooks are (`core.netsafety`): https only, no credentials in the URL,
  and every address the host resolves to must be public -- checked again on every request, not
  only when the connector is saved, because DNS can change. A self-hosted instance on a private
  network needs `BULWARK_CONNECTOR_ALLOW_PRIVATE=1`, an explicit operator decision (and how the
  local DefectDojo round trip runs).
- **Bounded.** Timeouts on every request, a response-size cap, no redirects followed (a redirect is
  how an allowed host hands you to a forbidden one), and a page cap enforced by the callers.
- **Never logs a credential.** Headers are not logged; errors carry the status and the path only.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from core.netsafety import Resolver, default_resolver, is_public_ip

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
USER_AGENT = "bulwark-connector"


class ConnectorError(RuntimeError):
    """A run that cannot complete. `auth` marks a credential the server refused (401/403), which
    health shows differently from an outage."""

    def __init__(self, message: str, *, auth: bool = False, status: int | None = None) -> None:
        super().__init__(message)
        self.auth = auth
        self.status = status


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: Any


Transport = Callable[[str, str, dict[str, str], bytes | None], Response]


def allow_private() -> bool:
    return os.environ.get("BULWARK_CONNECTOR_ALLOW_PRIVATE", "").strip().lower() in ("1", "true")


def check_url(
    url: str, resolver: Resolver = default_resolver, *, private_ok: bool | None = None
) -> str:
    """The URL, normalized, or ConnectorError saying why it is refused."""
    private_ok = allow_private() if private_ok is None else private_ok
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("https", "http") or (parts.scheme == "http" and not private_ok):
        raise ConnectorError("only https:// URLs are allowed")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ConnectorError("credentials in the URL are not allowed; use the credential field")
    host = (parts.hostname or "").lower()
    if not host:
        raise ConnectorError("the URL has no host")
    if private_ok:
        return url.strip().rstrip("/")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            addresses = resolver(host)
        except OSError as exc:
            raise ConnectorError(f"could not resolve {host}") from exc
    if not addresses:
        raise ConnectorError(f"{host} did not resolve")
    if any(not is_public_ip(a) for a in addresses):
        raise ConnectorError(
            f"{host} resolves to a private or internal address; set "
            "BULWARK_CONNECTOR_ALLOW_PRIVATE=1 if this instance really is on your private network"
        )
    return url.strip().rstrip("/")


def http_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Response:
    check_url(url)  # every request, not only on save: DNS can change
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
            with client.stream(method, url, headers=headers, content=body) as r:
                chunks = []
                size = 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ConnectorError(f"the response from {urlsplit(url).path} is too large")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                hdrs = {k.lower(): v for k, v in r.headers.items()}
    except httpx.HTTPError as exc:
        raise ConnectorError(
            f"could not reach {urlsplit(url).hostname} ({type(exc).__name__})"
        ) from exc
    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode("utf-8", errors="replace")[:500]
    return Response(r.status_code, hdrs, parsed)


def expect_ok(resp: Response, what: str) -> Any:
    """The body of a 2xx, or the right ConnectorError."""
    if resp.status in (401, 403):
        raise ConnectorError(
            f"{what}: the credential was refused (HTTP {resp.status})",
            auth=True,
            status=resp.status,
        )
    if resp.status == 404:
        raise ConnectorError(
            f"{what}: not found (HTTP 404) -- check the name and the credential's " "access",
            status=404,
        )
    if resp.status in (301, 302, 303, 307, 308):
        raise ConnectorError(
            f"{what}: the server redirected (HTTP {resp.status}); use the final URL",
            status=resp.status,
        )
    if not 200 <= resp.status < 300:
        reason = _reason(resp.body) if 400 <= resp.status < 500 else ""
        raise ConnectorError(
            f"{what}: HTTP {resp.status}" + (f" -- {reason}" if reason else ""), status=resp.status
        )
    return resp.body


def _reason(body: Any) -> str:
    """What a refused request's body says (DefectDojo: `["Product ... does not exist ..."]` or
    `{"field": ["..."]}`), as one short line of text."""
    if isinstance(body, (dict, list)):
        body = json.dumps(body, ensure_ascii=False)
    text = " ".join(str(body or "").split())
    return text[:300] + ("..." if len(text) > 300 else "")


def next_link(headers: dict[str, str]) -> str | None:
    """The `rel="next"` URL of an RFC 8288 Link header (GitHub's pagination), if any."""
    for part in headers.get("link", "").split(","):
        section = part.strip().split(";")
        if len(section) >= 2 and any(s.strip() == 'rel="next"' for s in section[1:]):
            return section[0].strip().lstrip("<").rstrip(">")
    return None
