"""Proving someone registering a web target actually controls it (plan §22.4).

Two standard methods, the same ones every CDN/TLS-cert issuer/search-console uses for the same
reason: a DNS TXT record at a fixed subdomain, or a fixed well-known file served over HTTPS. Either
proves control of the domain (DNS) or the web server answering for it (HTTP) -- not both at once,
the asset owner picks one when registering.

This module is pure check logic with injectable resolver/fetcher (`DnsResolver`/`HttpFetcher`
protocols) so it's unit-testable without real network access, plus one real implementation of each
(`DnsPythonResolver`, `HttpxFetcher`) for actual use. `core.persistence.repo` and the DAST campaign
path call `verify()` with the real implementations; tests call it with fakes.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from core.netsafety import Resolver, default_resolver, is_public_ip

WELL_KNOWN_PATH = "/.well-known/bulwark-verification.txt"
DNS_TXT_LABEL = "_bulwark-challenge"

METHODS = frozenset({"dns_txt", "well_known"})

#: A DNS name: dot-separated labels, the last one not a number -- so not an IP address, and
#: nothing with a port, a path, a query or credentials in it.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
NOT_A_DOMAIN = "a web target is a domain name, like example.com: not an address, a port or a path"

#: The verification file holds a 32-character token; anything much larger is not one.
MAX_BODY_BYTES = 4096
MAX_REDIRECTS = 5


def is_hostname(value: str) -> bool:
    return bool(_HOSTNAME.match(value or ""))


def generate_token() -> str:
    return secrets.token_hex(16)


def dns_record_name(domain: str) -> str:
    return f"{DNS_TXT_LABEL}.{domain}"


def dns_expected_value(token: str) -> str:
    return f"bulwark-site-verification={token}"


def well_known_url(domain: str) -> str:
    return f"https://{domain}{WELL_KNOWN_PATH}"


@dataclass(frozen=True)
class VerificationOutcome:
    ok: bool
    error: str | None = None


class DnsResolver(Protocol):
    def resolve_txt(self, name: str) -> list[str]: ...  # pragma: no cover - protocol


class HttpFetcher(Protocol):
    def get_text(self, url: str) -> str: ...  # pragma: no cover - protocol


class DnsPythonResolver:
    """Real DNS lookups via dnspython. A short, fixed timeout: verification runs synchronously on
    an API request, and again synchronously before every campaign starts (plan §22.4's "re-checked
    before every campaign", not just trusted from a past check) -- a slow or black-holed resolver
    must fail fast, not hang the request."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def resolve_txt(self, name: str) -> list[str]:
        import dns.resolver  # imported lazily: only the DAST path needs this dependency

        answer = dns.resolver.resolve(name, "TXT", lifetime=self._timeout)
        values: list[str] = []
        for rdata in answer:
            # dnspython splits a long TXT value into multiple quoted byte-strings per record;
            # rejoin them before comparing against the single expected string.
            values.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
        return values


class FetchRefused(ValueError):
    """The well-known file was not fetched, or not read to the end: said in words a person
    registering a target can act on."""


class HttpxFetcher:
    """Real HTTPS fetches via httpx. TLS verification is never disabled: a target behind a cert
    Bulwark doesn't trust failing verification is not a false negative to work around, it's exactly
    the kind of thing ownership verification exists to catch.

    The address is given by whoever registers the target, so the fetch is guarded the way every
    other outbound request to a person-supplied address is (threat T5; `core.connectors.http`):

    - **https, to public addresses only**, checked for the first request and for every redirect.
      Redirects are followed (a site commonly sends `example.com` to `www.example.com`), but by
      hand, at most `MAX_REDIRECTS`: left to the HTTP client, a public host could answer with
      `Location: http://169.254.169.254/...` and have the server fetch its own network.
    - **A small answer, soon.** At most `MAX_BODY_BYTES` are read, and the whole check has one
      deadline: httpx's timeout is per read, so a server sending a byte every few seconds would
      otherwise hold the request (and the memory for whatever it sent) for as long as it liked.

    The host is resolved here and again by the HTTP client; a name that changes between the two is
    not caught (the same limit `core.connectors.http` states)."""

    def __init__(
        self,
        timeout: float = 10.0,
        *,
        total_timeout: float = 20.0,
        resolver: Resolver = default_resolver,
        transport: Any = None,
    ) -> None:
        self._timeout = timeout
        self._total = total_timeout
        self._resolver = resolver
        self._transport = transport  # an httpx transport, for tests

    def _allowed(self, url: str) -> str:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not host:
            raise FetchRefused(f"only https:// addresses are fetched, not {url[:200]!r}")
        if parts.username or parts.password:
            raise FetchRefused("an address with credentials in it is not fetched")
        try:
            addresses = self._resolver(host)
        except OSError as exc:
            raise FetchRefused(f"could not resolve {host}") from exc
        if not addresses or any(not is_public_ip(a) for a in addresses):
            raise FetchRefused(f"{host} is not a public address")
        return url

    def get_text(self, url: str) -> str:
        import httpx

        deadline = time.monotonic() + self._total
        with httpx.Client(
            timeout=self._timeout, follow_redirects=False, transport=self._transport
        ) as client:
            for _ in range(MAX_REDIRECTS + 1):
                if time.monotonic() > deadline:
                    raise FetchRefused(f"{url} took too long to answer")
                with client.stream("GET", self._allowed(url)) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location")
                        if not location:
                            raise FetchRefused(f"{url} redirected to nowhere")
                        url = urljoin(url, location)
                        continue
                    resp.raise_for_status()
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body += chunk
                        if len(body) > MAX_BODY_BYTES:
                            raise FetchRefused(
                                f"{url} is larger than a verification file "
                                f"({MAX_BODY_BYTES} bytes at most)"
                            )
                        if time.monotonic() > deadline:
                            raise FetchRefused(f"{url} took too long to answer")
                    return body.decode("utf-8", errors="replace")
        raise FetchRefused(f"more than {MAX_REDIRECTS} redirects")


def check_dns_txt(domain: str, token: str, *, resolver: DnsResolver) -> VerificationOutcome:
    name = dns_record_name(domain)
    expected = dns_expected_value(token)
    try:
        values = resolver.resolve_txt(name)
    except Exception as exc:
        # dnspython raises distinct types for NXDOMAIN/NoAnswer/Timeout/etc -- all of them mean
        # "not verified yet," identically, from this function's point of view.
        return VerificationOutcome(ok=False, error=f"DNS lookup for {name} failed: {exc}")
    if expected not in values:
        return VerificationOutcome(
            ok=False,
            error=f"no TXT record at {name} matched the expected value "
            f"(found {len(values)} record(s))",
        )
    return VerificationOutcome(ok=True)


def check_well_known(domain: str, token: str, *, fetcher: HttpFetcher) -> VerificationOutcome:
    url = well_known_url(domain)
    try:
        body = fetcher.get_text(url)
    except Exception as exc:
        return VerificationOutcome(ok=False, error=f"fetching {url} failed: {exc}")
    if body.strip() != token:
        return VerificationOutcome(ok=False, error=f"{url} did not contain the expected token")
    return VerificationOutcome(ok=True)


def verify(
    method: str, domain: str, token: str, *, resolver: DnsResolver, fetcher: HttpFetcher
) -> VerificationOutcome:
    if method not in METHODS:
        raise ValueError(f"unknown verification method: {method!r}; valid: {sorted(METHODS)}")
    if not is_hostname(domain):  # a target registered before names were checked
        return VerificationOutcome(ok=False, error=NOT_A_DOMAIN)
    if method == "dns_txt":
        return check_dns_txt(domain, token, resolver=resolver)
    if method == "well_known":
        return check_well_known(domain, token, fetcher=fetcher)
    raise ValueError(f"unknown verification method: {method!r}; valid: {sorted(METHODS)}")
