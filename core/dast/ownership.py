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

import secrets
from dataclasses import dataclass
from typing import Protocol

WELL_KNOWN_PATH = "/.well-known/bulwark-verification.txt"
DNS_TXT_LABEL = "_bulwark-challenge"

METHODS = frozenset({"dns_txt", "well_known"})


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


class HttpxFetcher:
    """Real HTTPS fetches via httpx. TLS verification is never disabled: a target behind a cert
    Bulwark doesn't trust failing verification is not a false negative to work around, it's exactly
    the kind of thing ownership verification exists to catch."""

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    def get_text(self, url: str) -> str:
        import httpx

        resp = httpx.get(url, timeout=self._timeout, follow_redirects=True)
        resp.raise_for_status()
        return resp.text


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
    if method == "dns_txt":
        return check_dns_txt(domain, token, resolver=resolver)
    if method == "well_known":
        return check_well_known(domain, token, fetcher=fetcher)
    raise ValueError(f"unknown verification method: {method!r}; valid: {sorted(METHODS)}")
