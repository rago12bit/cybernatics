"""The SSRF guard for outbound webhook destinations (Week 51 task 2, plan §23: "webhook destinations
pass the same SSRF guard as Git ingestion"). Shares `core.netsafety`'s DNS-resolve-and-check-every-
address logic with `core.gitfetch.validate_git_url` directly -- the same function, not a lookalike
reimplementation that could drift out of sync with it.

Deliberately NOT `core.gitfetch.validate_git_url` itself: that function also enforces a 3-host
allowlist (`github.com`/`gitlab.com`/`bitbucket.org`) and a git-owner/repo-shaped URL path, both
specific to cloning a repository. A webhook destination is an arbitrary operator-configured HTTPS
endpoint (Slack, Discord, Jira, or a custom receiver) with no such shape -- what it shares with git
ingestion is exactly the part that matters for SSRF: resolve the host, and refuse to send anything
to one that resolves to a private, loopback, link-local, or cloud-metadata address.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from core.netsafety import Resolver, default_resolver, is_public_ip


class WebhookUrlError(ValueError):
    """A webhook destination rejected by validation (bad scheme/credentials or unsafe address)."""


@dataclass(frozen=True)
class ValidatedWebhookUrl:
    url: str
    host: str
    ip: str


def validate_webhook_url(url: str, resolver: Resolver = default_resolver) -> ValidatedWebhookUrl:
    """https only (confidentiality for the HMAC secret and the payload in transit, not only
    authenticity of the destination), no embedded credentials, and every resolved address must be
    globally routable -- the same three checks `core.gitfetch.validate_git_url` applies, minus its
    git-specific host allowlist and path grammar. No restriction on query strings or non-standard
    ports: unlike a git clone URL, a webhook destination routinely carries both (a path-embedded
    token for Slack/Discord, a non-443 port for a self-hosted receiver behind a reverse proxy)."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise WebhookUrlError("only https:// URLs are allowed")
    if parts.username or parts.password or "@" in parts.netloc:
        raise WebhookUrlError("credentials in URL are not allowed")
    host = (parts.hostname or "").lower()
    if not host:
        raise WebhookUrlError("URL has no host")
    try:
        ips = resolver(host)
    except OSError as exc:
        raise WebhookUrlError(f"could not resolve {host}: {exc}") from exc
    if not ips:
        raise WebhookUrlError(f"{host} did not resolve")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise WebhookUrlError(f"{host} resolves to non-public address(es): {bad}")
    return ValidatedWebhookUrl(url=url.strip(), host=host, ip=ips[0])
