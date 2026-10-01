"""core.integrations.ssrf.validate_webhook_url -- the same core.netsafety primitives
core.gitfetch.validate_git_url uses, applied to an arbitrary webhook destination instead of a git
clone URL. Mirrors tests/unit/test_gitfetch.py's own `resolves_to()` fake-resolver pattern."""

from __future__ import annotations

import pytest

from core.integrations.ssrf import WebhookUrlError, validate_webhook_url


def resolves_to(*ips: str):  # type: ignore[no-untyped-def]
    return lambda host: list(ips)


PUBLIC = resolves_to("140.82.112.3")


def test_a_valid_https_url_resolving_publicly_is_accepted() -> None:
    v = validate_webhook_url("https://hooks.example.com/services/T000/B000/xxx", PUBLIC)
    assert v.host == "hooks.example.com" and v.ip == "140.82.112.3"


def test_query_strings_and_nonstandard_ports_are_allowed_unlike_git_urls() -> None:
    """Unlike validate_git_url, a webhook destination legitimately carries a path-embedded token
    (Slack/Discord) or a non-443 port (a self-hosted receiver behind a reverse proxy)."""
    v = validate_webhook_url("https://receiver.example.com:8443/hook?team=acme", PUBLIC)
    assert v.host == "receiver.example.com"


def test_plain_http_is_rejected() -> None:
    with pytest.raises(WebhookUrlError, match="https"):
        validate_webhook_url("http://hooks.example.com/x", PUBLIC)


def test_credentials_in_url_are_rejected() -> None:
    with pytest.raises(WebhookUrlError, match="credentials"):
        validate_webhook_url("https://user:pass@hooks.example.com/x", PUBLIC)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # RFC 1918
        "169.254.169.254",  # cloud metadata
        "::1",  # IPv6 loopback
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6 bypass trick
    ],
)
def test_resolving_to_a_non_public_address_is_rejected(ip: str) -> None:
    with pytest.raises(WebhookUrlError, match="non-public"):
        validate_webhook_url("https://evil.example.com/x", resolves_to(ip))


def test_a_host_that_fails_to_resolve_is_rejected() -> None:
    def boom(host: str) -> list[str]:
        raise OSError("name or service not known")

    with pytest.raises(WebhookUrlError, match="could not resolve"):
        validate_webhook_url("https://nowhere.example.com/x", boom)


def test_a_url_with_no_host_is_rejected() -> None:
    with pytest.raises(WebhookUrlError, match="no host"):
        validate_webhook_url("https:///just/a/path", PUBLIC)
