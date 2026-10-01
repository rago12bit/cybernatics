"""Slack/Discord payload shape (core.integrations.slack/discord) and delivery (both are thin
wrappers over core.integrations.webhooks.deliver_plain -- proven generically in
tests/unit/test_integrations_webhooks.py; this file only checks the message formatting and that
each module really does call the unsigned path, not the HMAC-signed one)."""

from __future__ import annotations

from typing import Any

import pytest

from core.ci.github import Transport
from core.integrations import discord, slack

PUBLIC = lambda host: ["140.82.112.3"]  # noqa: E731


def _fake_transport(captured: dict[str, Any]) -> Transport:
    def run(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, Any]:
        captured.update(method=method, url=url, headers=headers, body=body)
        return 200, None

    return run


def test_slack_payload_with_no_changes_reports_a_clean_scan() -> None:
    p = slack.scan_summary_payload(
        asset_label="acme/app", scan_id="s1", new_count=0, reintroduced_count=0, fixed_count=0
    )
    assert "no new issues" in p["text"]


def test_slack_payload_summarizes_new_reintroduced_and_fixed() -> None:
    p = slack.scan_summary_payload(
        asset_label="acme/app", scan_id="s1", new_count=2, reintroduced_count=1, fixed_count=3
    )
    assert "2 new" in p["text"] and "1 reintroduced" in p["text"] and "3 fixed" in p["text"]
    assert "s1" in p["text"]


def test_slack_send_never_signs_the_request() -> None:
    from core.integrations.webhooks import HEADER_SIGNATURE

    captured: dict[str, Any] = {}
    slack.send(
        "https://hooks.example.com/x", {"text": "hi"}, resolver=PUBLIC,
        transport=_fake_transport(captured),
    )  # fmt: skip
    assert HEADER_SIGNATURE not in captured["headers"]


def test_discord_payload_truncates_to_2000_characters() -> None:
    p = discord.scan_summary_payload(
        asset_label="x" * 3000, scan_id="s1", new_count=1, reintroduced_count=0, fixed_count=0
    )
    assert len(p["content"]) <= 2000


def test_discord_payload_with_no_changes_reports_a_clean_scan() -> None:
    p = discord.scan_summary_payload(
        asset_label="acme/app", scan_id="s1", new_count=0, reintroduced_count=0, fixed_count=0
    )
    assert "no new issues" in p["content"]


def test_discord_send_never_signs_the_request() -> None:
    from core.integrations.webhooks import HEADER_SIGNATURE

    captured: dict[str, Any] = {}
    discord.send(
        "https://discord.com/api/webhooks/x", {"content": "hi"}, resolver=PUBLIC,
        transport=_fake_transport(captured),
    )  # fmt: skip
    assert HEADER_SIGNATURE not in captured["headers"]


@pytest.mark.parametrize("module", [slack, discord])
def test_send_refuses_an_unsafe_destination(module: Any) -> None:
    from core.integrations.ssrf import WebhookUrlError

    with pytest.raises(WebhookUrlError):
        module.send("https://evil.example.com/x", {}, resolver=lambda h: ["127.0.0.1"])
