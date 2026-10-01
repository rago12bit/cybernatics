"""core.integrations.webhooks: HMAC signing/verification (pure, real crypto, no mocks needed) and
delivery (mocked transport -- the real wire-level delivery is proven against a real local HTTP
server in tests/integration/test_integrations_webhooks_live.py)."""

from __future__ import annotations

from typing import Any

import pytest

from core.ci.github import Transport
from core.integrations.webhooks import (
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    WebhookDeliveryError,
    deliver_plain,
    deliver_signed,
    sign,
    verify_signature,
)

PUBLIC = lambda host: ["140.82.112.3"]  # noqa: E731


def test_sign_is_deterministic_for_the_same_inputs() -> None:
    assert sign("secret", 1000, b"body") == sign("secret", 1000, b"body")


def test_sign_changes_with_secret_timestamp_or_body() -> None:
    base = sign("secret", 1000, b"body")
    assert sign("other", 1000, b"body") != base
    assert sign("secret", 1001, b"body") != base
    assert sign("secret", 1000, b"other") != base


def test_verify_signature_accepts_a_correct_fresh_signature() -> None:
    sig = sign("secret", 1000, b"body")
    assert verify_signature("secret", 1000, b"body", sig, now=1000) is True


def test_verify_signature_rejects_a_replayed_old_timestamp() -> None:
    """Replay prevention: the signature itself is still mathematically correct, but too much wall-
    clock time has passed since it was issued."""
    sig = sign("secret", 1000, b"body")
    assert verify_signature("secret", 1000, b"body", sig, now=1000 + 301) is False


def test_verify_signature_rejects_a_timestamp_from_the_future_too() -> None:
    sig = sign("secret", 1000, b"body")
    assert verify_signature("secret", 1000, b"body", sig, now=1000 - 301) is False


def test_verify_signature_rejects_a_tampered_body() -> None:
    sig = sign("secret", 1000, b"body")
    assert verify_signature("secret", 1000, b"tampered", sig, now=1000) is False


def test_verify_signature_rejects_the_wrong_secret() -> None:
    sig = sign("secret", 1000, b"body")
    assert verify_signature("wrong", 1000, b"body", sig, now=1000) is False


def _fake_transport(status: int, captured: dict[str, Any]) -> Transport:
    def run(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, Any]:
        captured.update(method=method, url=url, headers=headers, body=body)
        return status, None

    return run


def test_deliver_signed_sends_the_correct_headers_and_a_sorted_json_body() -> None:
    captured: dict[str, Any] = {}
    deliver_signed(
        "https://receiver.example.com/hook", {"b": 1, "a": 2}, "topsecret",
        resolver=PUBLIC, transport=_fake_transport(200, captured), now=1000,
    )  # fmt: skip
    assert captured["method"] == "POST"
    assert captured["url"] == "https://receiver.example.com/hook"
    assert captured["headers"][HEADER_TIMESTAMP] == "1000"
    assert captured["headers"][HEADER_SIGNATURE] == sign("topsecret", 1000, captured["body"])
    assert captured["body"] == b'{"a": 2, "b": 1}'  # sorted keys


def test_deliver_plain_sends_no_signature_headers() -> None:
    captured: dict[str, Any] = {}
    deliver_plain(
        "https://hooks.example.com/x", {"text": "hi"}, resolver=PUBLIC,
        transport=_fake_transport(200, captured),
    )  # fmt: skip
    assert HEADER_SIGNATURE not in captured["headers"]
    assert HEADER_TIMESTAMP not in captured["headers"]


def test_delivery_raises_on_a_non_2xx_response() -> None:
    with pytest.raises(WebhookDeliveryError, match="HTTP 500"):
        deliver_plain(
            "https://hooks.example.com/x", {}, resolver=PUBLIC,
            transport=_fake_transport(500, {}),
        )  # fmt: skip


def test_delivery_refuses_a_destination_that_fails_ssrf_validation_before_ever_calling_transport() -> (
    None
):
    calls: list[Any] = []

    def spy_transport(method: str, url: str, headers: dict[str, str], body: bytes | None):  # type: ignore[no-untyped-def]
        calls.append(url)
        return 200, None

    with pytest.raises(Exception, match="non-public"):
        deliver_plain(
            "https://evil.example.com/x", {}, resolver=lambda h: ["127.0.0.1"],
            transport=spy_transport,
        )  # fmt: skip
    assert calls == []  # never reached the transport at all
