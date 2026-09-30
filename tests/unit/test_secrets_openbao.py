"""core.secrets.openbao's request shaping and error handling (Week 47 task 1, plan §22.2).

Mocks urllib.request.urlopen, not OpenBao itself -- every method here, including the exact error
shapes asserted against, was exercised live against a real `openbao/openbao:2.1` dev-mode container
first; see docs/v2-week47-verification.md. Unit tests cover the logic around those calls: request
construction, idempotency checks, response parsing, error propagation."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from unittest.mock import MagicMock

import pytest

from core.secrets.openbao import (
    DataKey,
    OpenBaoClient,
    OpenBaoError,
    decode_wrapped_key,
    encode_wrapped_key,
)


def _response(body: dict[str, Any]) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def test_ensure_transit_engine_enabled_mounts_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        calls.append((req.get_method(), req.full_url))
        if req.get_method() == "GET":
            return _response({"data": {"secret/": {}}})  # transit/ not present
        return _response({})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    OpenBaoClient(addr="http://openbao:8200", token="t").ensure_transit_engine_enabled()
    methods = [m for m, _ in calls]
    assert methods == ["GET", "POST"]


def test_ensure_transit_engine_enabled_skips_when_already_mounted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        calls.append(req.get_method())
        return _response({"data": {"transit/": {}}})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    OpenBaoClient(addr="http://openbao:8200", token="t").ensure_transit_engine_enabled()
    assert calls == ["GET"]  # no POST -- would be a real error against a real instance


def test_ensure_org_key_posts_to_the_named_key_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        seen["url"] = req.full_url
        seen["method"] = req.get_method()
        seen["token"] = req.get_header("X-vault-token")
        return _response({})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    OpenBaoClient(addr="http://openbao:8200", token="s3cr3t").ensure_org_key("org-1")
    assert seen["url"] == "http://openbao:8200/v1/transit/keys/org-org-1"
    assert seen["method"] == "POST"
    assert seen["token"] == "s3cr3t"


def test_generate_data_key_parses_plaintext_and_wrapped_forms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from base64 import b64encode

    plaintext = b"\x01" * 32

    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        return _response(
            {
                "data": {
                    "plaintext": b64encode(plaintext).decode(),
                    "ciphertext": "vault:v1:abcdef",
                }
            }
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    dk = OpenBaoClient(addr="http://openbao:8200", token="t").generate_data_key("org-1")
    assert dk == DataKey(plaintext=plaintext, wrapped="vault:v1:abcdef")


def test_unwrap_data_key_sends_the_ciphertext_and_returns_plaintext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from base64 import b64encode

    plaintext = b"\x02" * 32
    sent_body = {}

    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        sent_body.update(json.loads(req.data))
        return _response({"data": {"plaintext": b64encode(plaintext).decode()}})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = OpenBaoClient(addr="http://openbao:8200", token="t").unwrap_data_key(
        "org-1", "vault:v1:abcdef"
    )
    assert result == plaintext
    assert sent_body == {"ciphertext": "vault:v1:abcdef"}


def test_http_error_is_wrapped_with_status_and_body(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        raise urllib.error.HTTPError(
            req.full_url, 400, "Bad Request", {}, MagicMock(read=lambda: b'{"errors":["bad"]}')
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(OpenBaoError, match="HTTP 400"):
        OpenBaoClient(addr="http://openbao:8200", token="t").ensure_org_key("org-1")


def test_connection_failure_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(req: urllib.request.Request, timeout: float) -> MagicMock:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(OpenBaoError, match="could not reach OpenBao"):
        OpenBaoClient(addr="http://openbao:8200", token="t").ensure_org_key("org-1")


def test_wrapped_key_encode_decode_roundtrip() -> None:
    assert decode_wrapped_key(encode_wrapped_key("vault:v1:abcdef")) == "vault:v1:abcdef"
