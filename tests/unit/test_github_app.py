from __future__ import annotations

import hmac
import time
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.github_app import (
    GithubAppError,
    app_jwt,
    installation_token,
    parse_pull_request_event,
    pr_comment_body,
    verify_signature,
)


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    """A real (test-only) RSA keypair: RS256 needs actual asymmetric crypto, not a fake."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


class FakeTransport:
    def __init__(self, status: int, body: Any) -> None:
        self.status, self.body, self.calls = status, body, []

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        self.calls.append((method, url, headers, body))
        return self.status, self.body


def test_app_jwt_is_signed_rs256_and_verifiable_with_the_public_key(
    keypair: tuple[str, str],
) -> None:
    private_pem, public_pem = keypair
    now = time.time()
    token = app_jwt("12345", private_pem, now=now)
    decoded = pyjwt.decode(token, public_pem, algorithms=["RS256"], issuer="12345")
    assert decoded["iss"] == "12345"
    assert decoded["exp"] - decoded["iat"] == 10 * 60  # 9 min validity + 60s clock-skew margin
    assert decoded["iat"] == int(now) - 60


def test_installation_token_is_cached_until_near_expiry(keypair: tuple[str, str]) -> None:
    private_pem, _ = keypair
    expires_at = datetime.now(timezone.utc).timestamp() + 3600
    expires_iso = (
        datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    )
    start = expires_at - 3600  # "now" when the first token is minted

    t = FakeTransport(201, {"token": "tok-1", "expires_at": expires_iso})
    first = installation_token("999", "app-1", private_pem, transport=t, now=start)
    second = installation_token("999", "app-1", private_pem, transport=t, now=start + 60)
    assert first == second == "tok-1"
    assert len(t.calls) == 1  # second call was served from cache, not a new HTTP request

    # Past expiry minus the refresh margin: a fresh token is minted, not the stale cached one.
    t2 = FakeTransport(201, {"token": "tok-2", "expires_at": expires_iso})
    later = installation_token("999", "app-1", private_pem, transport=t2, now=expires_at + 1)
    assert later == "tok-2" and len(t2.calls) == 1


def test_installation_token_raises_on_a_non_201_response(keypair: tuple[str, str]) -> None:
    private_pem, _ = keypair
    with pytest.raises(GithubAppError):
        installation_token(
            "unique-fail-1", "app-1", private_pem, transport=FakeTransport(401, {"message": "bad"})
        )


def test_installation_token_request_shape(keypair: tuple[str, str]) -> None:
    private_pem, _ = keypair
    t = FakeTransport(201, {"token": "tok", "expires_at": "2026-01-01T00:00:00Z"})
    installation_token("shape-check", "app-1", private_pem, transport=t, now=1.0)
    method, url, headers, body = t.calls[0]
    assert method == "POST"
    assert url == "https://api.github.com/app/installations/shape-check/access_tokens"
    assert headers["Authorization"].startswith("Bearer ")
    assert body is None


def test_verify_signature_matches_githubs_hmac_sha256_scheme() -> None:
    secret = "s3cret"
    payload = b'{"action":"opened"}'
    sig = "sha256=" + hmac.new(secret.encode(), payload, "sha256").hexdigest()
    assert verify_signature(payload, sig, secret) is True
    assert verify_signature(payload, sig, "wrong-secret") is False
    assert verify_signature(payload, "sha256=deadbeef", secret) is False
    assert verify_signature(payload, None, secret) is False
    assert verify_signature(payload, "not-even-prefixed", secret) is False


def _pr_payload(action: str = "opened", **overrides: Any) -> dict[str, Any]:
    payload = {
        "action": action,
        "installation": {"id": 42},
        "repository": {
            "owner": {"login": "acme"},
            "full_name": "acme/widgets",
            "clone_url": "https://github.com/acme/widgets.git",
        },
        "pull_request": {"number": 7},
    }
    payload.update(overrides)
    return payload


def test_parse_pull_request_event_extracts_what_a_scan_needs() -> None:
    ev = parse_pull_request_event(_pr_payload())
    assert ev is not None
    assert ev.installation_id == "42"
    assert ev.account_login == "acme"
    assert ev.repo_full_name == "acme/widgets"
    assert ev.clone_url == "https://github.com/acme/widgets.git"
    assert ev.pr_number == 7
    assert ev.ref == "refs/pull/7/head"


@pytest.mark.parametrize("action", ["closed", "labeled", "assigned", "edited"])
def test_parse_pull_request_event_ignores_actions_we_dont_scan_for(action: str) -> None:
    assert parse_pull_request_event(_pr_payload(action=action)) is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"action": "opened"},
        {"action": "opened", "installation": {}},
        {"action": "opened", "installation": {"id": 1}, "repository": {}},
        {"action": "opened", "installation": {"id": 1}, "repository": {"owner": {}}},
    ],
)
def test_parse_pull_request_event_is_never_a_crash_on_a_short_payload(
    payload: dict[str, Any],
) -> None:
    assert parse_pull_request_event(payload) is None


def test_pr_comment_reports_a_non_completed_status_without_a_finding_table() -> None:
    body = pr_comment_body(status="partial", severity_counts={}, findings=[], scan_id="s1")
    assert "did not complete" in body
    assert "|" not in body  # no table for an incomplete scan


def test_pr_comment_says_no_findings_when_clean() -> None:
    body = pr_comment_body(status="completed", severity_counts={}, findings=[], scan_id="s1")
    assert "No findings." in body


def test_pr_comment_lists_findings_and_escapes_untrusted_text() -> None:
    findings = [
        {
            "scoring": {"normalized_severity": "HIGH"},
            "title": "SQLi via `|pipe|` and *markdown*",
            "location": {"path": "a.py", "start_line": 3},
        },
        {
            "scoring": {"normalized_severity": "LOW"},
            "title": "minor",
            "location": {"path": "b.py", "start_line": 1},
        },
    ]
    body = pr_comment_body(
        status="completed",
        severity_counts={"HIGH": 1, "LOW": 1},
        findings=findings,
        scan_id="deadbeef",
    )
    assert "2 finding(s)" in body and "1 high" in body and "1 low" in body
    assert "|pipe|" not in body  # markdown-escaped, not rendered as a table cell separator
    assert "deadbeef" in body


def test_pr_comment_caps_the_listed_findings() -> None:
    findings = [
        {"scoring": {"normalized_severity": "LOW"}, "title": f"f{i}", "location": {"path": "a.py", "start_line": i}}
        for i in range(25)
    ]  # fmt: skip
    body = pr_comment_body(
        status="completed", severity_counts={"LOW": 25}, findings=findings, scan_id="s1"
    )
    assert "and 5 more" in body
