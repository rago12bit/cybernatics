"""core.integrations.jira against a mocked Transport. Live-testing this against a real Jira Cloud
instance needs a real account/API token/project and explicit opt-in; not done here -- see this
module's own docstring and docs/v2-week51-verification.md."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from core.integrations.jira import JiraError, add_comment, create_ticket

EMAIL, TOKEN, BASE = "ops@acme.com", "fake-api-token", "https://acme.atlassian.net"


def _transport(status: int, body: dict[str, Any] | None):  # type: ignore[no-untyped-def]
    calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def run(method: str, url: str, headers: dict[str, str], data: bytes | None):  # type: ignore[no-untyped-def]
        calls.append((method, url, headers, data))
        return status, body

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_create_ticket_posts_basic_auth_and_adf_description() -> None:
    t = _transport(201, {"key": "SEC-42", "id": "10042"})
    created = create_ticket(
        BASE, EMAIL, TOKEN, "SEC", "SQL injection", "found in login.py", transport=t
    )
    assert created.key == "SEC-42"
    assert created.url == f"{BASE}/browse/SEC-42"
    method, url, headers, data = t.calls[0]  # type: ignore[attr-defined]
    assert method == "POST" and url == f"{BASE}/rest/api/3/issue"
    expected_auth = "Basic " + base64.b64encode(f"{EMAIL}:{TOKEN}".encode()).decode()
    assert headers["Authorization"] == expected_auth
    body = json.loads(data)  # type: ignore[arg-type]
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["summary"] == "SQL injection"
    assert body["fields"]["issuetype"]["name"] == "Bug"


def test_create_ticket_accepts_a_custom_issue_type() -> None:
    t = _transport(201, {"key": "SEC-1"})
    create_ticket(BASE, EMAIL, TOKEN, "SEC", "s", "d", issue_type="Vulnerability", transport=t)
    body = json.loads(t.calls[0][3])  # type: ignore[attr-defined,arg-type]
    assert body["fields"]["issuetype"]["name"] == "Vulnerability"


def test_create_ticket_raises_on_failure() -> None:
    t = _transport(400, {"errors": {"project": "project is required"}})
    with pytest.raises(JiraError, match="HTTP 400"):
        create_ticket(BASE, EMAIL, TOKEN, "SEC", "s", "d", transport=t)


def test_create_ticket_raises_when_the_response_has_no_key() -> None:
    t = _transport(201, {"id": "10042"})
    with pytest.raises(JiraError):
        create_ticket(BASE, EMAIL, TOKEN, "SEC", "s", "d", transport=t)


def test_add_comment_posts_adf_body() -> None:
    t = _transport(201, {})
    add_comment(BASE, EMAIL, TOKEN, "SEC-42", "marked fixed by scan s1", transport=t)
    _, url, _, data = t.calls[0]  # type: ignore[attr-defined]
    assert url == f"{BASE}/rest/api/3/issue/SEC-42/comment"
    body = json.loads(data)  # type: ignore[arg-type]
    assert body["body"]["content"][0]["content"][0]["text"] == "marked fixed by scan s1"


def test_add_comment_raises_on_failure() -> None:
    t = _transport(404, None)
    with pytest.raises(JiraError, match="HTTP 404"):
        add_comment(BASE, EMAIL, TOKEN, "SEC-999", "x", transport=t)
