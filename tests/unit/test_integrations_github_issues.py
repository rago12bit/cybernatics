"""core.integrations.github_issues against a mocked Transport -- the same injectable-callable
testing convention core/ci/github.py's own test file already uses for upsert_comment. Live-testing
this against the real GitHub REST API would create a real, visible issue on a real repository, which
needs the repository owner's own token and explicit opt-in; not done here. See this module's own
docstring and docs/v2-week51-verification.md for what remains unverified against the real API."""

from __future__ import annotations

import json
from typing import Any

import pytest

from core.integrations.github_issues import (
    GithubIssueError,
    add_comment,
    create_issue,
    set_issue_state,
)

TOKEN = "ghp_faketoken"


def _transport(status: int, body: dict[str, Any] | None):  # type: ignore[no-untyped-def]
    calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def run(method: str, url: str, headers: dict[str, str], data: bytes | None):  # type: ignore[no-untyped-def]
        calls.append((method, url, headers, data))
        return status, body

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_create_issue_posts_to_the_repos_issues_endpoint_with_a_bearer_token() -> None:
    t = _transport(201, {"number": 42, "html_url": "https://github.com/acme/app/issues/42"})
    created = create_issue("acme/app", "SQL injection in login", "body text", TOKEN, transport=t)
    assert created.number == 42
    assert created.url == "https://github.com/acme/app/issues/42"
    method, url, headers, data = t.calls[0]  # type: ignore[attr-defined]
    assert method == "POST" and url == "https://api.github.com/repos/acme/app/issues"
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(data)["title"] == "SQL injection in login"  # type: ignore[arg-type]


def test_create_issue_includes_labels_when_given() -> None:
    t = _transport(201, {"number": 1, "html_url": "https://x"})
    create_issue("acme/app", "t", "b", TOKEN, labels=("security", "bulwark"), transport=t)
    _, _, _, data = t.calls[0]  # type: ignore[attr-defined]
    assert json.loads(data)["labels"] == ["security", "bulwark"]  # type: ignore[arg-type]


def test_create_issue_rejects_an_invalid_repo_name_before_any_network_call() -> None:
    t = _transport(201, {"number": 1, "html_url": "https://x"})
    with pytest.raises(GithubIssueError, match="invalid repository"):
        create_issue("not-a-valid-repo", "t", "b", TOKEN, transport=t)
    assert t.calls == []  # type: ignore[attr-defined]


def test_create_issue_raises_on_a_non_201_response() -> None:
    t = _transport(403, None)
    with pytest.raises(GithubIssueError, match="HTTP 403"):
        create_issue("acme/app", "t", "b", TOKEN, transport=t)


def test_set_issue_state_patches_with_the_requested_state() -> None:
    t = _transport(200, {})
    set_issue_state("acme/app", 42, "closed", TOKEN, transport=t)
    method, url, _, data = t.calls[0]  # type: ignore[attr-defined]
    assert method == "PATCH" and url.endswith("/repos/acme/app/issues/42")
    assert json.loads(data)["state"] == "closed"  # type: ignore[arg-type]


def test_set_issue_state_raises_on_failure() -> None:
    t = _transport(404, None)
    with pytest.raises(GithubIssueError, match="HTTP 404"):
        set_issue_state("acme/app", 42, "open", TOKEN, transport=t)


def test_add_comment_posts_the_body() -> None:
    t = _transport(201, {})
    add_comment("acme/app", 42, "fixed by scan s1", TOKEN, transport=t)
    _, url, _, data = t.calls[0]  # type: ignore[attr-defined]
    assert url.endswith("/repos/acme/app/issues/42/comments")
    assert json.loads(data)["body"] == "fixed by scan s1"  # type: ignore[arg-type]
