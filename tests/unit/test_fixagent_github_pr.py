"""create_pull_request (plan §21.2) against a fake Transport, mirroring
`core.ci.github.upsert_comment`'s own test style -- no live GitHub App installation exists in this
environment to validate against (see docs/v2-week42-verification.md's honest disclosure of that
gap); every request shape below was checked against GitHub's documented REST v3 contract instead.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from core.fixagent.github_pr import PullRequestError, create_pull_request


class SequencedTransport:
    """Each call consumes the next canned (status, body); records every request for inspection."""

    def __init__(self, responses: list[tuple[int, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        self.calls.append((method, url, headers, body))
        return self.responses.pop(0)


HAPPY_PATH = [
    (200, {"default_branch": "main"}),
    (200, {"object": {"sha": "base-sha-123"}}),
    (201, {}),  # create ref
    (200, {"sha": "file-sha-abc"}),  # get file (for its sha)
    (200, {}),  # put contents
    (201, {"html_url": "https://github.com/acme/widgets/pull/42", "number": 42}),
]


def test_create_pull_request_happy_path_makes_the_documented_sequence_of_calls() -> None:
    t = SequencedTransport(HAPPY_PATH)
    result = create_pull_request(
        "acme/widgets", "bulwark/fix-1", "app/users.py", "new content",
        title="Bulwark: fix SQL injection", body="explanation", token="tok-1", transport=t,
    )  # fmt: skip
    assert result.html_url == "https://github.com/acme/widgets/pull/42"
    assert result.number == 42 and result.branch == "bulwark/fix-1"
    methods_and_paths = [(m, u.split("api.github.com")[1]) for m, u, _, _ in t.calls]
    assert methods_and_paths == [
        ("GET", "/repos/acme/widgets"),
        ("GET", "/repos/acme/widgets/git/ref/heads/main"),
        ("POST", "/repos/acme/widgets/git/refs"),
        ("GET", "/repos/acme/widgets/contents/app/users.py?ref=bulwark/fix-1"),
        ("PUT", "/repos/acme/widgets/contents/app/users.py"),
        ("POST", "/repos/acme/widgets/pulls"),
    ]


def test_create_pull_request_sends_the_bearer_token_on_every_call() -> None:
    t = SequencedTransport(HAPPY_PATH)
    create_pull_request(
        "acme/widgets", "b", "f.py", "x", title="t", body="b", token="secret-tok", transport=t
    )
    assert all(h["Authorization"] == "Bearer secret-tok" for _, _, h, _ in t.calls)


def test_create_pull_request_base64_encodes_the_new_file_content() -> None:
    import base64

    t = SequencedTransport(HAPPY_PATH)
    create_pull_request(
        "acme/widgets", "b", "f.py", "print('hi')", title="t", body="b", token="x", transport=t
    )
    put_body_bytes = t.calls[4][3]
    assert put_body_bytes is not None
    put_body = json.loads(put_body_bytes)
    assert base64.b64decode(put_body["content"]).decode() == "print('hi')"
    assert put_body["sha"] == "file-sha-abc" and put_body["branch"] == "b"


@pytest.mark.parametrize(
    "fail_at_index,bad_status",
    [(0, 404), (1, 404), (2, 422), (3, 404), (4, 409), (5, 422)],
)
def test_create_pull_request_raises_with_the_step_name_on_any_non_success_status(
    fail_at_index: int, bad_status: int
) -> None:
    responses = list(HAPPY_PATH)
    status, body = responses[fail_at_index]
    responses[fail_at_index] = (bad_status, body)
    t = SequencedTransport(responses)
    with pytest.raises(PullRequestError) as exc:
        create_pull_request(
            "acme/widgets", "b", "f.py", "x", title="t", body="b", token="x", transport=t
        )
    assert str(bad_status) in str(exc.value)


def test_create_pull_request_never_leaks_the_token_in_its_error_message() -> None:
    t = SequencedTransport([(404, {})])
    with pytest.raises(PullRequestError) as exc:
        create_pull_request(
            "acme/widgets", "b", "f.py", "x", title="t", body="b",
            token="sk-super-secret-token", transport=t,
        )  # fmt: skip
    assert "sk-super-secret-token" not in str(exc.value)
