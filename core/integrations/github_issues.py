"""Create and update GitHub Issues from Bulwark Issues (Week 51 task 2, plan §23).

Deliberately separate from `core.github_app` (the GitHub *App* integration for PR-triggered
scanning, Week 30/ADR-0017): that flow authenticates as an installed App and is about running
scans, not filing issues. This integration authenticates with a plain personal access token the
operator generates themselves and pastes into their own per-org integration settings -- no App
installation required, matching this project's self-hosted, one-operator-configures-their-own-
credentials posture elsewhere (`core/secrets/resolve.py`'s "off means off" convention). A deployment
that *also* has the GitHub App installed for PR scanning can still use this independently; the two
features share no credential.

Reuses `core.ci.github`'s `Transport`/`http_transport` convention (plain `urllib.request`, the same
HTTP client style every outbound call in this codebase already uses) rather than a new HTTP
dependency.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from core.ci.github import Transport, http_transport

_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GithubIssueError(RuntimeError):
    pass


@dataclass(frozen=True)
class CreatedIssue:
    number: int
    url: str


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "bulwark-integrations",
        "Content-Type": "application/json",
    }


def create_issue(
    repo: str,
    title: str,
    body: str,
    token: str,
    *,
    labels: tuple[str, ...] = (),
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> CreatedIssue:
    if not _REPO.match(repo):
        raise GithubIssueError(f"invalid repository name: {repo!r}")
    payload: dict[str, object] = {"title": title[:256], "body": body}
    if labels:
        payload["labels"] = list(labels)
    status, data = transport(
        "POST", f"{api_url.rstrip('/')}/repos/{repo}/issues", _headers(token),
        json.dumps(payload).encode(),
    )  # fmt: skip
    if status != 201 or not isinstance(data, dict):
        raise GithubIssueError(f"could not create issue on {repo} (HTTP {status})")
    return CreatedIssue(number=int(data["number"]), url=str(data["html_url"]))


def set_issue_state(
    repo: str,
    issue_number: int,
    state: Literal["open", "closed"],
    token: str,
    *,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> None:
    status, _ = transport(
        "PATCH", f"{api_url.rstrip('/')}/repos/{repo}/issues/{issue_number}", _headers(token),
        json.dumps({"state": state}).encode(),
    )  # fmt: skip
    if status != 200:
        raise GithubIssueError(f"could not set {repo}#{issue_number} to {state} (HTTP {status})")


def add_comment(
    repo: str,
    issue_number: int,
    body: str,
    token: str,
    *,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> None:
    status, _ = transport(
        "POST", f"{api_url.rstrip('/')}/repos/{repo}/issues/{issue_number}/comments",
        _headers(token), json.dumps({"body": body}).encode(),
    )  # fmt: skip
    if status != 201:
        raise GithubIssueError(f"could not comment on {repo}#{issue_number} (HTTP {status})")
