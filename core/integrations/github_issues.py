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


# --- Week 66 (plan §49): two-way sync -------------------------------------------------------------


@dataclass(frozen=True)
class IssueState:
    state: str  # "open" | "closed"
    state_reason: str | None  # "completed" | "not_planned" | "reopened" | None
    assignee: str | None  # login
    labels: tuple[str, ...]

    @property
    def status(self) -> str:
        """One name for the status mapping: "open", "closed", or "closed (not planned)"."""
        if self.state == "closed" and self.state_reason == "not_planned":
            return "closed (not planned)"
        return self.state


def get_issue(
    repo: str,
    issue_number: int,
    token: str,
    *,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> IssueState:
    if not _REPO.match(repo):
        raise GithubIssueError(f"invalid repository name: {repo!r}")
    status, data = transport(
        "GET", f"{api_url.rstrip('/')}/repos/{repo}/issues/{issue_number}", _headers(token), None
    )
    if status != 200 or not isinstance(data, dict):
        raise GithubIssueError(f"could not read {repo}#{issue_number} (HTTP {status})")
    assignee = data.get("assignee") or {}
    return IssueState(
        state=str(data.get("state") or "open"),
        state_reason=data.get("state_reason"),
        assignee=str(assignee["login"]) if assignee.get("login") else None,
        labels=tuple(
            str(lb.get("name")) for lb in data.get("labels") or [] if isinstance(lb, dict)
        ),
    )


def update_issue(
    repo: str,
    issue_number: int,
    token: str,
    *,
    title: str,
    labels: list[str],
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> None:
    status, _ = transport(
        "PATCH", f"{api_url.rstrip('/')}/repos/{repo}/issues/{issue_number}", _headers(token),
        json.dumps({"title": title[:256], "labels": labels}).encode(),
    )  # fmt: skip
    if status != 200:
        raise GithubIssueError(f"could not update {repo}#{issue_number} (HTTP {status})")
