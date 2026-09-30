"""Open a pull request through the GitHub App, after a human approves a verified fix (plan §21.2).

No "create a pull request" code existed anywhere before this (confirmed before writing it --
`core/github_app.py` only mints tokens and posts PR comments). Built entirely on the GitHub REST
API's Contents API, not local git: `core.gitfetch.clone_repo` deletes `.git` from every checkout it
makes (an existing, deliberate isolation choice, unrelated to this feature), so there is no local
git history to commit from. A single-file patch -- which is all this ever produces, since
`core.llm.contract.validate_patch` already requires exactly one file -- needs nothing heavier than:
read the base branch's head commit, create a new branch ref from it, and update one file on that
branch (GitHub commits it for you). Same `Transport`-injection style `core.ci.github.upsert_comment`
already uses, for the same reason: real HTTP in production, a fake in tests.

**Not validated against a real GitHub App installation** -- this environment has no App credentials
to test against. Each request shape below matches GitHub's documented, long-stable REST v3 contract;
verified by reading the docs, not by guessing, but the honest gap is that no live installation has
exercised it end to end. See docs/v2-week42-verification.md.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from core.ci.github import Transport, http_transport


class PullRequestError(RuntimeError):
    """Any GitHub API call in this flow failed. The message names the failing step and HTTP status,
    never repository content or the token."""


@dataclass(frozen=True)
class PullRequestResult:
    html_url: str
    number: int
    branch: str


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "bulwark-fixagent",
        "Content-Type": "application/json",
    }


def create_pull_request(
    repo: str,  # "owner/repo"
    branch_name: str,
    path: str,
    new_content: str,
    *,
    title: str,
    body: str,
    token: str,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> PullRequestResult:
    """Creates `branch_name` from the repository's current default branch, commits `new_content` to
    `path` on it (one file -- the finding's own, matching what a verified-fix patch ever touches),
    and opens a PR from it back to the default branch. Every step is get-then-act with an explicit
    status check; nothing here retries or guesses a fallback on a partial failure, since a partially
    created branch with no PR pointing at it should surface as an error, not silently disappear."""
    base = api_url.rstrip("/")
    headers = _headers(token)

    status, repo_doc = transport("GET", f"{base}/repos/{repo}", headers, None)
    if status != 200 or not isinstance(repo_doc, dict):
        raise PullRequestError(f"could not read repository {repo} (status {status})")
    default_branch = str(repo_doc["default_branch"])

    status, ref_doc = transport(
        "GET", f"{base}/repos/{repo}/git/ref/heads/{default_branch}", headers, None
    )
    if status != 200 or not isinstance(ref_doc, dict):
        raise PullRequestError(f"could not read the default branch's ref (status {status})")
    base_sha = str(ref_doc["object"]["sha"])

    status, _ = transport(
        "POST",
        f"{base}/repos/{repo}/git/refs",
        headers,
        json.dumps({"ref": f"refs/heads/{branch_name}", "sha": base_sha}).encode(),
    )
    if status != 201:
        raise PullRequestError(f"could not create branch {branch_name} (status {status})")

    status, file_doc = transport(
        "GET", f"{base}/repos/{repo}/contents/{path}?ref={branch_name}", headers, None
    )
    if status != 200 or not isinstance(file_doc, dict):
        raise PullRequestError(f"could not read {path} on {branch_name} (status {status})")
    file_sha = str(file_doc["sha"])

    status, _ = transport(
        "PUT",
        f"{base}/repos/{repo}/contents/{path}",
        headers,
        json.dumps(
            {
                "message": title,
                "content": base64.b64encode(new_content.encode()).decode("ascii"),
                "sha": file_sha,
                "branch": branch_name,
            }
        ).encode(),
    )
    if status not in (200, 201):
        raise PullRequestError(f"could not commit {path} to {branch_name} (status {status})")

    status, pr_doc = transport(
        "POST",
        f"{base}/repos/{repo}/pulls",
        headers,
        json.dumps(
            {"title": title, "head": branch_name, "base": default_branch, "body": body}
        ).encode(),
    )
    if status != 201 or not isinstance(pr_doc, dict):
        raise PullRequestError(f"could not open the pull request (status {status})")
    return PullRequestResult(
        html_url=str(pr_doc["html_url"]), number=int(pr_doc["number"]), branch=branch_name
    )
