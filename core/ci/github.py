"""Post or update the one Bulwark comment on a pull request. Standard library only, https only."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from core.ci.report import COMMENT_MARKER

Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, Any]]
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BOT = "github-actions[bot]"
MAX_PAGES = 5


class CommentError(RuntimeError):
    pass


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only within the same scheme, host and port. urllib follows any redirect
    and keeps the Authorization header, so a Jira address (or a webhook's) that answered 302 to
    another host would be sent the credentials, and one that answered with an internal address
    would be fetched from inside the network, past the address check made when it was saved.
    GitHub's own redirects (a renamed repository) stay on its host and still work. A refused
    redirect is returned to the caller as its 3xx status, like any other unexpected answer."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if (new.scheme, new.hostname, new.port) != (old.scheme, old.hostname, old.port):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirects)


def http_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=30) as resp:  # noqa: S310 - https only, checked by caller
            raw = resp.read(8 * 1024 * 1024)
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        return exc.code, None


def post_comment(
    repo: str,
    pr_number: int,
    body: str,
    token: str,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> int:
    """A new comment on a pull request (the GitHub App's `/fix` replies, Week 76: one per reply,
    not one edited in place). Returns its id."""
    if not _REPO.match(repo):
        raise CommentError("invalid repository name")
    if not api_url.startswith("https://") or pr_number < 1 or not token:
        raise CommentError("invalid api url, pull request number or token")
    status, data = transport(
        "POST",
        f"{api_url.rstrip('/')}/repos/{repo}/issues/{pr_number}/comments",
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bulwark-github-app",
            "Content-Type": "application/json",
        },
        json.dumps({"body": body}).encode(),
    )
    if status != 201 or not isinstance(data, dict):
        raise CommentError(f"GitHub returned HTTP {status} while posting the comment")
    return int(data.get("id") or 0)


def upsert_comment(
    repo: str,
    pr_number: int,
    body: str,
    token: str,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
) -> str:
    """Update our existing comment or create it. Returns "created" or "updated"."""
    if not _REPO.match(repo):
        raise CommentError("invalid repository name")
    if not api_url.startswith("https://") or pr_number < 1 or not token:
        raise CommentError("invalid api url, pull request number or token")
    if COMMENT_MARKER not in body:
        raise CommentError("comment body is missing its marker")
    base = api_url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "bulwark-ci",
        "Content-Type": "application/json",
    }
    payload = json.dumps({"body": body}).encode()
    existing: int | None = None
    for page in range(1, MAX_PAGES + 1):
        status, data = transport(
            "GET",
            f"{base}/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}",
            headers,
            None,
        )
        if status != 200 or not isinstance(data, list):
            raise CommentError(
                f"could not list comments (HTTP {status}); a fork PR's token cannot write comments"
            )
        for c in data:
            # Only our own bot's comment: a user quoting the marker must not redirect the update.
            if (
                isinstance(c, dict)
                and COMMENT_MARKER in str(c.get("body", ""))
                and (c.get("user") or {}).get("login") == BOT
            ):
                existing = int(c["id"])
        if len(data) < 100:
            break
    if existing is not None:
        status, _ = transport(
            "PATCH", f"{base}/repos/{repo}/issues/comments/{existing}", headers, payload
        )
        action = "updated"
    else:
        status, _ = transport(
            "POST", f"{base}/repos/{repo}/issues/{pr_number}/comments", headers, payload
        )
        action = "created"
    if status not in (200, 201):
        raise CommentError(f"GitHub returned HTTP {status} while posting the comment")
    return action
