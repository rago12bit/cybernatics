"""GitHub App integration (Week 30, ADR-0017): app-level JWT auth, installation tokens, webhook
signature verification, and the PR comment body for an App-triggered scan.

Deliberately separate from `core/ci/github.py` (the GitHub *Action*'s PR-comment poster): that
module authenticates with whatever token its caller already has (the Actions runtime's own
`GITHUB_TOKEN`, minted by GitHub for that one workflow run). This module is what obtains a token
in the first place, for a long-running server that isn't inside a GitHub Actions job at all -- but
once it has one, it reuses `core.ci.github.upsert_comment` to actually post, rather than a second
HTTP client.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import jwt as pyjwt

from core.ci.github import Transport, http_transport
from core.ci.report import code, md

_SAFE_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


class GithubAppError(RuntimeError):
    """Anything wrong with App auth or a webhook: a bad signature, an unexpected payload shape, or
    GitHub itself refusing a token request. Callers turn this into "ignore the event" or a 4xx,
    never a scan attempt with incomplete information."""


def app_jwt(app_id: str, private_key: str, *, now: float | None = None) -> str:
    """The App's own short-lived (~9 min) identity token, per GitHub's auth flow. RS256, signed with
    the App's private key; GitHub verifies it against the public key it already has for this App id.
    The -60s `iat` is GitHub's own documented margin for clock drift between us and their servers.
    """
    t = int(now if now is not None else time.time())
    payload = {"iat": t - 60, "exp": t + 9 * 60, "iss": app_id}
    return pyjwt.encode(payload, private_key, algorithm="RS256")


@dataclass(frozen=True)
class _CachedToken:
    token: str
    expires_at: float  # unix time


_installation_tokens: dict[str, _CachedToken] = {}
_REFRESH_MARGIN_S = 60.0  # re-mint a bit before GitHub's own ~1h expiry, not exactly at it


def _parse_expiry(value: Any, fallback: float) -> float:
    if not isinstance(value, str):
        return fallback
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return fallback


def installation_token(
    installation_id: str,
    app_id: str,
    private_key: str,
    *,
    api_url: str = "https://api.github.com",
    transport: Transport = http_transport,
    now: float | None = None,
) -> str:
    """An ~1h token scoped to exactly one installation's granted permissions and repositories, used
    to call the GitHub API on its behalf. Cached in-process per installation until near expiry: a
    cache miss on process restart is fine, but re-minting one on every single webhook event is not
    (needless latency and load, and GitHub does rate-limit this endpoint).

    The cache is per-process, not shared across API/worker replicas -- an accepted Week 30 scope
    cut; each process re-mints its own on first use, which costs one extra HTTP round trip per
    process, not per request.
    """
    t = now if now is not None else time.time()
    cached = _installation_tokens.get(installation_id)
    if cached is not None and cached.expires_at - _REFRESH_MARGIN_S > t:
        return cached.token
    status, body = transport(
        "POST",
        f"{api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens",
        {
            "Authorization": f"Bearer {app_jwt(app_id, private_key, now=t)}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bulwark-github-app",
        },
        None,
    )
    if status != 201 or not isinstance(body, dict) or not isinstance(body.get("token"), str):
        raise GithubAppError(f"could not mint an installation token (status {status})")
    token: str = body["token"]
    _installation_tokens[installation_id] = _CachedToken(
        token, _parse_expiry(body.get("expires_at"), fallback=t + 3600)
    )
    return token


def verify_signature(payload: bytes, signature_header: str | None, secret: str) -> bool:
    """Constant-time check of GitHub's `X-Hub-Signature-256` header. Never trust a webhook body
    before this passes -- it is the only thing standing between this endpoint and the public
    internet, since (unlike the rest of the API) a webhook has no bearer token to check."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, "sha256").hexdigest()
    return hmac.compare_digest(signature_header[len("sha256=") :], expected)


@dataclass(frozen=True)
class PullRequestEvent:
    installation_id: str
    account_login: str
    repo_full_name: str
    clone_url: str
    pr_number: int
    ref: str


def parse_pull_request_event(payload: dict[str, Any]) -> PullRequestEvent | None:
    """`None` for anything this integration doesn't act on: an action we don't scan for (closed,
    labeled, ...), or a payload missing a field we need -- never a crash on a shape GitHub is
    free to extend, and never a scan started from a half-understood event."""
    if payload.get("action") not in _SAFE_ACTIONS:
        return None
    try:
        installation_id = str(payload["installation"]["id"])
        account_login = str(payload["repository"]["owner"]["login"])
        repo_full_name = str(payload["repository"]["full_name"])
        clone_url = str(payload["repository"]["clone_url"])
        pr_number = int(payload["pull_request"]["number"])
    except (KeyError, TypeError, ValueError):
        return None
    return PullRequestEvent(
        installation_id=installation_id,
        account_login=account_login,
        repo_full_name=repo_full_name,
        clone_url=clone_url,
        pr_number=pr_number,
        ref=f"refs/pull/{pr_number}/head",
    )


def pr_comment_body(
    *, status: str, severity_counts: dict[str, int], findings: list[dict[str, Any]], scan_id: str
) -> str:
    """A plain summary of this PR's scan, not a diff against the base branch (`core/ci/compare.py`
    is the Action's base-vs-head diffing tool; the App path deliberately doesn't run a second scan
    of the base branch per PR just to reuse it -- see ADR-0017 for why). Every value from
    `findings` is untrusted scanner/repo text and goes through `core.ci.report`'s escaping helpers.
    """
    from core.ci.report import COMMENT_MARKER, MAX_LISTED, SEV_ORDER

    lines = [COMMENT_MARKER, "## Bulwark security scan", ""]
    if status != "completed":
        lines.append(f"Scan did not complete cleanly (status: `{md(status)}`).")
        return "\n".join(lines)
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    counted = ", ".join(
        f"{severity_counts[s]} {s.lower()}" for s in SEV_ORDER if severity_counts.get(s)
    )
    lines.append(f"**{len(findings)} finding(s)**: {counted}")
    lines += ["", "| Severity | Rule | Location |", "|---|---|---|"]
    ordered = sorted(
        findings, key=lambda f: -SEV_ORDER.index(str(f.get("scoring", {}).get(
            "normalized_severity", "INFO")).upper()) if str(f.get("scoring", {}).get(
            "normalized_severity", "INFO")).upper() in SEV_ORDER else 0,
    )  # fmt: skip
    for f in ordered[:MAX_LISTED]:
        sev = str(f.get("scoring", {}).get("normalized_severity", "INFO")).upper()
        loc = f.get("location", {})
        where = f"{loc.get('path', '?')}:{loc.get('start_line', '?')}"
        lines.append(f"| {md(sev)} | {code(f.get('title', ''))} | {code(where)} |")
    if len(findings) > MAX_LISTED:
        lines.append(f"\n_...and {len(findings) - MAX_LISTED} more._")
    lines.append(f"\n_Scan `{scan_id}`._")
    return "\n".join(lines)


_ = Transport, http_transport  # re-exported for callers that only import this module
