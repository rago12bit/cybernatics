"""Asset identity: the key that groups repeated scans of "the same thing" (ADR-0012).

A git source's identity is its normalized URL: scans of "https://github.com/owner/repo",
"https://github.com/owner/repo.git" and "https://GitHub.com/owner/repo/" are all the same asset.
An archive upload has no stable identity of its own — the server-side path is a one-time temp file —
so its identity is the filename the user gave it. That's a heuristic, not a guarantee: renaming the
archive between uploads starts a new asset, and uploading someone else's differently-named archive
of the same project starts a new asset too. Documented rather than solved, because solving it needs
either content hashing (defeated by any change to the code) or the user naming a project explicitly,
which is out of scope for Week 28.
"""

from __future__ import annotations

from urllib.parse import urlsplit

SourceType = str  # "git" | "archive" | "web"


def asset_key(source_type: SourceType, source_label: str) -> str:
    """The identity a repeated scan is matched against. Same inputs -> same key, always."""
    if source_type == "git":
        return _normalize_git_url(source_label)
    if source_type == "web":
        return _normalize_domain(source_label)
    return source_label.strip()


def _normalize_git_url(url: str) -> str:
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    return f"https://{host}{path}"


def _normalize_domain(domain_or_url: str) -> str:
    """A web asset's identity is just its registrable host, lowercased, scheme/path/port dropped --
    "https://Example.com/", "example.com:443" and "example.com" are the same asset (plan §22.4's
    DAST target). Unlike a git URL, a web target has no meaningful path component to preserve: the
    whole site is in scope once ownership is verified, not one URL under it."""
    raw = domain_or_url.strip()
    if "//" not in raw:
        raw = f"//{raw}"
    host = (urlsplit(raw).hostname or raw.strip("/")).lower()
    return host
