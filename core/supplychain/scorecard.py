"""OpenSSF Scorecard enrichment for direct dependencies (plan §20.5).

Two public, unauthenticated REST APIs, both validated against their live endpoints before this was
written (`github.com/psf/requests`, `github.com/sirupsen/logrus`):
  - deps.dev's purl lookup (`GET api.deps.dev/v3alpha/purl/<percent-encoded purl>`) resolves a
    package version to its source repository, when one is known (`version.relatedProjects[]` with
    `relationType == "SOURCE_REPO"`).
  - The OpenSSF Scorecard REST API (`GET api.securityscorecards.dev/projects/<repo>`) returns that
    repository's own weekly-refreshed Scorecard run -- no local `scorecard` binary needed.

Runs API/worker side only, the same trust boundary `core.risk.feeds` already draws for EPSS/KEV:
scanner containers never get network. Scoped to *direct* dependencies only (the plan's own
wording), both because that is what an organization can act on directly and because it bounds the
number of outbound requests a scan makes to one pair per direct dependency, not one per transitive
package (which can be hundreds).
"""

from __future__ import annotations

import json
import os
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import Settings
from core.risk.feeds import http_get

STALE_AFTER_HOURS = 24 * 7  # Scorecard itself only re-runs against a given repo about once a week
Fetcher = Callable[[str], bytes]


@dataclass(frozen=True)
class ScorecardResult:
    repo: str
    score: float
    checks: dict[str, float] = field(default_factory=dict)
    date: str = ""


def scorecard_cache_dir() -> Path:
    d = Settings.from_env().workdir / "feeds" / "scorecard"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_source_repo(purl: str, fetch: Fetcher = http_get) -> str | None:
    """`github.com/owner/repo`, when deps.dev knows one for this exact package version; `None` on
    anything else (an ecosystem deps.dev's purl API does not cover, an unknown package, a network
    error, no GitHub source) -- never a guess."""
    try:
        encoded = urllib.parse.quote(purl, safe="")
        doc = json.loads(fetch(f"https://api.deps.dev/v3alpha/purl/{encoded}"))
        for link in (doc.get("version") or {}).get("relatedProjects") or []:
            if link.get("relationType") == "SOURCE_REPO":
                repo_id = str((link.get("projectKey") or {}).get("id", ""))
                if repo_id.startswith("github.com/"):
                    return repo_id
    except Exception:  # noqa: BLE001 - best effort; a scan must never fail because deps.dev did
        pass
    return None


def _cache_path(repo: str) -> Path:
    return scorecard_cache_dir() / (repo.replace("/", "__") + ".json")


def _read_cache(repo: str, now: datetime) -> ScorecardResult | None:
    try:
        doc = json.loads(_cache_path(repo).read_text())
        fetched_at = datetime.fromisoformat(doc["fetched_at"])
        if (now - fetched_at).total_seconds() > STALE_AFTER_HOURS * 3600:
            return None
        r = doc["result"]
        return ScorecardResult(r["repo"], r["score"], r["checks"], r["date"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_cache(result: ScorecardResult) -> None:
    doc = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "result": {
            "repo": result.repo,
            "score": result.score,
            "checks": result.checks,
            "date": result.date,
        },
    }
    path = _cache_path(result.repo)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, path)


def fetch_scorecard(
    repo: str, fetch: Fetcher = http_get, now: datetime | None = None
) -> ScorecardResult | None:
    """A repo's own Scorecard run, cached for a week (matching Scorecard's own refresh cadence) so
    a scan does not re-fetch the same repo's result every time. `None` when Scorecard has never
    analyzed this repository, or on a network error -- absent, not a fabricated zero score."""
    now = now or datetime.now(timezone.utc)
    cached = _read_cache(repo, now)
    if cached is not None:
        return cached
    try:
        doc: Any = json.loads(fetch(f"https://api.securityscorecards.dev/projects/{repo}"))
        result = ScorecardResult(
            repo=repo,
            score=float(doc["score"]),
            checks={str(c["name"]): float(c["score"]) for c in doc.get("checks") or []},
            date=str(doc.get("date", "")),
        )
    except Exception:  # noqa: BLE001
        return None
    _write_cache(result)
    return result


def enrich_direct_dependencies(
    direct_purls: frozenset[str], fetch: Fetcher = http_get, now: datetime | None = None
) -> dict[str, ScorecardResult]:
    """One Scorecard lookup per direct-dependency purl that resolves to a GitHub repo. Silently
    skips (never fails on) a purl deps.dev cannot resolve, or a repo Scorecard has never analyzed.
    """
    out: dict[str, ScorecardResult] = {}
    for purl in sorted(direct_purls):
        repo = resolve_source_repo(purl, fetch)
        if repo is None:
            continue
        result = fetch_scorecard(repo, fetch, now)
        if result is not None:
            out[purl] = result
    return out


__all__ = [
    "ScorecardResult",
    "enrich_direct_dependencies",
    "fetch_scorecard",
    "resolve_source_repo",
    "scorecard_cache_dir",
]
