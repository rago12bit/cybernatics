"""Content-addressed scan result cache (plan §20.1).

File-local tools (Bandit, Semgrep, Gitleaks) reuse a cached result for any file whose content
hasn't changed since it was last scanned by the same tool version and ruleset. Repo-wide tools
(Trivy, OSV-Scanner) reuse a cached result for the whole tool run when the files that actually
drive their output (lockfiles, plus Dockerfile/IaC files for Trivy) are unchanged.

Disk-backed, not a database table: `bulwark scan`'s CLI and the GitHub Action run with no database
available, and that standalone path is exactly where the plan's speed target ("under 60 seconds
for a typical 50-file pull request") applies. A cache directory persisted across CI runs (e.g. via
actions/cache) is what turns a PR scan's *unchanged* files free on every run after the first.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from core.models import Finding, finding_from_dict

log = logging.getLogger(__name__)

#: Bump to invalidate every cache entry at once (a change to what a key means, not a tool upgrade
#: — a tool/ruleset change already changes the key on its own).
CACHE_VERSION = 1


@dataclass(frozen=True)
class CacheKey:
    """Identity of one cached result (plan §20.1): `(tool, tool_version, ruleset_hash,
    file_content_hash)`. `content_hash` is one file's content hash for a file-local tool, or a
    combined hash of every file that drives the result for a repo-wide one."""

    tool: str
    tool_version: str
    ruleset_hash: str
    content_hash: str

    def digest(self) -> str:
        raw = "|".join(
            (str(CACHE_VERSION), self.tool, self.tool_version, self.ruleset_hash, self.content_hash)
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: list[Path], root: Path | None = None) -> str:
    """Combined identity of several files (a repo-wide tool's inputs). Sorted, not in encounter
    order, so an unrelated reordering of the same files never manufactures a cache miss. With
    `root`, each file counts by its path under it rather than its bare name: the cached findings
    carry those paths, so a lockfile moved to another directory must not be served the old ones."""

    def label(p: Path) -> str:
        return p.relative_to(root).as_posix() if root is not None else p.name

    parts = sorted(f"{label(p)}:{hash_file(p)}" for p in paths if p.is_file())
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


class ResultCache:
    """One entry is one key's Findings, stored as a JSON file under `root`. A cache must never be
    able to fail a scan: a missing, corrupt, or unwritable entry is treated as a miss and logged,
    never raised — at worst it costs the time it would have saved."""

    def __init__(self, root: Path):
        self.root = root
        self.hits = 0
        self.misses = 0

    def _path(self, key: CacheKey) -> Path:
        digest = key.digest()
        return self.root / digest[:2] / f"{digest}.json"

    def get(self, key: CacheKey) -> list[Finding] | None:
        path = self._path(key)
        if not path.exists():
            self.misses += 1
            return None
        try:
            docs = json.loads(path.read_text("utf-8"))
            findings = [finding_from_dict(d) for d in docs]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("cache entry %s unreadable, treating as a miss: %s", path, exc)
            self.misses += 1
            return None
        self.hits += 1
        return findings

    def set(self, key: CacheKey, findings: list[Finding]) -> None:
        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps([f.to_dict() for f in findings]), encoding="utf-8")
            tmp.replace(path)  # atomic on the same filesystem: a reader never sees a partial write
        except OSError as exc:
            log.warning("could not write cache entry %s: %s", path, exc)
