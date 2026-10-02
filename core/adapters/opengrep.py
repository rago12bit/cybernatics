"""Opengrep adapter (SAST) -- hosted mode's replacement for Semgrep (ADR-0038).

Semgrep's own community/Pro rules (`docker/semgrep/`, ADR-006) are licensed for internal business
use only: a hosted, multi-tenant deployment offering scans as a service is exactly the use that
license excludes. Opengrep is a community-maintained, LGPL-2.1 fork of the Semgrep engine with no
such restriction -- but its own bundled ruleset (github.com/opengrep/opengrep-rules) carries a
Commons Clause condition with the identical restriction, so this adapter ships a small, originally
written ruleset instead (`docker/opengrep/rules/`, Apache-2.0, same license as this project).

Deliberately a separate adapter from `SemgrepAdapter`, not a config flag on it: they point at
different images (no official Opengrep container exists upstream, so `docker/opengrep/` builds one
from a pinned, checksummed binary release) and different, non-overlapping rule directories, and
mixing "which binary" with "which license track" into one adapter's conditionals would make the
licensing boundary this adapter exists to enforce harder to see, not easier.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.adapters.base import TARGET_PREFIX, RepoContext, ToolSpec
from core.adapters.helpers import JsonAdapter, make_finding
from core.models import Category, Finding

_LANG_RULES = {"python": "python", "javascript": "javascript", "typescript": "javascript"}


def _rule_files(ctx: RepoContext | None) -> list[str]:
    if ctx is None or not ctx.languages:
        return ["/rules/python.yaml", "/rules/javascript.yaml"]  # unknown repo: run everything
    files = sorted(
        {f"/rules/{_LANG_RULES[lang]}.yaml" for lang in ctx.languages if lang in _LANG_RULES}
    )
    return files or ["/rules/python.yaml", "/rules/javascript.yaml"]


class OpengrepAdapter(JsonAdapter):
    spec = ToolSpec(
        name="opengrep",
        image="bulwark/opengrep:1.30.0",
        categories=frozenset({"sast"}),
        languages=frozenset({"python", "javascript", "typescript"}),
        timeout_seconds=900,
        # Opengrep's own binary self-extracts a child "opengrep-core" executable and execs it from
        # $TMPDIR. The sandbox's shared /tmp is a `noexec` tmpfs (every adapter gets one) -- rather
        # than loosening that shared protection for one tool, docker/opengrep/Dockerfile points
        # $TMPDIR/$HOME at /scratch, a plain writable volume (like trivy's own `/db`), which isn't
        # tmpfs and so isn't noexec. Confirmed live: the self-extraction fails against the default
        # /tmp with "couldn't launch child (exec): Permission denied", and succeeds against
        # /scratch with the exact same container flags otherwise unchanged.
        writable_volumes=("/scratch",),
    )

    def ruleset_id(self, ctx: RepoContext | None) -> str:
        return "|".join(_rule_files(ctx))

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        configs: list[str] = []
        for f in _rule_files(ctx):
            configs += ["--config", f]
        return ["scan", *configs, "--json", "--output", str(output), str(target)]

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return list(doc["results"])

    def to_finding(self, r: dict[str, Any]) -> Finding:
        path = str(r["path"]).removeprefix(TARGET_PREFIX)
        start, end = int(r["start"]["line"]), int(r["end"]["line"])
        meta = r.get("extra", {}).get("metadata", {}) or {}
        message = str(r.get("extra", {}).get("message", r["check_id"]))
        return make_finding(
            "opengrep", Category.SAST, rule=str(r["check_id"]), title=message,
            path=path, start=start, end=end,
            snippet=str(r.get("extra", {}).get("lines", "")),
            native=str(r.get("extra", {}).get("severity", "WARNING")),
            description=message, confidence=0.6,
            cwe=[str(c) for c in meta.get("cwe", [])],
            refs=meta.get("references", []),
        )  # fmt: skip
