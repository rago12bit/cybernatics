"""Semgrep CE adapter (SAST). Native SARIF -> shared ingestion path."""

from __future__ import annotations

import json
from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.models import Category, Finding
from core.sarif import parse_sarif

# detected language -> rule files baked into the image (one merged file per directory, see
# docker/semgrep/merge-rules.py; loading hundreds of small files was ~25 s of every scan).
# Loading only what the repo contains roughly halves scan time (measured: 71s -> 32s on a small
# Python repo, identical findings).
_LANG_RULES = {
    "python": ["python"],
    "javascript": ["javascript", "typescript"],
    "go": ["go"],
    "java": ["java"],
}


def _rule_dirs(ctx: RepoContext | None) -> list[str]:
    if ctx is None or not ctx.languages:
        return ["/rules"]  # unknown repo: fall back to everything
    dirs = [f"/rules/{d}.yaml" for lang in sorted(ctx.languages) for d in _LANG_RULES.get(lang, [])]
    return dirs or ["/rules"]


class SemgrepAdapter(ToolAdapter):
    spec = ToolSpec(
        name="semgrep",
        image="bulwark/semgrep:1.90.0",
        categories=frozenset({"sast"}),
        languages=frozenset({"python", "javascript", "go", "java"}),
        timeout_seconds=900,
        cpus=4,  # measured 20-40% faster on larger repos; rule loading is single-threaded
        native_sarif=True,
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        configs: list[str] = []
        for cfg in _rule_dirs(ctx):
            configs += ["--config", cfg]
        return [
            "scan",
            *configs,
            "--sarif",
            "--autofix",  # with --dryrun: report the rule's own fix in the SARIF, change nothing
            "--dryrun",
            "--output",
            str(output),
            f"--jobs={max(1, int(self.spec.cpus))}",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            str(target),
        ]

    def warnings(self, raw: bytes) -> list[str]:
        """Semgrep gives up on a rule/file after 5 s and still exits 0, so slow or CPU-starved runs
        silently lose findings (dvpwa: 5 findings under load vs 169). Say so."""
        try:
            runs = json.loads(raw).get("runs", [])
            notes = [
                n
                for run in runs
                for inv in run.get("invocations", [])
                for n in inv.get("toolExecutionNotifications", [])
            ]
        except (ValueError, AttributeError):
            return []
        timeouts = [n for n in notes if n.get("descriptor", {}).get("id") == "Timeout"]
        if not timeouts:
            return []
        return [
            f"{len(timeouts)} rule/file pairs timed out and were skipped; results may be incomplete"
        ]

    def parse(self, raw: bytes) -> list[Finding]:
        return parse_sarif(
            raw,
            tool="semgrep",
            category=Category.SAST,
            strip_rule_prefix="rules.",
        )
