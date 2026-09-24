"""Semgrep CE adapter (SAST). Native SARIF -> shared ingestion path."""

from __future__ import annotations

from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.models import Category, Finding, Severity
from core.sarif import parse_sarif

# Judgment call, not derived truth (design doc §6.2): Semgrep ERROR ~ HIGH, WARNING ~ MEDIUM.
LEVEL_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW}


# detected language -> rule directories baked into the image. Loading only what the repo contains
# roughly halves scan time (measured: 71s -> 32s on a small Python repo, identical findings).
_LANG_RULES = {
    "python": ["python"],
    "javascript": ["javascript", "typescript"],
    "go": ["go"],
    "java": ["java"],
}


def _rule_dirs(ctx: RepoContext | None) -> list[str]:
    if ctx is None or not ctx.languages:
        return ["/rules"]  # unknown repo: fall back to everything
    dirs = [f"/rules/{d}" for lang in sorted(ctx.languages) for d in _LANG_RULES.get(lang, [])]
    return dirs or ["/rules"]


class SemgrepAdapter(ToolAdapter):
    spec = ToolSpec(
        name="semgrep",
        image="bulwark/semgrep:1.90.0",
        categories=frozenset({"sast"}),
        languages=frozenset({"python", "javascript", "go", "java"}),
        timeout_seconds=900,
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
            "--output",
            str(output),
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            str(target),
        ]

    def parse(self, raw: bytes) -> list[Finding]:
        return parse_sarif(
            raw,
            tool="semgrep",
            category=Category.SAST,
            level_map=LEVEL_MAP,
            strip_rule_prefix="rules.",
        )
