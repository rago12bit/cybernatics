"""Semgrep CE adapter (SAST). Native SARIF -> shared ingestion path."""

from __future__ import annotations

from pathlib import Path

from core.adapters.base import ToolAdapter, ToolSpec
from core.models import Category, Finding, Severity
from core.sarif import parse_sarif

# Judgment call, not derived truth (design doc §6.2): Semgrep ERROR ~ HIGH, WARNING ~ MEDIUM.
LEVEL_MAP = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW}


class SemgrepAdapter(ToolAdapter):
    spec = ToolSpec(
        name="semgrep",
        image="bulwark/semgrep:1.90.0",
        categories=frozenset({"sast"}),
        languages=frozenset({"python", "javascript", "go", "java"}),
        timeout_seconds=900,
        native_sarif=True,
    )

    def build_command(self, target: Path, output: Path) -> list[str]:
        return [
            "scan",
            "--config",
            "/rules",
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
