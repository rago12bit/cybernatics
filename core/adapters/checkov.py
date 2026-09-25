"""Checkov adapter (infrastructure-as-code misconfiguration), from Checkov's JSON."""

from pathlib import Path
from typing import Any

from core.adapters.base import RepoContext, ToolSpec
from core.adapters.helpers import JsonAdapter, make_finding
from core.models import Category, Finding


class CheckovAdapter(JsonAdapter):
    # Checkov chooses its own file name inside --output-file-path, hence output_name.
    spec = ToolSpec(
        "checkov",
        "bulwark/checkov:3.3.19",
        frozenset({"iac"}),
        frozenset(),
        600,
        output_name="results_json.json",
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "-d",
            str(target),
            "-o",
            "json",
            "--output-file-path",
            str(output.parent),
            "--quiet",
            "--compact",
        ]

    def applies_to(self, ctx: RepoContext) -> bool:
        return ctx.has_iac or ctx.has_dockerfile

    def records(self, doc: Any) -> list[dict[str, Any]]:
        reports = doc if isinstance(doc, list) else [doc]  # one report per framework
        return [c for r in reports for c in r["results"]["failed_checks"]]

    def to_finding(self, c: dict[str, Any]) -> Finding:
        start, end = (int(n) for n in c["file_line_range"])
        return make_finding(
            "checkov",
            Category.IAC,
            rule=str(c["check_id"]),
            title=str(c["check_name"]),
            path=str(c["file_path"]).lstrip("/"),
            start=start,
            end=end,
            snippet=str(c.get("resource", "")),
            native=str(c.get("severity") or "MEDIUM"),  # open-source Checkov reports no severity
            description=str(c.get("description") or c["check_name"]),
            confidence=0.6,
            refs=[c.get("guideline")],
        )
