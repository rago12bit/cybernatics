"""Bandit adapter (Python SAST). The pathfinder adapter: simplest output format."""

import re
from pathlib import Path
from typing import Any

from core.adapters.base import TARGET_PREFIX, RepoContext, ToolSpec
from core.adapters.helpers import CONFIDENCE, JsonAdapter, make_finding
from core.models import Category, Finding

# B105-B107 echo the hardcoded value in their message; never carry it into a Finding (T7).
_HARDCODED_PW_RULES = {"B105", "B106", "B107"}
_QUOTED = re.compile(r"(['\"]).*?\1")


class BanditAdapter(JsonAdapter):
    spec = ToolSpec(
        "bandit", "bulwark/bandit:1.7.10", frozenset({"sast"}), frozenset({"python"}), 600
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return ["-r", str(target), "-f", "json", "-o", str(output), "-q"]

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return list(doc["results"])

    def to_finding(self, r: dict[str, Any]) -> Finding:
        lines = r.get("line_range") or [r["line_number"]]
        text, snippet = str(r["issue_text"]), str(r.get("code", ""))
        if r.get("test_id") in _HARDCODED_PW_RULES:
            text = _QUOTED.sub("'[redacted]'", text)
            snippet = "[snippet withheld: hardcoded credential]"
        cwe = r.get("issue_cwe") or {}
        return make_finding(
            "bandit", Category.SAST, rule=str(r["test_id"]), title=text, snippet=snippet,
            path=str(r["filename"]).removeprefix(TARGET_PREFIX), key=str(r["line_number"]),
            start=int(min(lines)), end=int(max(lines)), native=str(r["issue_severity"]),
            description=f"{r['test_name']} ({r['test_id']}): {text}",
            confidence=CONFIDENCE.get(str(r.get("issue_confidence", "")).upper(), 0.5),
            cwe=[f"CWE-{cwe['id']}"] if "id" in cwe else [], refs=[r.get("more_info")],
        )  # fmt: skip
