"""gosec adapter (Go SAST), from gosec's native JSON."""

import re
from pathlib import Path
from typing import Any

from core.adapters.base import TARGET_PREFIX, RepoContext, ToolSpec
from core.adapters.helpers import CONFIDENCE, JsonAdapter, make_finding
from core.models import Category, Finding

_CODE_LINE = re.compile(r"^(\d+): ?(.*)$")


class GosecAdapter(JsonAdapter):
    # Taint analysis (G7xx) silently vanishes when the Go build cache does not fit in /tmp.
    spec = ToolSpec(
        "gosec",
        "bulwark/gosec:2.29.0",
        frozenset({"sast"}),
        frozenset({"go"}),
        600,
        tmp_size="512m",
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return ["-fmt=json", f"-out={output}", "-no-fail", "-quiet", f"{target}/..."]

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return doc["Issues"] or []

    def to_finding(self, i: dict[str, Any]) -> Finding:
        first, _, last = str(i["line"]).partition("-")  # gosec reports "15" or "15-17"
        start = int(first)
        code = {
            int(m[1]): m[2]
            for ln in str(i.get("code", "")).splitlines()
            if (m := _CODE_LINE.match(ln))
        }
        cwe = i.get("cwe") or {}
        return make_finding(
            "gosec",
            Category.SAST,
            rule=str(i["rule_id"]),
            title=str(i["details"]),
            path=str(i["file"]).removeprefix(TARGET_PREFIX),
            start=start,
            end=int(last or first),
            snippet=code.get(start, ""),
            native=str(i["severity"]),
            confidence=CONFIDENCE.get(str(i.get("confidence", "")).upper(), 0.5),
            cwe=[f"CWE-{cwe['id']}"] if cwe.get("id") else [],
            refs=[cwe.get("url")],
        )
