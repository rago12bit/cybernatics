"""A real ToolAdapter shipped by a package Bulwark's own source tree never imports -- the thing the
Plugin SDK's discovery (core.plugins.registry) has to find instead of a hardcoded import.

Honest simplification, not something a real plugin publisher would do: this reuses
`bulwark/bandit:1.7.10`'s own image (already proven compatible with the sandbox's strict runtime
flags by every existing bandit test) rather than building and signing a new scanner image of its
own, which needs a real CI pipeline with OIDC access this example repo doesn't have. See this
package's own README for what a real plugin would do differently; `core.plugins.signing` will
correctly refuse this exact adapter's image at resolution time, since it was never Sigstore-signed
-- demonstrated deliberately in tests/integration/test_plugin_sandbox_execution_live.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.adapters.base import TARGET_PREFIX, RepoContext, ToolSpec
from core.adapters.helpers import CONFIDENCE, JsonAdapter, make_finding
from core.models import Category, Finding


class DemoAdapter(JsonAdapter):
    spec = ToolSpec(
        "demo-bandit-plugin",
        "bulwark/bandit:1.7.10",
        frozenset({"sast"}),
        frozenset({"python"}),
        timeout_seconds=600,
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return ["-r", str(target), "-f", "json", "-o", str(output), "-q"]

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return list(doc["results"])

    def to_finding(self, r: dict[str, Any]) -> Finding:
        lines = r.get("line_range") or [r["line_number"]]
        return make_finding(
            "demo-bandit-plugin", Category.SAST, rule=str(r["test_id"]),
            title=f"[demo plugin] {r['issue_text']}", snippet=str(r.get("code", "")),
            path=str(r["filename"]).removeprefix(TARGET_PREFIX), key=str(r["line_number"]),
            start=int(min(lines)), end=int(max(lines)), native=str(r["issue_severity"]),
            description=f"bulwark-plugin-demo wrapping bandit: {r['test_name']} ({r['test_id']})",
            confidence=CONFIDENCE.get(str(r.get("issue_confidence", "")).upper(), 0.5),
        )  # fmt: skip
