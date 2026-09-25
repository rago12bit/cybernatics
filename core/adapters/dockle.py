"""Dockle adapter (container image linting, CIS Docker benchmark) over a `docker save` archive."""

from pathlib import Path
from typing import Any

from core.adapters.base import RepoContext, ToolSpec
from core.adapters.helpers import JsonAdapter, make_finding
from core.models import Category, Finding

IMAGE_ARCHIVE = "bulwark-image.tar"  # the name `bulwark scan-image` gives the saved image


class DockleAdapter(JsonAdapter):
    spec = ToolSpec("dockle", "bulwark/dockle:0.4.15", frozenset({"container"}), frozenset(), 300)

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "--input",
            f"{target}/{IMAGE_ARCHIVE}",
            "-f",
            "json",
            "-o",
            str(output),
            "--exit-code",
            "0",
        ]

    def applies_to(self, ctx: RepoContext) -> bool:
        return ctx.has_image_archive

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return [d for d in doc["details"] or [] if str(d["level"]).upper() not in ("PASS", "SKIP")]

    def to_finding(self, d: dict[str, Any]) -> Finding:
        code, alerts = str(d["code"]), "; ".join(str(a) for a in d.get("alerts") or [])
        return make_finding(
            "dockle",
            Category.CONTAINER,
            rule=code,
            title=str(d["title"]),
            path=IMAGE_ARCHIVE,
            snippet=alerts,
            native=str(d["level"]),
            description=f"{d['title']}: {alerts}" if alerts else str(d["title"]),
            confidence=0.8,
            aliases=[code],
            refs=[
                f"https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#{code.lower()}"
            ],
        )
