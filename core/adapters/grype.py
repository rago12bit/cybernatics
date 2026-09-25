"""Grype adapter (SCA). Scope note: Grype has no option to include dev dependencies."""

from pathlib import Path
from typing import Any

from core.adapters.base import RepoContext, ToolSpec
from core.adapters.helpers import JsonAdapter, make_finding
from core.models import Category, Finding, Package


class GrypeAdapter(JsonAdapter):
    spec = ToolSpec("grype", "bulwark/grype:0.119.0", frozenset({"sca"}), frozenset(), 600)

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [f"dir:{target}", "-o", "json", "--file", str(output), "-q"]

    def applies_to(self, ctx: RepoContext) -> bool:
        return bool(ctx.lockfiles)

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return doc["matches"] or []

    def to_finding(self, m: dict[str, Any]) -> Finding:
        v, art = m["vulnerability"], m["artifact"]
        vid, name, version = str(v["id"]), str(art["name"]), str(art["version"])
        aliases = [vid, *(str(r["id"]) for r in m.get("relatedVulnerabilities") or [])]
        purl_type = str(art.get("purl", "pkg:unknown/")).split("/", 1)[0].removeprefix("pkg:")
        scores = [
            float(c["metrics"]["baseScore"])
            for c in v.get("cvss") or []
            if str(c.get("version")).startswith("3")
        ]
        fixed = (v.get("fix") or {}).get("versions") or []
        return make_finding(
            "grype",
            Category.SCA,
            rule=vid,
            title=f"{name} {version}: {v.get('description') or vid}",
            path=str((art.get("locations") or [{"path": "unknown"}])[0]["path"]).lstrip("/"),
            snippet=f"{name}@{version}",
            key=f"{name}@{version}",
            native=str(v.get("severity", "Unknown")),
            description=str(v.get("description") or vid),
            confidence=0.9,
            cvss=max(scores, default=None),
            cwe=[str(c["cwe"]) for c in v.get("cwes") or []],
            cve=[a for a in aliases if a.startswith("CVE-")],
            aliases=aliases,
            refs=[v.get("dataSource")],
            summary=f"Upgrade {name} to {fixed[0]} or later." if fixed else "",
            package=Package(name, version, Package.normalize_ecosystem(purl_type)),
        )
