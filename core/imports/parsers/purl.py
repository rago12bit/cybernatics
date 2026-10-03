"""Package URLs (https://github.com/package-url/purl-spec) -> the (ecosystem, name, version) triple
every other tool in Bulwark identifies a dependency by (ADR-004). SBOM formats name components this
way, and CycloneDX `affects` entries often carry nothing else."""

from __future__ import annotations

from urllib.parse import unquote

from core.models import Package


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """`pkg:npm/%40babel/core@7.1.0?x=y#z` -> ("npm", "@babel/core", "7.1.0"); None if it is not a
    purl. A purl without a version gives version "" (the caller decides whether that is usable)."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    version = ""
    if "@" in body:
        body, _, version = body.rpartition("@")
    parts = [unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    ptype, rest = parts[0].lower(), parts[1:]
    name = rest[-1]
    namespace = "/".join(rest[:-1])
    if namespace:
        # OSV (and so the rest of Bulwark) writes a Maven package as "group:artifact"; every other
        # ecosystem joins namespace and name with a slash (npm scopes, Go module paths).
        name = f"{namespace}:{name}" if ptype == "maven" else f"{namespace}/{name}"
    return Package.normalize_ecosystem(ptype), name, unquote(version)
