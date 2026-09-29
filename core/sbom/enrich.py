"""Joins a CycloneDX SBOM's own package licenses onto findings before policy evaluation (plan
§20.5). `core.policy.input.issue_document` already reads `finding["package"]["license"]` -- that
field was only ever waiting for something to populate it; this is that something.

Works at the plain-dict level (`Finding.to_dict()` shape), the same level `core.ci.compare` and
`core.policy.gate` already operate at for the standalone CLI/Action path, which is the only path
that has a separately-generated SBOM file to join against today (the hosted pipeline does not yet
run Syft as part of a scan -- that is its own, separate piece of work, not done here).
"""

from __future__ import annotations

from typing import Any

from core.models import Package
from core.sbom.syft import Sbom


def _key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    return (Package.normalize_ecosystem(ecosystem), name, version)


def license_map(sbom: Sbom) -> dict[tuple[str, str, str], str]:
    return {_key(p.ecosystem, p.name, p.version): p.license for p in sbom.packages if p.license}


def apply_licenses(findings: list[dict[str, Any]], sbom: Sbom) -> list[dict[str, Any]]:
    """Enrichment only: a finding with no package, or one the SBOM has no license for, is returned
    unchanged -- never a fabricated "unknown". A finding that already carries a license (should
    that ever happen) is left as-is rather than overwritten by a second source."""
    licenses = license_map(sbom)
    if not licenses:
        return findings
    out = []
    for f in findings:
        pkg = f.get("package")
        if not pkg or pkg.get("license"):
            out.append(f)
            continue
        lic = licenses.get(
            _key(
                str(pkg.get("ecosystem", "")), str(pkg.get("name", "")), str(pkg.get("version", ""))
            )
        )
        out.append({**f, "package": {**pkg, "license": lic}} if lic else f)
    return out


__all__ = ["apply_licenses", "license_map"]
