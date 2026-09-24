"""OSV-Scanner adapter (SCA over lockfiles, offline databases).

Uses OSV-Scanner's native JSON: one Finding per vulnerability *group* (OSV lists the GHSA, PYSEC
and CVE records of one issue separately; `groups` ties them together via aliases).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.adapters.base import TARGET_PREFIX, RepoContext, ToolAdapter, ToolSpec
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)

log = logging.getLogger(__name__)

_LABEL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def severity_from_cvss(score: float) -> Severity:
    """CVSS v3.1 base score bands (design doc §6.2)."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


class OsvScannerAdapter(ToolAdapter):
    spec = ToolSpec(
        name="osv-scanner",
        image="bulwark/osv-scanner:1.9.2",
        categories=frozenset({"sca"}),
        languages=frozenset(),
        timeout_seconds=600,
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "--experimental-offline-vulnerabilities",
            "--format", "json",
            "--output", str(output),
            "-r", str(target),
        ]  # fmt: skip

    def applies_to(self, ctx: RepoContext) -> bool:
        return bool(ctx.lockfiles)

    def parse(self, raw: bytes) -> list[Finding]:
        try:
            results = json.loads(raw)["results"]
            if not isinstance(results, list):
                raise TypeError("results is not a list")
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("osv-scanner: could not parse output: %s", exc)
            return []
        findings: list[Finding] = []
        for res in results:
            try:
                path = str(res["source"]["path"]).removeprefix(TARGET_PREFIX)
                for pkg in res.get("packages") or []:
                    findings.extend(self._package_findings(pkg, path))
            except (KeyError, TypeError, AttributeError) as exc:
                log.warning("osv-scanner: skipping malformed result: %s", exc)
        return findings

    def _package_findings(self, pkg: dict[str, Any], path: str) -> list[Finding]:
        info = pkg["package"]
        name, version = str(info["name"]), str(info["version"])
        eco = Package.normalize_ecosystem(str(info["ecosystem"]))
        vulns = {str(v["id"]): v for v in pkg.get("vulnerabilities") or []}
        out: list[Finding] = []
        for group in pkg.get("groups") or []:
            try:
                ids = [str(i) for i in group["ids"]]
                rep = next((vulns[i] for i in ids if i in vulns), None)
                if rep is None:
                    continue
                aliases = {str(a) for a in group.get("aliases", [])} | set(ids)
                cves = tuple(sorted(a for a in aliases if a.startswith("CVE-")))
                db = rep.get("database_specific") or {}
                score = _to_float(group.get("max_severity"))
                sev = (
                    severity_from_cvss(score)
                    if score is not None
                    else _LABEL_SEVERITY.get(str(db.get("severity", "")).upper(), Severity.INFO)
                )
                fixed = _fixed_versions(rep, name)
                text = f"{name}@{version}"
                out.append(
                    Finding(
                        id=f"osv-scanner:{ids[0]}:{path}:{text}",
                        title=f"{name} {version}: {rep.get('summary') or ids[0]}"[:300],
                        description=str(rep.get("details") or rep.get("summary") or ids[0]),
                        location=Location(path, 1, 1, text, Location.hash_snippet(text)),
                        taxonomy=Taxonomy(
                            Category.SCA,
                            cwe=tuple(str(c) for c in db.get("cwe_ids") or []),
                            cve=cves,
                        ),
                        scoring=Scoring(
                            native_severity={"osv-scanner": str(group.get("max_severity", ""))},
                            normalized_severity=sev,
                            cvss_v3_1=score,
                            confidence=0.9,
                        ),
                        evidence=Evidence(
                            reported_by=["osv-scanner"], rule_ids={"osv-scanner": ids[0]}
                        ),
                        remediation=Remediation(
                            summary=(
                                f"Upgrade {name} to {fixed[0]} or later."
                                if fixed
                                else f"No fixed version of {name} is listed; consider mitigations."
                            ),
                            references=[f"https://osv.dev/{ids[0]}"],
                        ),
                        package=Package(name, version, eco),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("osv-scanner: skipping malformed group: %s", exc)
        return out


def _to_float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _fixed_versions(vuln: dict[str, Any], name: str) -> list[str]:
    fixed: list[str] = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            fixed += [str(e["fixed"]) for e in rng.get("events") or [] if "fixed" in e]
    return fixed
