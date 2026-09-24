"""Trivy adapter: SCA (lockfile vulns) + IaC + Dockerfile misconfig in one integration.

Uses Trivy's native JSON rather than its SARIF: SARIF drops package identity, CVSS and CWE data
that SCA deduplication and scoring need (see ADR-001 note). Secret scanning is disabled here
because Gitleaks owns that category.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Taxonomy,
)
from core.scoring.severity import normalize

log = logging.getLogger(__name__)


class TrivyAdapter(ToolAdapter):
    spec = ToolSpec(
        name="trivy",
        image="bulwark/trivy:0.55.2",
        categories=frozenset({"sca", "iac", "container"}),
        languages=frozenset(),
        timeout_seconds=900,
        writable_volumes=("/db",),  # Trivy opens its DB read-write; volume is copied from image
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "fs",
            "--cache-dir", "/db",
            "--skip-db-update",
            "--skip-check-update",
            "--offline-scan",
            # OSV-Scanner reports dev dependencies; Trivy skips them by default. Scanning the same
            # scope lets cross-tool agreement mean something (NodeGoat: 83 -> 291 of 292 OSV
            # findings matched). Risk scoring can later down-weight dev-only dependencies.
            "--include-dev-deps",
            "--scanners", "vuln,misconfig",
            "--format", "json",
            "--output", str(output),
            "--quiet",
            str(target),
        ]  # fmt: skip

    def applies_to(self, ctx: RepoContext) -> bool:
        return bool(ctx.lockfiles) or ctx.has_dockerfile or ctx.has_iac

    def parse(self, raw: bytes) -> list[Finding]:
        try:
            results = json.loads(raw).get("Results") or []
            if not isinstance(results, list):
                raise TypeError("Results is not a list")
        except (ValueError, TypeError, AttributeError) as exc:
            log.warning("trivy: could not parse output: %s", exc)
            return []
        findings: list[Finding] = []
        seen_misconfigs: set[tuple[str, str, int, int, str]] = set()
        for res in results:
            try:
                target = str(res["Target"])
                rtype = str(res.get("Type", ""))
                for v in res.get("Vulnerabilities") or []:
                    if (f := self._vuln(v, target, rtype)) is not None:
                        findings.append(f)
                for m in res.get("Misconfigurations") or []:
                    # Trivy reports some misconfigs twice (same rule, resource and lines; only
                    # cosmetic fields differ). Collapse them here, deliberately and visibly.
                    cause = m.get("CauseMetadata") or {}
                    key = (
                        str(m.get("ID")),
                        target,
                        int(cause.get("StartLine") or 0),
                        int(cause.get("EndLine") or 0),
                        str(cause.get("Resource", "")),
                    )
                    if key in seen_misconfigs:
                        log.debug("trivy: collapsed duplicate misconfiguration %s", key)
                        continue
                    seen_misconfigs.add(key)
                    if (f := self._misconfig(m, target, rtype)) is not None:
                        findings.append(f)
            except (KeyError, TypeError, AttributeError) as exc:
                log.warning("trivy: skipping malformed result block: %s", exc)
        return findings

    def _vuln(self, v: dict[str, Any], target: str, rtype: str) -> Finding | None:
        try:
            vid = str(v["VulnerabilityID"])
            name, version = str(v["PkgName"]), str(v["InstalledVersion"])
            native = str(v.get("Severity", "UNKNOWN")).upper()
            fixed = v.get("FixedVersion")
            title = str(v.get("Title") or vid)
            desc = str(v.get("Description") or title)
            loc_text = f"{name}@{version}"
            return Finding(
                id=f"trivy:{vid}:{target}:{loc_text}",
                title=f"{name} {version}: {title}"[:300],
                description=desc,
                location=Location(target, 1, 1, loc_text, Location.hash_snippet(loc_text)),
                taxonomy=Taxonomy(
                    Category.SCA,
                    cwe=tuple(str(c) for c in v.get("CweIDs") or []),
                    cve=(vid,) if vid.startswith("CVE-") else (),
                    aliases=(vid,),
                ),
                scoring=Scoring(
                    native_severity={"trivy": native},
                    normalized_severity=normalize("trivy", native),
                    cvss_v3_1=_best_cvss(v.get("CVSS") or {}),
                    confidence=0.9,
                ),
                evidence=Evidence(reported_by=["trivy"], rule_ids={"trivy": [vid]}),
                remediation=Remediation(
                    summary=(
                        f"Upgrade {name} to {fixed} or later."
                        if fixed
                        else f"No fixed version of {name} is available yet; consider mitigations."
                    ),
                    references=[u for u in [v.get("PrimaryURL")] if u],
                ),
                package=Package(name, version, Package.normalize_ecosystem(rtype)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("trivy: skipping malformed vulnerability: %s", exc)
            return None

    def _misconfig(self, m: dict[str, Any], target: str, rtype: str) -> Finding | None:
        try:
            rule = str(m["ID"])
            native = str(m.get("Severity", "UNKNOWN")).upper()
            cause = m.get("CauseMetadata") or {}
            start = max(int(cause.get("StartLine") or 1), 1)
            end = max(int(cause.get("EndLine") or start), start)
            lines = (cause.get("Code") or {}).get("Lines") or []
            snippet = "\n".join(str(ln.get("Content", "")) for ln in lines)
            category = Category.CONTAINER if rtype == "dockerfile" else Category.IAC
            return Finding(
                id=f"trivy:{rule}:{target}:{start}",
                title=str(m.get("Title") or rule),
                description=str(m.get("Message") or m.get("Description") or rule),
                location=Location(target, start, end, snippet, Location.hash_snippet(snippet)),
                taxonomy=Taxonomy(category),
                scoring=Scoring(
                    native_severity={"trivy": native},
                    normalized_severity=normalize("trivy", native),
                    confidence=0.8,
                ),
                evidence=Evidence(reported_by=["trivy"], rule_ids={"trivy": [rule]}),
                remediation=Remediation(
                    summary=str(m.get("Resolution") or ""),
                    references=[u for u in [m.get("PrimaryURL")] if u],
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("trivy: skipping malformed misconfiguration: %s", exc)
            return None


def _best_cvss(cvss: dict[str, Any]) -> float | None:
    """CVSS v3 score, preferring NVD, else the highest any source reports."""
    nvd = (cvss.get("nvd") or {}).get("V3Score")
    if nvd is not None:
        return float(nvd)
    scores = [float(s["V3Score"]) for s in cvss.values() if s.get("V3Score") is not None]
    return max(scores) if scores else None
