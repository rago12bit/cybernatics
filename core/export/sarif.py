"""SARIF 2.1.0 export, shaped for GitHub Code Scanning (`github/codeql-action/upload-sarif`).

One result per merged finding. Rules carry `security-severity` (GitHub's 0-10 scale) so alerts sort the
way Bulwark ranks them, and `partialFingerprints` reuse Bulwark's stable fingerprint so re-uploads track
the same alert. Snippets were already redacted by the pipeline; secrets never appear here.
"""

from __future__ import annotations

from typing import Any

from core.export.model import ReportData

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# GitHub buckets security-severity as >=9 critical, 7-8.9 high, 4-6.9 medium, 0.1-3.9 low.
SECURITY_SEVERITY = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 0.5}
TOOL_URI = "https://github.com/rago12bit/cybernatics"


def _rule_id(f: dict[str, Any]) -> str:
    """A stable id per kind of issue: the CVE for dependencies, else the first scanner rule that fired."""
    tax = f["taxonomy"]
    if tax["category"] == "sca" and tax["cve"]:
        return str(tax["cve"][0])
    for tool, rules in f["evidence"]["rule_ids"].items():
        if rules:
            return f"{tool}/{rules[0]}"
    return f"bulwark/{tax['category']}"


def _tags(f: dict[str, Any]) -> list[str]:
    tax = f["taxonomy"]
    tags = ["security", tax["category"]]
    tags += [f"external/cwe/{c.lower()}" for c in tax["cwe"]]
    tags += [f"external/owasp/{o.lower()}" for o in tax["owasp_top_10_2021"]]
    return tags


def _sec_severity(f: dict[str, Any]) -> str:
    cvss = f["scoring"].get("cvss_v3_1")
    val = (
        cvss
        if isinstance(cvss, (int, float)) and cvss > 0
        else SECURITY_SEVERITY[f["scoring"]["normalized_severity"]]
    )
    return f"{val:.1f}"


def to_sarif(report: ReportData) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.by_risk():
        rid = _rule_id(f)
        sev = f["scoring"]["normalized_severity"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("/", "_").replace(".", "_")[:120],
                "shortDescription": {"text": f["title"][:1000]},
                "fullDescription": {"text": (f["description"] or f["title"])[:4000]},
                "help": {"text": f["remediation"]["summary"] or "See the finding details."},
                "defaultConfiguration": {"level": LEVEL[sev]},
                "properties": {"tags": _tags(f), "security-severity": _sec_severity(f)},
            }
        loc = f["location"]
        region: dict[str, Any] = {
            "startLine": max(1, int(loc["start_line"])),
            "endLine": max(1, int(loc["end_line"]), int(loc["start_line"])),
        }
        if loc.get("snippet"):
            region["snippet"] = {"text": loc["snippet"]}
        sc = f["scoring"]
        results.append(
            {
                "ruleId": rid,
                "level": LEVEL[sev],
                "message": {"text": f["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": loc["path"], "uriBaseId": "%SRCROOT%"},
                            "region": region,
                        }
                    }
                ],
                "partialFingerprints": {"bulwarkFingerprint/v1": f.get("fingerprint") or f["id"]},
                "properties": {
                    "severity": sev,
                    "risk_score": sc.get("risk_score"),
                    "epss": sc.get("epss_score"),
                    "in_cisa_kev": sc.get("in_cisa_kev", False),
                    "risk_factors": sc.get("risk_factors", []),
                    "reported_by": f["evidence"]["reported_by"],
                    "agreement_count": f["evidence"]["agreement_count"],
                    "confidence": sc.get("confidence"),
                },
            }
        )
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bulwark",
                        "informationUri": TOOL_URI,
                        "semanticVersion": _version(),
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"bulwark/{report.scan_id}"},
                "originalUriBaseIds": {
                    "%SRCROOT%": {"description": {"text": "Root of the scanned source."}}
                },
                "results": results,
                "properties": {
                    "source": report.source_label,
                    "raw_findings": report.raw_findings,
                    "unique_findings": report.unique_findings,
                    "tool_status": {k: v.get("status") for k, v in report.tool_status.items()},
                },
            }
        ],
    }


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("bulwark-scan")
    except PackageNotFoundError:  # running from a source tree without an install
        return "0.0.0"
