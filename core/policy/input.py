"""Builds the OPA input document from a scan's own findings (plan §20.4: "the input is the scan
summary plus the Issue set").

Every field here comes from data a `Finding` (or, when the caller has it, an `IssueRow`) already
carries -- nothing is invented. `malicious` (plan §20.5) is derived the same way `in_cisa_kev` is:
always present, `false` unless the finding's own alias set contains an OSSF malicious-packages
report id (`osv-scanner`, the only adapter that surfaces these, already forces such a finding's
`aliases` to include its `MAL-...` id -- see `core.adapters.osv_scanner`). Two fields the starter
policy library's own examples need have no real source yet anywhere in this codebase and are
included only when present, never guessed:

  - `license`: needs Week 40's SBOM/license work (plan §20.5); until then, `Finding`/`Package`
    simply carries no license, so it is omitted from the input document entirely rather than sent
    as `null` or `"unknown"` -- a policy testing `issue.license == "GPL-3.0"` correctly never
    matches an absent field, the same "no signal" behavior an unresolved license lookup would
    produce once one exists.
  - `triage_expires_at`: lives on `IssueRow` (`core/persistence/models.py`), a database row keyed
    by asset, not on the standalone `Finding` JSON a `bulwark scan --format json` file contains --
    so it is only ever present when the caller passes real `issues` (the hosted pipeline, which has
    database access); the standalone CLI/Action gate never has it.
"""

from __future__ import annotations

from typing import Any


def _entrypoint(finding: dict[str, Any]) -> str:
    """The HTTP entrypoint a taint path (plan §20.3) traced this finding back to, if any --
    `TaintHop.description` for the entrypoint step is always written as
    "HTTP entrypoint: <method> <path> (<framework>)" (`core.taint.engine.find_taint_paths`)."""
    for step in finding.get("taint_path") or []:
        description = str(step.get("description", ""))
        if description.startswith("HTTP entrypoint:"):
            return description.removeprefix("HTTP entrypoint:").strip()
    return ""


def issue_document(finding: dict[str, Any], issue: dict[str, Any] | None = None) -> dict[str, Any]:
    """One finding, as OPA sees it. `issue` (triage state, expiry) is optional -- omitted fields
    are simply absent from the document, never a fabricated default."""
    scoring = finding.get("scoring") or {}
    taxonomy = finding.get("taxonomy") or {}
    package = finding.get("package") or {}
    doc: dict[str, Any] = {
        "id": finding.get("id", ""),
        "fingerprint": finding.get("fingerprint", ""),
        "title": finding.get("title", ""),
        "severity": str(scoring.get("normalized_severity", "")).upper(),
        "category": taxonomy.get("category", ""),
        "cwe": list(taxonomy.get("cwe", [])),
        "owasp": list(taxonomy.get("owasp_top_10_2021", [])),
        "in_cisa_kev": bool(scoring.get("in_cisa_kev", False)),
        "malicious": any(str(a).startswith("MAL-") for a in taxonomy.get("aliases", [])),
        "risk_score": scoring.get("risk_score"),
        "entrypoint": _entrypoint(finding),
    }
    if scoring.get("reachable") is not None:
        doc["reachable"] = bool(scoring["reachable"])
    if package.get("license"):
        doc["license"] = package["license"]
    if issue:
        if issue.get("triage_status"):
            doc["triage_status"] = issue["triage_status"]
        if issue.get("triage_expires_at"):
            doc["triage_expires_at"] = issue["triage_expires_at"]
    return doc


def build_input(
    findings: list[dict[str, Any]],
    issues_by_fingerprint: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """`new_issues`: the plan's own field name (§20.4's example policy reads `input.new_issues`).
    `issues_by_fingerprint` (optional) supplies per-issue triage state, keyed the same way
    `core.correlation.fingerprint` already identifies a finding across scans."""
    issues_by_fingerprint = issues_by_fingerprint or {}
    return {
        "new_issues": [
            issue_document(f, issues_by_fingerprint.get(f.get("fingerprint", ""))) for f in findings
        ]
    }


__all__ = ["build_input", "issue_document"]
