"""VEX vocabulary (plan §46.3): OpenVEX's statuses and justifications, and CycloneDX's equivalents.

OpenVEX v0.2.0 (https://github.com/openvex/spec), whose justifications are CISA's "Vulnerability
Exploitability eXchange (VEX) -- Status Justifications" (June 2022). CycloneDX 1.6's
`vulnerabilities[].analysis` (https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_analysis).
The justification mapping below is Bulwark's own reading of the two vocabularies (neither
specification defines one); `vulnerable_code_cannot_be_controlled_by_adversary` has no exact
CycloneDX counterpart and is exported as `requires_environment`, and every CycloneDX statement
keeps the OpenVEX value in its detail and properties, so nothing is lost.
"""

from __future__ import annotations

STATUSES = ("not_affected", "affected", "fixed", "under_investigation")

JUSTIFICATIONS = {
    "component_not_present": "The vulnerable component is not included in the product.",
    "vulnerable_code_not_present": "The component is included, but not the vulnerable code.",
    "vulnerable_code_not_in_execute_path": (
        "The vulnerable code is present but the product never executes it."
    ),
    "vulnerable_code_cannot_be_controlled_by_adversary": (
        "The vulnerable code runs, but an attacker cannot control its input."
    ),
    "inline_mitigations_already_exist": (
        "The product has built-in protections against the vulnerability."
    ),
}

CDX_STATE = {
    "not_affected": "not_affected",
    "affected": "exploitable",
    "fixed": "resolved",
    "under_investigation": "in_triage",
}

CDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}


def check_justification(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if value not in JUSTIFICATIONS:
        raise ValueError(f"unknown VEX justification {value!r}: one of {', '.join(JUSTIFICATIONS)}")
    return value
