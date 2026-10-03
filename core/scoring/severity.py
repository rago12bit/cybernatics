"""Severity normalization matrix (design doc §6.2).

Tool severity vocabularies are not comparable: Semgrep's ERROR is not Trivy's HIGH. This table is
an explicit *judgment call*, not a derived truth, and lives in one place so it can be reviewed.
"""

from __future__ import annotations

from core.models import Severity

S = Severity

# tool -> {native label (upper-case) -> normalized severity}. "*" matches any label.
MATRIX: dict[str, dict[str, Severity]] = {
    "semgrep": {"ERROR": S.HIGH, "WARNING": S.MEDIUM, "INFO": S.LOW},
    # Hosted mode's Semgrep replacement (ADR-0038) -- same engine lineage, same severity labels.
    "opengrep": {"ERROR": S.HIGH, "WARNING": S.MEDIUM, "INFO": S.LOW},
    "bandit": {"HIGH": S.HIGH, "MEDIUM": S.MEDIUM, "LOW": S.LOW},
    "trivy": {
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
        "UNKNOWN": S.INFO,
    },
    "grype": {  # Grype's own label case differs from Trivy's; NEGLIGIBLE is its lowest, not "none"
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
        "NEGLIGIBLE": S.INFO,
        "UNKNOWN": S.INFO,
    },
    "gosec": {"HIGH": S.HIGH, "MEDIUM": S.MEDIUM, "LOW": S.LOW},
    # Open-source Checkov attaches no severity, so every check arrives as MEDIUM (see the adapter).
    "checkov": {"CRITICAL": S.CRITICAL, "HIGH": S.HIGH, "MEDIUM": S.MEDIUM, "LOW": S.LOW},
    "dockle": {"FATAL": S.HIGH, "WARN": S.MEDIUM, "INFO": S.LOW},
    "gitleaks": {"*": S.HIGH},  # a committed credential is always treated as high
    # Pre-commit hook's native, no-Docker complements to gitleaks/bandit (plan §23, Week 51 task 4).
    "precommit-secrets": {"*": S.HIGH},
    "precommit-sast": {"HIGH": S.HIGH, "MEDIUM": S.MEDIUM, "LOW": S.LOW},
    # OSV-Scanner reports CVSS scores where available (see from_cvss), else GitHub-style labels:
    "osv-scanner": {
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MODERATE": S.MEDIUM,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
    },
    # Syft produces a document, not Findings (`SyftAdapter.parse` always returns []) -- no native
    # severity ever reaches `normalize()` for it. An empty row, not an absent one: every registered
    # tool gets a row in the published matrix, even a trivially unreachable one.
    "syft": {},
    # An uploaded SARIF report from a tool Bulwark has no row for (core.imports.parsers.sarif): the
    # SARIF level, which `core.sarif` maps note -> INFO. A `security-severity` score, when the rule
    # carries one, overrides this.
    "sarif": {"ERROR": S.HIGH, "WARNING": S.MEDIUM, "INFO": S.LOW},
    # DAST and network tools' own words, read by `core.dast.mapping`. ZAP's `riskcode` 0-3 is
    # Informational/Low/Medium/High (it has no Critical); Nuclei's own "unknown" is defined by
    # Nuclei, so it is Info without a warning, while a word Nuclei does not define still warns.
    "zap": {"INFORMATIONAL": S.INFO, "LOW": S.LOW, "MEDIUM": S.MEDIUM, "HIGH": S.HIGH},
    "nuclei": {
        "INFO": S.INFO,
        "LOW": S.LOW,
        "MEDIUM": S.MEDIUM,
        "HIGH": S.HIGH,
        "CRITICAL": S.CRITICAL,
        "UNKNOWN": S.INFO,
    },
    # Burp's own words (its "Information" is Info; it has no Critical).
    "burp": {
        "HIGH": S.HIGH,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
        "INFORMATION": S.INFO,
        "INFO": S.INFO,
    },
    # Nessus's 0-4 scale by name (core.imports.parsers.nessus maps the digit); "None" is Info.
    "nessus": {
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
        "NONE": S.INFO,
        "INFO": S.INFO,
        "INFORMATIONAL": S.INFO,
    },
    # OpenVAS "threat" levels. It reports Critical as High; Log, Debug and an overridden False
    # Positive carry no risk of their own, so they are Info (all defined by OpenVAS, so no warning).
    "openvas": {
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
        "LOG": S.INFO,
        "INFO": S.INFO,
        "DEBUG": S.INFO,
        "FALSE POSITIVE": S.INFO,
    },
    # CycloneDX defines exactly these rating severities (core.imports.parsers.cyclonedx); anything
    # else a file says is unknown, imported as INFO, and reported.
    "cyclonedx": {
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
        "INFO": S.INFO,
        "NONE": S.INFO,
        "UNKNOWN": S.INFO,
    },
}

# CVSS v3.1 base-score bands (FIRST.org qualitative severity rating scale).
CVSS_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, S.CRITICAL),
    (7.0, S.HIGH),
    (4.0, S.MEDIUM),
    (0.1, S.LOW),
)


def normalize(tool: str, native: str, default: Severity = S.INFO) -> Severity:
    table = MATRIX.get(tool, {})
    return table.get(native.strip().upper(), table.get("*", default))


def from_cvss(score: float) -> Severity:
    for floor, sev in CVSS_BANDS:
        if score >= floor:
            return sev
    return S.INFO


def as_markdown() -> str:
    cols = [S.CRITICAL, S.HIGH, S.MEDIUM, S.LOW, S.INFO]
    rows = ["| Tool | " + " | ".join(c.value for c in cols) + " |", "|---|" + "---|" * len(cols)]
    for tool, table in MATRIX.items():
        cells = []
        for c in cols:
            labels = [k if k != "*" else "(any)" for k, v in table.items() if v is c]
            cells.append(", ".join(labels) or "—")
        rows.append(f"| {tool} | " + " | ".join(cells) + " |")
    bands = {S.CRITICAL: "≥ 9.0", S.HIGH: "7.0–8.9", S.MEDIUM: "4.0–6.9", S.LOW: "0.1–3.9"}
    rows.append(
        "| OSV via CVSS v3.1 | " + " | ".join(bands.get(c, "0 / none") for c in cols) + " |"
    )
    return "\n".join(rows)
