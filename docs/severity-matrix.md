# Severity normalization matrix

_Generated from `core/scoring/severity.py` by `scripts/gen-api-docs.py`; do not edit._

Tool severity vocabularies are not comparable. This table is a **judgment call**, not a derived truth: it maps each tool's native label to one shared scale.

| Tool | CRITICAL | HIGH | MEDIUM | LOW | INFO |
|---|---|---|---|---|---|
| semgrep | — | ERROR | WARNING | INFO | — |
| bandit | — | HIGH | MEDIUM | LOW | — |
| trivy | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
| grype | CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE, UNKNOWN |
| gosec | — | HIGH | MEDIUM | LOW | — |
| checkov | CRITICAL | HIGH | MEDIUM | LOW | — |
| dockle | — | FATAL | WARN | INFO | — |
| gitleaks | — | (any) | — | — | — |
| precommit-secrets | — | (any) | — | — | — |
| precommit-sast | — | HIGH | MEDIUM | LOW | — |
| osv-scanner | CRITICAL | HIGH | MODERATE, MEDIUM | LOW | — |
| syft | — | — | — | — | — |
| OSV via CVSS v3.1 | ≥ 9.0 | 7.0–8.9 | 4.0–6.9 | 0.1–3.9 | 0 / none |
