# ADR-001: SARIF 2.1.0 as the canonical intermediate format

Status: Accepted (2026-09-24)

## Context
Each scanner emits its own format and severity vocabulary. We need one intermediate
representation before mapping to our internal `Finding` model.

## Options
1. Bespoke schema.
2. SARIF 2.1.0 (OASIS standard).

## Decision
Every tool's output is converted to SARIF 2.1.0, then to `Finding`. Tools with native SARIF
(Semgrep, Trivy, Gitleaks, OSV-Scanner) share one ingestion path; others (Bandit) are converted
by their adapter.

## Consequences
- GitHub Code Scanning consumes our export with no extra work.
- One SARIF ingestion path is reused across adapters.
- SARIF is verbose and lacks some fields we need (EPSS, KEV); those live on `Finding`, not SARIF.

## Amendment (2026-09-24, Week 4)
SARIF is lossy for SCA: it carries no package identity, CVSS vector or CWE list. The Trivy and
OSV-Scanner adapters therefore parse each tool's richer native JSON straight into `Finding`.
SARIF remains the ingestion path for tools that emit it natively (Semgrep) and will be the
*export* format generated from `Finding` (Week 10, for GitHub Code Scanning).
