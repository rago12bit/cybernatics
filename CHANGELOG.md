# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com);
versions will follow [SemVer](https://semver.org) once `v0.1.0` is tagged (planned for Week 10).

## [Unreleased]

Pre-alpha: everything below is unreleased.

### Added
- **Scanning:** sandboxed runners for Bandit, Semgrep CE, Gitleaks, Trivy and OSV-Scanner; one canonical
  `Finding` schema; SARIF ingestion.
- **Ingestion:** local directories, zip/tar archives (zip-slip, symlink and size guards) and public Git URLs
  (https-only, host allowlist, public-IP pinning).
- **Correlation:** cross-tool deduplication with stable fingerprints, a severity matrix, and a benchmark:
  28.5% fewer findings across five public repositories (2552 raw, 1824 unique).
- **Service:** FastAPI API with bearer-token auth and live progress over WebSocket; Postgres persistence
  (Alembic); S3-compatible object store; Celery workers; periodic housekeeping; docker compose stack.
- **Web UI:** sample report as the home page, findings table with URL-synced filters and JSON export,
  finding detail panel with keyboard navigation, `/about` page, accessibility tests.
- **Taxonomy:** CWE normalization and OWASP Top 10:2021 mapping from OWASP's own table, with documented
  defaults for dependency and misconfiguration findings.
- **Docs:** README with architecture diagram, ADRs 0001-0008, API reference, severity matrix,
  `SECURITY.md`, `CONTRIBUTING.md`.

### Fixed
- Trivy now scans dev dependencies so its scope matches OSV-Scanner (NodeGoat matches 83 to 291 of 292).
- OSV-Scanner upgraded to 2.6.0: offline matching went from about 140s to 11s for 250 packages.
- Bandit output could echo secrets into titles and snippets; it is now scrubbed.
- Scans no longer stay orphaned when the job queue is unreachable (the API returns 503).
- Findings no longer disappear silently when a scanner emits colliding ids.
- API pipeline now applies the CWE/OWASP mapping (the CLI path already did).

### Known issues
- Single shared bearer token; no users or rate limiting.
- Semgrep takes 30-40s even on small repositories.
- Semgrep rules licence blocks a public hosted demo (ADR-006).
