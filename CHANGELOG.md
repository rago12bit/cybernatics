# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com);
versions will follow [SemVer](https://semver.org) once `v0.1.0` is tagged (planned for Week 10).

## [Unreleased]

### Added
- **LLM remediation design (Week 12), off by default:** a provider-agnostic `LLMClient` (Anthropic behind the
  optional `llm` extra); a prompt with random-nonce data fences and instructions only in the system message; a
  strict output contract (five fields, unified-diff patch limited to the finding's file, rejects severity or
  triage keys and "false positive" language); secret scrubbing before any code is sent; static fallback text for
  every failure; `bulwark llm status|prompt|suggest`. 135 tests including 20 hostile payloads and simulated
  hijacked models. No real model has been run against it yet. See [docs/llm-remediation.md](docs/llm-remediation.md), ADR-010.

### Added
- **Remediation knowledge base (Week 11):** a committed corpus of 211 CWE entries and 1,697 OWASP cheat-sheet
  chunks; pgvector (`vector(1024)`, HNSW) in the existing PostgreSQL via migration `0002`; a model-free hashed
  TF-IDF embedder; `context_for(finding)` retrieval; `bulwark kb load|stats|search`. Measured: right sheet in
  the top 5 for 84% of real findings without metadata. See [docs/rag.md](docs/rag.md), ADR-009.
- Postgres image is now built locally with pgvector on the same Alpine base (`docker/postgres`).

### Fixed (UI behaviour)
- A scan that finished while the live socket was connecting stayed on "Running" forever; the socket's
  snapshot is now honoured, and any close before the scan finishes falls back to polling.
- Opening a scan page showed the previous scan's data until the new one loaded; late responses for an old id
  can no longer leak in.
- Polling refetched the whole findings table every 3 seconds; results now refresh only when they change.
- An expired or rejected token now returns to the sign-in screen instead of polling 401s forever.
- The header's "Sign out" and the app disagreed about being signed in until you navigated.
- The new-scan form could submit an archive you could no longer see after switching source type, and greyed
  out "Start" without saying why (now explains: non-https URL, no scanner chosen).
- Recent scans never updated while a scan ran and its "3 min ago" labels froze; both now stay current, and
  polling stops when nothing is running.
- Filter changes replaced the router's history state, so Back/Forward reloaded the page; links to a page past
  the end now land on the last page.
- Previous/next in the finding panel followed the table even when opened from "Fix these first"; they now
  follow the list you opened it from.
- Within a severity, findings are ordered by risk (they were ordered by file path).

### Added
- **Sample-only web build** (`NEXT_PUBLIC_DEMO_ONLY=1`) for public hosting: no API or scanning, `/app` redirects to a
  `/self-host` page, tighter CSP, HSTS; `web/fly.toml` and [docs/deploy-demo.md](docs/deploy-demo.md).

## [0.1.0] - 2026-09-25

First tagged release (pre-alpha: single shared token, not for untrusted multi-user hosting).

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
- **Risk ranking:** EPSS (FIRST.org) and CISA KEV feeds, validated and cached, refreshed daily; a 0-100
  `risk_score` with plain-language `risk_factors`; a **Fix these first** top-10 panel; `bulwark update-feeds`;
  `GET /risk/feeds`. See [docs/risk-score.md](docs/risk-score.md).
- **Exports:** whole-scan **SARIF 2.1.0** (validated against the official schema; GitHub Code Scanning
  shaped), a self-contained script-free **HTML** report, and a **PDF**; `GET /scans/{id}/export`,
  `bulwark scan --format sarif|html|pdf -o FILE`, and download buttons in the UI.
- **Docs:** [threat model](docs/THREAT-MODEL.md) with per-threat status; README with architecture diagram, ADRs 0001-0008, API reference, severity matrix,
  `SECURITY.md`, `CONTRIBUTING.md`.

### Fixed
- Trivy now scans dev dependencies so its scope matches OSV-Scanner (NodeGoat matches 83 to 291 of 292).
- OSV-Scanner upgraded to 2.6.0: offline matching went from about 140s to 11s for 250 packages.
- Bandit output could echo secrets into titles and snippets; it is now scrubbed.
- Scans no longer stay orphaned when the job queue is unreachable (the API returns 503).
- Findings no longer disappear silently when a scanner emits colliding ids.
- API pipeline now applies the CWE/OWASP mapping (the CLI path already did); both paths now share one
  `finalize()` step so they cannot drift again.

### Known issues
- Single shared bearer token; no users or rate limiting.
- Semgrep takes 30-40s even on small repositories.
- Semgrep rules licence blocks a public hosted demo (ADR-006).
