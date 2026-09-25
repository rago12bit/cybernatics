# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com);
versions will follow [SemVer](https://semver.org) once `v0.1.0` is tagged (planned for Week 10).

## [Unreleased]

### Added
- **GitHub Action (Week 18), `action/`:** composite action that scans, uploads SARIF to Code Scanning, comments
  the findings a pull request **introduces** (base and head scans compared by fingerprint; one comment updated in
  place) and fails at a configurable severity (`fail-on`, counting only new findings on pull requests). New CLI:
  `bulwark ci compare` (exit 0/1/2, writes SARIF, comment, job summary and outputs) and `bulwark ci comment`.
  A baseline where a scanner failed is not trusted; the comment then lists everything and says so. Not yet run on
  GitHub: the step scripts were run locally against a real base/head git repository. See docs/github-action.md.

### Added
- **VS Code hover and Quick Fix (Week 17):** hovering a finding shows severity, risk score and why, description,
  CWE/OWASP, the fix summary, references and the reporting scanners (plain, untrusted markdown built from escaped
  text). **Quick Fix** offers "apply scanner-suggested fix" when the finding carries a patch, and "open CWE
  reference". A patch is offered only if its context and removed lines equal the text in the editor right now
  (one file, the finding's own, at most 20 hunks, no ambiguous matches), so a file edited since the scan is never
  patched blindly. New settings: `bulwark.tools` (list of scanners) and `bulwark.minimumSeverity`.
- **Semgrep autofix as suggested patches:** Semgrep now runs with `--autofix --dryrun` (nothing is modified) and a
  rule's own single-line fix is converted to a unified diff in `remediation.suggested_patch` when its shape is safe
  (`generated_by: static`). Fixes it cannot convert safely are dropped. A merged finding keeps a patch from any
  reporting tool. Checked against real Semgrep on a sample file.

### Added
- **VS Code extension scaffold (Week 16), `extensions/vscode`:** TypeScript extension that runs the CLI without a
  shell and maps findings to native diagnostics (severity, CWE/rule code, risk score, reporting tools) in the
  Problems panel. Commands: Scan Workspace (cancellable, with a timeout), Clear Findings, Show Output. Refuses
  untrusted workspaces, takes the CLI path from machine-scope settings only, and ignores findings whose path
  escapes the scanned folder. 44 tests; verified against the real CLI, **not yet run inside a real VS Code**.

### Added
- **Reachability v1 (Week 15):** for npm and PyPI dependency findings, Bulwark now checks whether the scanned
  code imports the vulnerable package (Python via `ast`, JavaScript/TypeScript via tree-sitter; CommonJS, ESM,
  dynamic `import()`, `importlib`, and test vs application code). `scoring.reachable` is `true`, `false` or unknown,
  the reason appears under "Why this ranks here", and an unimported package's risk is reduced by 15% (KEV floor 90 → 80).
  It is deliberately coarse and never turns "cannot tell" (transitive dependency, plugin loaded by name, unparsable
  files, other ecosystems) into "unreachable": see docs/reachability.md. New threat T14 (parsing untrusted source
  in the worker) recorded as Partial. New runtime dependencies: `tree-sitter` and its JavaScript/TypeScript grammars.

### Added
- **Patch checking (Week 14):** suggested patches are checked against the code the model saw: line numbers are
  corrected, hunk context is balanced so `patch`/`git apply` accept minimal model-style hunks (tested against the
  real `patch` tool), and a patch that does not match the code or changes nothing is discarded with a reason.
  The UI shows "Checked: matches the code" or "Not fully checked".
- **Fix-quality evaluation harness:** a deterministic 50-finding sample (35 code findings across 35 rules, 15
  dependency findings), a runner using the product's own path, a blinded offline scoring page, and a report with
  Wilson intervals that refuses unscored data. **The evaluation itself has not been run** (needs a model key and a
  human scorer): see docs/evaluation-remediation.md.

### Added
- **AI suggestions in the app (Week 13), off by default:** a **Fix guidance** section in the finding panel with
  always-available reference guidance (CWE + OWASP, labelled "not AI-generated") and, when a server enables it, an
  explicit **Generate AI suggestion** click; AI text sits in its own dashed block labelled "AI suggestion. Review
  before applying." with model, confidence, warnings and a text-only patch (no apply button). `GET
  /scans/{id}/guidance` (no model call), `POST /scans/{id}/suggestion`.
- **Response cache** keyed by rule + snippet hash (package + version for dependencies) + model + prompt version, shared
  across scans; only successful replies are stored; a cached patch is shown only at its own file and line;
  concurrent identical requests make one model call. **Spend limit** per minute and per day (`429` + `Retry-After`).
- Migrations `0003` (cache table); the migrate step now also loads the knowledge base if empty; the sample site ships
  precomputed reference guidance.

### Fixed
- Retrieval explained a finding by its most general CWE (CWE-20 "Improper Input Validation") instead of the exact one
  (CWE-1321 prototype pollution); it now prefers the most specific weakness.
- Corrected the Week 12 docs: through the API only the stored snippet is available to send, not +/-20 lines.

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
