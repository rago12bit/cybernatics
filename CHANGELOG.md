# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com), versions follow
[SemVer](https://semver.org).

## [Unreleased]

### Added
- **Week 27 verification gate:** every v2-plan §16.1 check re-run live against real Docker containers rather than
  inferred from unit tests — sandbox flags via `docker inspect`, network isolation, 9 adapters × 7 malformed
  inputs, a container killed mid-scan, zip-bomb/zip-slip/file-count/SSRF ingestion attacks, secret masking
  end-to-end, and a prompt-injection baseline. All passed; two gaps are real and documented rather than hidden:
  the VS Code extension has never run in a real VS Code install, and the GitHub Action has never run on GitHub's
  runners (`origin/main` is well behind local `HEAD`). Full results: docs/v1-verification.md.
- **ADR-0012 (design), ADR-0013 (design, Week 29):** the Issue/Occurrence data model split and Postgres
  Row-Level Security for multi-tenancy.
- **Week 28 — Issue/Occurrence data model, implemented (ADR-0012):** `core/assets.py` and `core/issues.py`
  (pure identity + lifecycle logic), `Asset`/`IssueRow` tables, and `core/pipeline.py` now syncs every completed
  scan's findings against its asset's history: `new` → `open` → `fixed` → `reintroduced`. The API's
  `GET /scans/{id}` gained `issue_counts`; each finding gained an `issue` field. The web app shows a badge on
  new/reintroduced findings and a quiet one-line summary, silent otherwise. `scripts/backfill-issues.py`
  backfills scans from before this shipped (dry-run by default); run for real against this environment's 13
  pre-existing scans (5 assets, 1,468 issues). Verified live end to end against a real API, worker and
  Postgres — four real scans of the same uploaded archive through the actual lifecycle, cross-checked directly
  against the database, not just the API's response. Caught and fixed a real fingerprint collision along the
  way: two findings of different categories can hash identically under ADR-0004's fingerprint when both lack a
  CWE and land on the same redacted line, so Issue identity is scoped to `(asset, category, fingerprint)`, not
  `(asset, fingerprint)`. Full writeup: docs/v2-week28-verification.md.
- **ADR-0014, ADR-0015, ADR-0016 (design, pre-implementation scope cuts):** before their respective v2 weeks
  start, three risks were reviewed and scoped down on the record rather than left to slip quietly later —
  taint analysis narrowed to intra-procedural, single-language (Python), configure-Semgrep-taint-mode-first
  (ADR-0014); the verified-fix agent's Temporal workflow given an overall *and* a per-attempt wall-clock
  timeout plus a per-tenant concurrency cap, with cancellation surfaced as a distinct `inconclusive` state
  rather than folded into `failed` (ADR-0015); scanner adapter drift caught by pinned tool versions plus a
  weekly CI job that bumps one tool at a time against the existing golden fixtures, rather than a daily
  schema-poll against upstream repositories that publish no such schema (ADR-0016).

## [1.0.0] - 2026-09-27

All 26 weeks of the plan. `v0.2.0` was tagged in git between `v0.1.0` and this release but was never given its own
entry here or a version bump in `pyproject.toml`/`package.json`; everything below is therefore the full set of
changes since `v0.1.0`, not only since `v0.2.0`.

### Added
- **v1.0.0 (Week 26):** documentation pass across README, docs/rag.md, docs/platform-support.md,
  docs/github-action.md and the landing page ("Roadmap" listed EPSS/KEV, AI fix suggestions, the VS Code extension,
  the GitHub Action and SBOMs as "soon" though all five had already shipped; moved to "What ships today"). Extended
  the accessibility test suite to SubmitForm, RecentScans and the self-host page, which fixed two real ARIA bugs:
  `role="status"` on a `<ul>` broke its list semantics, and `aria-label` had no effect on three loading `<div>`s
  with no role. `pyproject.toml`, `web/package.json` and `extensions/vscode/package.json` now say `1.0.0`.

### Fixed
- The API's OpenAPI description said the `tools` field "defaults to all tools"; it defaults to the same five as
  the CLI (`api/schemas.py`, `api/main.py`). docs/github-action.md was missing the `sbom` input and `sbom-file`
  output that `action.yml` has had since Week 20.

### Changed
- **Landing-page motion:** headline words rise on load (pure CSS), hero and results numbers count up when first seen,
  feature cards fade in as they scroll into view, feature and diagram panels get a soft pointer spotlight, and a
  hairline shows reading progress. Dependency-free, CSP-safe (styles set through the CSSOM), and all of it is off under
  `prefers-reduced-motion`; the server output already shows the final values, so nothing depends on JS.
- **Performance (Week 25):** median scan of the 25-repository corpus went from 47 s to 6 s (whole corpus 1,235 s to
  338 s), OWASP Benchmark Semgrep scan 202 s to 30 s. Cause: Semgrep spent ~26 s per scan loading 337 rule files;
  they are now merged per language at image build time with rule ids unchanged (rebuild `bulwark/semgrep`).
  Semgrep and Trivy get 4 CPUs each (`ToolSpec.cpus`). Findings are identical except where the old run had lost
  some (below). Trivy's multi-scanner IaC slowness is upstream and not fixed. See docs/evaluation.md.

### Fixed
- Semgrep skips a rule/file after 5 s and still exits 0, so slow or CPU-starved runs silently lost findings (dvpwa: 5
  vs 169). Adapters can now return `warnings`; Semgrep reports timeouts in the tool status (`warnings`, also in the
  API `ToolStatus`) and on stderr in the CLI. The first corpus run's dvpwa figure was affected; the OWASP and Juliet
  results were rechecked and were not.

### Added
- **Consolidated evaluation doc (Week 25):** docs/evaluation.md and a benchmark table in the README.
- **Juliet, corpus and prioritization evaluation (Week 24):** `benchmarks/juliet` scores Semgrep on the Juliet Java
  suite per CWE with method-level ground truth (recall 23.8%, false-alarm 19.6%, `related` matcher; 24 CWEs,
  chunked scan because one scan exceeds the 900 s tool limit). `benchmarks/corpus` scans 25 pinned repositories:
  0 crashes in 94 tool runs, dedup 19.9% on vulnerable apps vs 1.3% on ordinary repos (first-run figures; corrected below in Week 25).
  `benchmarks/prioritize.py` compares top-K precision of risk score vs severity only on the OWASP Benchmark: ahead at
  every K but inside the confidence interval. EPSS/KEV/reachability ordering is not evaluated (no ground truth).
  See docs/evaluation-juliet-corpus.md.
- **OWASP Benchmark evaluation (Week 23):** `benchmarks/owasp` fetches the pinned corpus, scans it through the real
  sandbox runner one tool at a time, and scores per test case (recall, false-positive rate, precision, F1, and the
  Benchmark's TPR - FPR) with Wilson intervals, per category, under three CWE matchers published together. First
  result: Semgrep recall 88.2%, false-positive rate 43.7%, F1 77.0% (`related` matcher); strong on pattern-shaped
  weaknesses, near a coin flip on injection categories. No ensemble result: only one scanner analyses Java. See
  docs/evaluation-owasp.md for method and limits.

### Fixed
- `pom.xml` now marks a repository as having dependencies, so Trivy and OSV-Scanner run on Maven projects.
- The dedup benchmark runs the original five scanners again (it had picked up the tier-2 tools).

### Added
- **Tier-2 scanners (Week 22):** Grype (SCA), Checkov (IaC), gosec (Go SAST) and Dockle (container image lint),
  opt-in with `--tools` (`DEFAULT_TOOLS` is still the original five) and selectable in the web form. `bulwark scan-image
  REF` lints a local image. Each was run for real in its sandbox against a fixture; golden files are real output.
  Adding them tested the "about 40 lines per adapter" claim: it was about twice that until the repeated parts moved
  into `core/adapters/helpers.py`; the four adapters are now 42 to 48 lines and Bandit went from 75 to 33. Friction it
  exposed (output file names, `/tmp` size silently dropping gosec's taint rules, Dockle needing an image rather than a
  source tree) is in docs/adding-a-scanner.md.
- **THIRD_PARTY_LICENSES.md** generated by `scripts/gen-licenses.py` (Python and npm dependencies, scanners, data sets),
  with a CI job that fails on an unknown or network-copyleft license and keeps the regenerated file as an artifact.

### Fixed
- The compose file's floating `redis:7-alpine` tag had moved to Redis 7.4, which is RSALv2/SSPLv1, not open source.
  Pinned to 7.2 (ADR-0011). Found by the license inventory. **If your Redis container restarts in a loop after
  updating** ("Can't handle RDB format version 12"), run `docker compose rm -sfv redis && docker compose up -d`.

### Added
- **Observability (Week 21):** structured JSON logs with `scan_id` (and trace ids) on every line of a scan, including
  the parallel scanner threads; OpenTelemetry traces with one span per pipeline stage and per scanner (optional,
  export with `OTEL_EXPORTER_OTLP_ENDPOINT`); Prometheus metrics from the worker (scan and scanner outcomes,
  durations, findings, queue depth); and an optional `observability` compose profile with Prometheus, Grafana (a
  provisioned dashboard) and Jaeger. Verified with real scans: the trace shows the scanners running in parallel and
  every dashboard query returns data. Not viewed in a browser, so no screenshot yet. See docs/observability.md.

### Added
- **SBOM, signing and provenance (Week 20):** `bulwark sbom` writes a CycloneDX 1.6 SBOM from Syft (pinned by
  digest, same sandbox as every scanner; dev dependencies included; validated against the official CycloneDX
  schema in a test). `bulwark attest sign | provenance | verify` sign reports with cosign (key-based, container with
  no network, no transparency log) and produce an in-toto attestation of which Bulwark and scanner images
  (content hashes) made the artifact, with result counts and artifact digests. Verified for real: valid signatures
  verify; a tampered file, wrong key, wrong subject or wrong predicate type is rejected. The action gained an optional
  `sbom` input. Not done: keyless (GitHub OIDC) signing, signing inside the action, transparency-log entries. See
  docs/supply-chain.md; new threat T15.

### Added
- **Dogfooding and release prep (Week 19):** `.github/workflows/bulwark.yml` runs the action on this repository
  (blocks pull requests on new HIGH findings; reports on pushes). `.bulwarkignore` (with `--ignore-file`, counted
  in `stats.ignored_findings` and shown in the PR comment); in CI the ignore file is taken from the **base** commit
  so a change cannot hide its own findings. The action is now at the repository root (`uses: Rag2102/cyberimp@...`)
  as the GitHub Marketplace requires. `docs/releasing.md` lists the Marketplace steps (yours to run);
  the extension packages to a 21 KB `.vsix`. See docs/dogfooding.md for what the self-scan found.

### Fixed
- Scanning a directory that contains `node_modules`, a virtualenv or tool caches no longer fails on the size limit;
  those directories are skipped (lockfiles are still scanned). Found by scanning this repository.
- The extension's dev dependencies (vitest/vite/esbuild) upgraded: no known advisories remain in its lockfile.

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
