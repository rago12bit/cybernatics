# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com), versions follow
[SemVer](https://semver.org).

## [Unreleased]

### Added
- **Week 36 — Incremental scanning (plan §20.1, §36, §28.6):** a content-addressed result cache
  (`core/cache.py`, `bulwark scan --cache-dir`) — file-local tools (Bandit, Semgrep, Gitleaks)
  cached per file, repo-wide SCA tools (Trivy, OSV-Scanner) cached as a whole, keyed on the files
  that actually drive their output. Wired into the GitHub Action with `actions/cache` so
  `compare-base`'s base-commit scan is cheap on repeat runs, not a second full scan every time.
  Measured on NodeGoat: 71.2s cold vs. 19.6s warm (3.6x), under the plan's 60-second target — full
  methodology, and an honest explanation of what the remaining warm-scan time is actually spent on
  (cross-tool correlation, not tool execution — unrelated to this week's cache), in
  `benchmarks/README.md`. A new read-only `core/issues.py::classify_for_pr()` gives PR-triggered
  scans "new in this PR" without mutating the asset's real Issue history (`sync()`'s
  `fixed_issue_ids` logic is wrong for a diff that only touches some files); this surfaced and fixed
  a real bug where a PR scan's Asset was keyed on its own display label instead of the repository's
  URL, so it never actually shared the repository's Issue history at all. New scan comparison screen
  (`/app/projects/[id]/compare`, `GET /scans/{id}/compare`): new/fixed/reintroduced/unchanged issues
  between any two of a project's scans — shown against each scan's label, finish time and PR number,
  not a full commit range, since `Scan` doesn't capture a resolved commit SHA yet (noted honestly
  rather than threaded through its ten call sites this week). VS Code extension: optional
  `--cache-dir` on every scan, and a new "Scan (new since base branch)" command comparing HEAD
  against a throwaway worktree of the merge-base. Full account in
  `docs/v2-week36-verification.md`.
- **Week 35 — Onboarding, states, accessibility, validation (plan §28.2, §30.3, §31):** the live
  scan screen now shows real elapsed time and an honestly-labelled "raw, not yet deduplicated"
  progress line while a scan runs (real cross-tool correlation only ever happens once, after every
  tool finishes — see `docs/v2-week35-verification.md` for why streaming reviewable results earlier
  isn't safely buildable in one week), plus named failed-scanner copy with a real "start a new scan"
  action. Every bare "Loading…" screen (`ProjectsList`, `ProjectOverview`, `IssueDetail`,
  `ScanPage`) is now a real skeleton, not a spinner on a blank page. j/k now moves between issues on
  the issue detail page (`lib/issue-nav.ts`), completing J3 — a gap Week 34 explicitly flagged.
  First Playwright end-to-end setup for this project: `scripts/e2e_server.py` (a disposable,
  self-seeding backend fixture running the real FastAPI app against a real file-backed SQLite
  database — no Docker/Postgres/Redis needed), real tests for J1 and J3 (J2 honestly not covered:
  no verified-fix/PR-creation feature exists yet), and visual regression snapshots with Linux
  baselines independently verified in the official Playwright Docker image. Extended the existing
  `axe-core` a11y suite (already running in CI from an earlier week) to cover every Week 33/34
  screen that had none, which found and fixed two real accessibility bugs (unlabelled triage
  dialog inputs; the new virtualized Issues table had zero ARIA table semantics); a real manual
  keyboard walkthrough found two more (checkboxes had no visible focus indicator at all; the issue
  detail page had no heading). The Week 31 baseline usability study still hasn't been run, so
  Week 35's own follow-up study — a before-and-after comparison — stays deferred; full account in
  `docs/v2-week35-verification.md`.

### Fixed
- **Cross-tool/cross-rule correlation identity (`core/correlation/engine.py`'s `fingerprint()`,
  `core/issues.py`'s `fallback_key()`):** two genuinely different findings could silently share one
  tracked Issue (ADR-0012) whenever their snippet gave nothing distinguishing to hash — either no
  snippet at all (Trivy's Dockerfile checks: `DS002` "runs as root" and `DS026` "no HEALTHCHECK" on
  the same line) or a real but non-unique snippet (Trivy's Terraform checks quote the whole resource
  block for every rule that fires against it — ten different misconfigurations, one snippet).
  Confirmed against this repo's own real golden scan data and this session's live Postgres
  deployment, where it meant triaging one Dockerfile finding silently also dismissed an unrelated
  one. Fixed by always folding the finding's rule id(s) into both functions' hash; never affects
  cross-tool merging of the *same* defect, which `correlate()` already decides via other signals
  before either function runs. Migrated and re-verified against real Postgres; see
  `docs/v2-week34-verification.md`.

### Added
- **Week 34 — Issues experience (plan §28.3, §30.4, §32):** a virtualized issues table
  (`components/IssuesTable.tsx`, real `@tanstack/react-table` + `@tanstack/react-virtual`, not a
  hand-rolled scroller) with severity/triage filters, sort, bulk selection, and saved views
  (`localStorage`-backed, no per-user identity yet — see the verification doc for why); an issue
  detail screen (`components/IssueDetail.tsx`) with the why-ranked panel reused from Week 33, a
  taint-path stepper that's honestly "static until Phase 9 supplies real paths" (one real step, the
  finding's own location — never a fabricated multi-hop path), a real Shiki code view, and a real
  event history built from the tamper-evident audit log. Triage itself: `not_a_risk` (reason
  required) and `accepted` (expiry required, and it reappears in the active queue automatically once
  the expiry passes) both write to the audit log, exactly as §28.3 specifies; `reopen` undoes either.
  New `GET/POST /assets/{id}/issues...` endpoints (migration `0009_issue_triage.py`) reuse the
  existing scan-findings query machinery rather than introducing a second source of truth. Novice
  and expert mode (`design-system/mode.tsx`, §30.4): a real, working, `localStorage`-persisted
  toggle for row density, the plain-language explanation's default state, and rule-id visibility —
  explicitly not the sign-in landing page, since no per-user sign-in flow exists yet. 13 new backend
  tests plus 2 correlation regression tests, 869 passed overall; live-verified end to end in the
  browser against a disposable local server, which caught and fixed a real hardcoded-plural bug
  along the way. Full account, including the real pre-existing correlation bug found while building
  this, in `docs/v2-week34-verification.md`.

### Added
- **Week 33 — App shell and project overview (plan §27, §28.1, §30.1, §32):** the first real
  screens built on Week 32's design system — additive at the route level (`/app/projects`,
  `/app/projects/[id]`), nothing under the existing `/app` screens changed. New `GET /assets` and
  `GET /assets/{id}/overview` endpoints (`api/schemas.py`, `core/persistence/repo.py`) turn the
  existing `Asset`/`IssueRow` data (ADR-0012) — already the plan's §27 "Project" identity under a
  different name — into a real verdict, risk-sorted fix-first queue, since-previous-scan
  fixed/new/returned counts, an open-issue trend, and what the latest scan did (and didn't) cover;
  6 new tests, 859 passed overall. A nav shell (`components/shell/AppShell.tsx`) adds breadcrumbs, a
  project switcher, a command palette (⌘K, filters and navigates by project name), and a shortcut
  help dialog listing the full §30.1 keymap with rows honestly marked "reserved" where they belong
  to the not-yet-built issues table (Week 34). The "why it's ranked" component (C8) ships as
  `design-system/why-ranked.tsx`, reused as a tooltip on every fix-first row, carrying the same real
  `risk_factors` text `core/risk/score.py` already computes. Caught two real bugs during a live
  click-through against a disposable local test server (never the real API token): a `Tooltip`
  crash from a missing `TooltipProvider`, and a hardcoded English plural — both fixed and
  re-verified live, not just re-built. Also caught, before any real page combined the two
  stylesheets: Week 32's design tokens (`--muted`, `--sev-*`, `--font-sans`/`--font-mono`,
  `--ease-out`) silently collided with the existing app's own theme names — invisible in Storybook's
  isolated iframe, would have corrupted one theme or the other the instant both loaded on one page.
  Fixed by prefixing every design-system token with `--ds-`. See `docs/v2-week33-verification.md`
  for what's real, what's a documented simplification (e.g. "since previous scan," not a literal
  calendar week), and what's explicitly not attempted (an org switcher, PR-gate status, "not
  scanned: X" gap detection — no fabricated look-alikes).

### Added
- **Week 32 — Design system (plan §29, §32):** the tokens, shapes, and primitives Weeks 33–35 will
  apply screen by screen — additive only, the live app's own theme is untouched this week (see
  `docs/v2-week32-verification.md` for why). `web/design-system/tokens.css`: the plan's exact §29.2
  color tokens (ink/muted/surface/raised/rule/brand) in light and dark, the §29.3 type scale, and
  §29.4's hierarchical radius (2px inputs/tags, 6px panels/dialogs, 0 tables). Five severity shapes
  — filled octagon/triangle/diamond/circle/ring, never color alone — with the calm-by-default
  outline variant for an unreachable critical (`design-system/severity.tsx`). A new
  `tests/design-tokens-contrast.test.ts` checks all 8 text tokens against both surfaces in both
  themes against WCAG AA (18 assertions, all passing) — the plan's own "CI script ... fails the
  build on any regression," now wired into the `web` CI job. Five Radix primitives
  (Button/Tooltip/DropdownMenu/Dialog/Tabs) restyled entirely from the tokens, with Storybook
  stories exercising all their variants (`npm run build-storybook`, now also a CI step). Self-hosted
  IBM Plex Sans and JetBrains Mono via `@fontsource` (no Google Fonts request), ligatures off on the
  mono face. Live-testing the Storybook theme toggle by hand caught a real bug before it shipped:
  the dark-mode CSS keys off `:root[data-theme]`, but the toggle was first wired to a wrapper `<div>`
  instead of `document.documentElement`, so it silently did nothing — fixed and re-verified.

### Added
- **Week 31 — UX research (plan Phase 8, §32):** a heuristic evaluation of the current live web app
  against Nielsen's ten heuristics, done by actually walking the running product rather than reading
  intent — found a real sync bug (the "Top 10 by risk" widget's list doesn't track `j`/`k`
  keyboard navigation the way the main findings table does, confirmed live) and a real KB
  content-quality bug (generic service-mesh/Istio guidance shown for an AWS security-group
  finding). Journey maps for J1–J5 against what's actually built today, not the plan's v2-aspirational
  target — J1 still has no GitHub sign-in (API-token paste instead), J3's filter/`j`/`k` half works
  but its risk-acceptance half doesn't exist yet (ADR-0012), J4/J5 are essentially unbuilt. Two
  overview layout sketches (a two-column direction matching the plan's own §28.1 wireframe, and a
  single-column alternative), evaluated against the plan's §25 principles and against the security
  engineer/team-lead personas (§26.1) — the two-column layout wins on progressive disclosure and
  keyboard-triage layout stability, recommended as the default with the single-column shape as a
  narrow-viewport fallback, not a discarded alternative. A ready-to-run baseline usability study
  protocol (task list reframed to what the current product can actually support, the real 10-item
  SUS questionnaire, the plan's own confidence question) — **not yet run**: this project has no
  fabricated participant data; the actual 5-person baseline study remains a pending, deliberately
  deferred piece of work for whenever real participants can be recruited.

### Added
- **Week 29/30 backfill — scoped API tokens, tamper-evident audit log, automated tenant-leak test
  (ADR-0018, ADR-0019):** reading the plan's actual §19.1–§19.3 text fresh surfaced that this
  session's earlier "Week 29"/"Week 30" work had drifted from the plan's real scope for those
  weeks (no scoped tokens, no CI-run cross-tenant test, no audit log; the GitHub App was actually a
  Week 29 sub-item, not Week 30's own "audit log" deliverable). This closes those specific gaps:
  - `bulwark_<hex>_<checksum>` scoped tokens (`core/tokens.py`), hashed at rest, with real
    `scans:read`/`scans:write` scope enforcement; a scoped token's org is authoritative and
    `X-Bulwark-Org` is ignored for it — the concrete fix for the exact "a caller can claim any org
    id" limitation ADR-0013 documented. `bulwark token create/list/revoke` (CLI-only; no
    self-service API yet, no per-user identity to hang one off).
  - A hash-chained, tamper-evident audit log (`core/audit.py`, `core/audit_rekor.py`):
    `bulwark audit verify` walks and recomputes the whole chain; `bulwark audit checkpoint` signs
    the current head and publishes it to Sigstore's Rekor (key-based signing with real Rekor
    upload, not keyless — no OIDC identity provider integration exists for a long-running
    self-hosted server). Logs `token.created`/`token.revoked` and
    `installation.created`/`installation.deleted` today; most of the plan's own example audit
    actions (role changes, triage, fix approvals) don't exist as features yet.
  - The automated cross-tenant leak test ADR-0013 committed to but never wired into CI: a new
    `tenancy-rls` GitHub Actions job with its own real Postgres service, running on every pull
    request against real Row-Level Security.
  Two real bugs found and fixed, both the same root cause: SQLite (and potentially a
  differently-configured Postgres session) hands back a naive `datetime` even for a
  `DateTime(timezone=True)` column, which crashed a token-expiry comparison and — more
  seriously — silently shifted timestamps inside the hash chain itself, meaning `verify_chain`
  would have reported a genuinely untampered chain as broken on any host not itself in UTC. Fixed
  by treating a naive value as UTC (every timestamp this codebase writes already is); confirmed
  fixed with a live tampering test against real Postgres. Explicitly deferred: the full
  Organization/project/role permission matrix and GitHub OAuth/passkey/TOTP sign-in (both need real
  human identity, which doesn't exist yet, and are security-sensitive enough to deserve their own
  pass), the custom Gitleaks rule for Bulwark's own token format (needs extending the sandboxed
  runner's mount mechanism), and an actual live Rekor checkpoint publish (a permanent, public,
  third-party write, done only with explicit confirmation). Full writeup:
  docs/v2-week29-backfill-verification.md.

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
- **Week 29 — multi-tenancy via Postgres Row-Level Security, implemented (ADR-0013):** `Organization`
  model; `Asset`/`Scan` gained `org_id` (`Asset` identity is now scoped to `(org_id, source_type, key)`
  so two orgs scanning the same public repo never share Issue history); RLS policies on `assets`,
  `scans`, `tool_runs`, `findings` and `issues`; a non-superuser `bulwark_app` Postgres role that the
  API and worker now connect as (the table-owning role is a superuser on this project's Postgres image,
  and `FORCE ROW LEVEL SECURITY` is a documented no-op against a superuser regardless of policies — the
  role split is load-bearing, not cosmetic). A caller selects scope with an optional `X-Bulwark-Org`
  header; absent, every pre-Week-29 client keeps behaving exactly as before. No org-management API yet
  (matches the plan's own later identity work) and no real per-org authentication — the single shared
  bearer token still gates API access, only scope selection is new. Verified live: full downgrade/
  upgrade cycle of the migration, direct role-by-role proof that a superuser bypasses RLS while
  `bulwark_app` fails closed with no org set, and real cross-org HTTP requests through a real scan the
  worker ran end to end. Caught and fixed three real bugs along the way, the most significant being
  that `SET LOCAL`-style scoping doesn't survive a mid-request commit (`create_scan` commits twice in
  one session) and that the worker — connecting as the same non-bypass role — never had an org context
  at all, silently rejecting every write until `org_id` was threaded through the dispatch path from the
  API's enqueue call. Full writeup: docs/v2-week29-verification.md.
- **Week 30 — GitHub App integration, implemented (ADR-0017):** app-level RS256 JWT auth and cached
  installation tokens (`core/github_app.py`); a webhook receiver (`POST /integrations/github/
  webhook`) verifying GitHub's HMAC signature and handling `installation` (created/deleted) and
  `pull_request` (opened/synchronize/reopened) events; a `GithubInstallation` model mapping each App
  installation onto a Bulwark `Organization` (ADR-0013) — installing the App is, for now, how a
  tenant gets created, since there's no org-management API yet. `core/gitfetch.clone_repo` gained a
  tightly-restricted `ref` parameter (`refs/pull/<n>/head` only) so a PR-triggered scan looks at the
  PR's actual head commit, not the default branch, keeping every SSRF/hardening flag on all four git
  invocations the ref path needs (init/remote/fetch/checkout) instead of one. PR-triggered scans
  deliberately don't feed the asset's Issue lifecycle (ADR-0012) — previewing a PR that might never
  merge would corrupt fixed/reintroduced detection for the real branch. Results post back as a PR
  comment, reusing the existing GitHub Action's `upsert_comment` rather than a second HTTP client.
  Verified live: real RS256 crypto, the full webhook path against the real API and Postgres (including
  real RLS), and — using an actual public GitHub pull request (`octocat/Hello-World#11297`) — the
  `ref`-based clone against real GitHub, fetching the PR's real head commit. Explicitly NOT verified
  live: an installation token actually accepted by GitHub and a comment actually posted, since no
  GitHub App is registered yet — that's a user action, not something done unilaterally. The
  best-effort PR-comment path was proven to fail gracefully (logged, scan still `completed`) when App
  credentials are absent. Two real bugs found and fixed: `org.id` read before a flush had assigned it
  (same category as Week 28's backfill bug), and an RLS design that would have made resolving a
  webhook's own org context require already knowing it — fixed by giving `github_installations` no
  RLS policy at all, by design. Full writeup: docs/v2-week30-verification.md.

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
