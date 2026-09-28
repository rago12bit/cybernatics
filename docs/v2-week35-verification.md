# Week 35 verification — onboarding, states, accessibility, validation (plan §28.2, §30.3, §31)

Honest record of what was built, run, and clicked through — for Week 35: the live scan screen,
every empty/partial/error/loading state's copy, an accessibility pass, and Playwright end-to-end
tests with visual regression for journeys J1 and J3.

## Live scan screen (§28.2)

- **A real elapsed-time header** (`components/ElapsedTime.tsx`) while a scan is queued or running,
  hydration-safe like `LocalTime`.
- **A real, honestly-scoped "progress so far" line**: `N of M scanners reported in, R raw findings
  so far`, using the live `tool_status[tool].findings` counts that already stream over the
  WebSocket/polling path.
- **What this deliberately does *not* claim**: the plan's own wireframe shows "2 critical issues
  found so far. You can start reviewing now. [Review]" while a scan is still running. Checked
  against the real backend and confirmed this isn't honestly buildable in one week without a much
  larger, riskier change: `core/pipeline.py` correlates and persists every `Finding`/`Issue` row
  in **one atomic step after every tool finishes** (`_run_scan_job`'s `correlate()` → `finalize()`
  → `add_findings()`), because cross-tool deduplication needs to see every tool's output at once to
  decide what's a duplicate — exactly the class of correctness problem Week 34's correlation-identity
  fix was about. Persisting per-tool findings incrementally and re-correlating live is real, valuable
  future work, not something to rush right after that fix. The progress line is explicit that its
  count is "raw" and not yet deduplicated, so it doesn't overclaim what's live.
- **Named, actionable failure copy**: a failed/timed-out scanner is now named directly ("trivy timed
  out, so its results may be incomplete") with a link to start a new scan — replacing a generic
  "some scanners failed or timed out" message. "Retry" in the wireframe is deliberately **not** a
  single-tool re-run: the backend has no such endpoint, and `ScanView` doesn't expose a reusable
  source URL/reference for uploads. "Start a new scan" is the same action stated honestly, not a
  fabricated one-click retry.
- **"No findings" now names how many scanners actually ran** ("5 scanners found no issues"),
  instead of a bare "No findings." — still not the wireframe's coverage-gap sentence ("Terraform
  files weren't scanned…"), which needs real gap detection this codebase doesn't have yet (Week 33's
  own verification doc already noted this honestly).

## State copy audit (§30.3)

- **Loading states are real skeletons now, not spinners on a blank page**: `ProjectsList`,
  `ProjectOverview`, `IssueDetail`, and `ScanPage` all showed bare "Loading…" text before this week;
  all four now render skeleton rows shaped like their final layout, reusing the existing `.sk`
  shimmer primitives from `app/globals.css` (already used elsewhere — `FindingGuidance`,
  `RecentScans`, `TokenGate`, `app/loading.tsx`).
- **"No projects yet"** copy tightened toward the plan's own wording ("Run your first scan to see
  it here. It takes about two minutes.") — not the literal "Connect a repository… [Connect GitHub]"
  text, since there's no GitHub-App-connect UI to link to yet (no per-user GitHub sign-in exists;
  same honest gap earlier weeks' verification docs already recorded).
- **Git-clone errors now lead with a plain-word summary**, not a raw git stderr string
  (`core/gitfetch.py`'s new `_friendly_clone_error()`): "Couldn't find this repository. Check the
  URL is correct." / "Couldn't clone this repository. Bulwark can only scan public repositories
  right now — make sure this one is public." The raw detail stays attached in parentheses, so
  nothing is hidden, just led with what happened and what to do next (§30.3's own stated principle).
  Two new backend tests reproduce both cases directly.
- **AI-unavailable copy**: already real before this week (`FindingGuidance.tsx`) — off entirely
  ("AI suggestions are off on this server…"), a degraded/failed call shown with its reason, and a
  rate-limit hit shown with "Reference guidance above still applies." The plan's example is a
  monthly *budget*; this codebase has a real per-minute/per-day rate limiter
  (`core/llm/limits.py`) instead of billing/budget tracking, so that's the honest equivalent
  actually implemented, not a gap this week introduced or fixed.

## Accessibility pass

**axe-core was already wired into `npm test`** (`tests/a11y.test.tsx`, `axe-core` in
`package.json`) from an earlier week — already effectively "in CI" via the `web` job's existing
`npm test` step, not a new thing this week added. What Week 35 did add: **axe coverage for every
screen built in Weeks 33-34 that had none** — `AppShell`'s screens weren't a gap (Week 33 verified
those live), but `ProjectsList`, `ProjectOverview`, `IssuesTable`, `IssueDetail` (including its
triage dialogs, opened, not just the closed state), and `ScanReport`'s new running/partial states
had zero automated a11y coverage before this week. That coverage **found two real bugs**, both fixed:

1. **The triage reason/expiry inputs had only placeholder text, no `<label>`** — a real WCAG
   failure (placeholder text is not a reliable accessible name), only caught because the new test
   opens the dialog rather than checking the closed state. Fixed in both `IssueDetail.tsx` and
   `IssuesTable.tsx`'s (bulk) triage dialogs.
2. **The new virtualized Issues table had zero table/grid ARIA semantics** — a `<div>`-based
   virtualized grid (real `@tanstack/react-virtual`, can't use a native `<table>` with
   absolute-positioned rows) with no `role="table"/"row"/"cell"/"columnheader"` at all, invisible to
   a screen reader as tabular data. Fixed with the standard ARIA grid pattern.

**A real, manual keyboard-only walkthrough** (not just automated checks) against a disposable local
server, driven by hand in the built-in browser — sign-in, submitting a scan, opening a finding, and
closing it — found and fixed two more real issues:

3. **Checkboxes had no visible focus indicator at all.** `app/globals.css`'s
   `input:focus-visible, select:focus-visible { outline: none; border-color: var(--teal); }` is a
   fine treatment for a bordered text input (the border-color change is the focus indicator) but a
   **native checkbox has no CSS border box for that to repaint** — removing its native outline left
   nothing in its place. Confirmed via `getComputedStyle` before (`outlineStyle: "none"`) and after
   (`outlineStyle: "solid"`, `matches(':focus-visible')`). This affects every checkbox in the app:
   the old scan report's scanner-selection checkboxes and the new Issues table's row-select
   checkboxes both share this one global rule.
4. **The issue detail page had no heading at all** — the title was a `<span>`, not an `<h1>`, so a
   screen-reader user navigating by headings (a standard pattern) had nothing to land on. Fixed by
   making it a real `<h1>` (CSS specificity meant no visual change was needed).

**What this doesn't claim**: no VoiceOver (or any real screen reader) testing — no such tool is
available in this environment, and simulating one honestly isn't possible; axe-core plus a real
keyboard walkthrough catches a meaningful, real subset of the same issue class (as items 1-4 above
show), but isn't the same thing. Flagged here explicitly rather than silently skipped, the same
pattern used for this project's other real capability gaps.

## Playwright end-to-end tests + visual regression (§31)

No Playwright setup existed before this week. Built from scratch:

- **`scripts/e2e_server.py`** (new): a disposable, self-seeding Bulwark API server for CI, since the
  `web`/`e2e` jobs have no Docker, Postgres, or Redis. Runs the **real** `api.main.create_app` and
  **real** `core.persistence.repo` functions against a real file-backed SQLite database (WAL mode —
  see below for why not in-memory), so every HTTP request Playwright makes runs real application
  code. Only two things a scanner-less, worker-less job genuinely can't do are faked, both marked
  in the module's own docstring: running actual scanner containers (a fake "worker" thread marks
  the scan running, then completed, writing real `Finding` rows through the same
  `sync_issues_for_scan`/`add_findings`/`finish_scan` calls the real pipeline uses — the frontend
  cannot tell the difference), and Redis pub/sub for live WebSocket updates (an empty subscriber, so
  the frontend correctly falls back to its own real polling path).
- **A real bug found building this fixture, not a hypothetical**: the first version used
  `sqlite://` in-memory with `StaticPool` (matching `tests/conftest.py`'s pattern) — fine for
  pytest's single-threaded-per-test usage, but this server genuinely serves concurrent requests
  (uvicorn's thread pool plus the fake worker's own background threads), and `StaticPool`'s one
  shared raw connection can't safely interleave transactions from more than one of them. Surfaced as
  `sqlite3.OperationalError: cannot commit transaction - SQL statements in progress` — but only
  under **real parallelism** (multiple Playwright workers in a Linux container; serial runs on this
  Mac never hit it). Fixed by switching to a real file-backed database with WAL mode and a busy
  timeout, SQLite's own documented answer to concurrent access.
- **`playwright.config.ts`**: two `webServer` entries (the Python API on port 8811, `next dev` on
  3911 — both deliberately far from any port the real dev stack uses), `NEXT_PUBLIC_API_URL` wired
  to the fake API.
- **`web/next.config.mjs`**: added `allowedDevOrigins: ["127.0.0.1", "localhost"]` — Next 16 blocks
  cross-origin dev-server requests by default, and Playwright drives the app via `127.0.0.1`.
- **`tests-e2e/journeys.spec.ts`**: J1 (sign in → submit a scan → live status transitions → a real
  verdict) and J3 (filter, open an issue, mark not-a-risk with a reason, j/k between issues, accept
  risk with an expiry, reopen) — all against real HTTP, real SQLite persistence, real
  triage/audit-log writes. **J2 is not covered**: its literal target ("review the verified fix, open
  a pull request") depends on a verified-fix/PR-creation feature that doesn't exist anywhere in this
  codebase yet (confirmed by searching for it) — Phase 9/10 territory, not something to fake a test
  for. Plan §26.2's time targets (J1 under 2 minutes, J3 100 issues in 30 minutes) describe a
  person's pace, which a scripted test can't assert; these tests assert the flow completes with no
  unnecessary step and no dead end instead.
- **A real test-isolation bug found and fixed**: the first version of these tests reused one fixed
  repo URL across every test. `sync_issues_for_scan`'s fallback-key matching (Week 34's correlation
  work) correctly recognized the *same* finding recurring across scans of the same asset and reused
  its existing Issue — triage state included — which is exactly what it's supposed to do. The bug
  was the test's assumption that each test got an independent, untouched issue queue. Fixed with a
  distinct fake repo path per test (`journeys.spec.ts`'s `uniqueRepoUrl()`), giving each test its
  own asset for real, not a coincidence of run order.
- **`tests-e2e/visual.spec.ts`**: full-page screenshots of the project overview, issues table, and
  issue detail screens. **Linux baselines, not the ones this Mac's browser would generate**:
  Playwright encodes the OS into the snapshot filename on purpose (font rendering differs), and CI
  runs `ubuntu-latest`, so macOS-generated baselines would fail on the very first real CI run.
  Generated and — critically — **independently re-verified against**, not just written by, the
  official `mcr.microsoft.com/playwright:v1.63.0-jammy` Docker image (matching the installed
  Playwright version exactly), run fully self-contained (its own `npm ci` and `pip install`, so
  nothing from this Mac's compiled native modules leaks in). Two more real flakiness sources found
  by actually re-running the comparison after generating a baseline, not assumed stable:
  - The per-test unique repo URL (needed for isolation, see above) is *rendered on screen* as the
    project's label, so different `Date.now()`-based text between the baseline run and any later
    run guaranteed a diff. Fixed for the visual spec specifically with fixed, deterministic labels
    (one literal per test — test isolation doesn't need to survive re-running the whole suite the
    way journey-test isolation does).
  - Three dates (`triage_expires_at`, `first_seen_at`, and each history entry's timestamp in
    `IssueDetail.tsx`) were rendered as plain text, not `<time>` elements, so they weren't covered
    by the existing `mask: [page.locator("time")]`. Fixed by making them real `<time
    dateTime=...>` elements — a genuine semantic/accessibility improvement on its own, and it means
    the existing mask now covers them for free. (The finding id in the topline — a real, freshly
    generated UUID every scan — is masked directly by selector instead, since it's supposed to
    differ every run.)
  - Confirmed stable across three independent full re-runs against the committed baselines,
    including one exactly matching how CI actually invokes it (`CI=true`, default parallel workers).
- **`.github/workflows/ci.yml`**: new `e2e` job (Python + Node, no scanner images) running
  `npm run e2e`; uploads the Playwright HTML report as an artifact on failure.

## Follow-up usability study — deferred

Plan §32's Week 35 line item is a follow-up study with five *new* participants on the redesign,
publishing before-and-after SUS results against Week 31's baseline. **Week 31's baseline study
itself was never run** (still deferred pending real participant recruitment, as that week's own
verification doc already recorded) — there is no "before" to compare a "after" against yet, so a
before-and-after publication is doubly not possible right now, not just deferred once. Recruiting
and running a real study with real people isn't something to fabricate or simulate; both studies
remain a real, separate task for when participant recruitment is actually in scope.

## Verification

- Backend: `ruff check .`, `black --check .`, `mypy` clean. Full suite: **871 passed, 2 skipped**
  (869 + 2 new `core/gitfetch.py` regression tests for the friendlier clone-error copy).
- Web: `npm run typecheck`, `npm test` (**145 passed**, up from 137 — the new `ElapsedTime`/
  `ScanReport` tests and 14 new/extended a11y tests), `npm run build`, `npm run build-storybook` —
  all clean from the actual CI commands.
- `npm run e2e`: **7 passed** (4 journeys + 3 visual regression), verified independently in the
  official Linux Playwright Docker image, including a run shaped exactly like the new CI job
  (`CI=true`, parallel workers).
- A real, manual keyboard-only walkthrough in the built-in browser (not just automated checks),
  documented above under Accessibility, found and fixed two real bugs beyond what axe-core alone
  caught.
