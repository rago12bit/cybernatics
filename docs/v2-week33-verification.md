# Week 33 verification — app shell and project overview (plan §27, §28.1, §30.1, §32)

Honest record of what was actually built, run, and clicked through — not just written — for Week
33: navigation (organization/project switchers, breadcrumbs), a command palette with keyboard map
and shortcut help, the project overview screen, and the "why it's ranked" component (C8) reused.

## What "project" means here

The plan's IA (§27) has `Organization → Projects → Project`. This codebase already has exactly
that identity under a different name: `Asset` (ADR-0012) — one row per distinct repository,
org-scoped (ADR-0013), with its issues tracked across every scan. No new table was added; `/assets`
and `/assets/{id}/overview` are new *read* endpoints over data that already existed.

## Backend — new, real aggregation over existing data

`core/persistence/repo.py` gained `list_assets`, `get_asset`, `latest_scan_for_asset`,
`previous_scan_for_asset`, `since_previous_scan_counts`, and `open_issue_trend`. None of them are a
new source of truth:

- **Fix-first queue**: the same `query_findings(sort="risk")` the scan-scoped "Top 10 by risk"
  widget already used, just called against the asset's latest completed scan.
- **Verdict count**: of that same risk-sorted list, how many are critical/high *and* not positively
  marked unreachable (`scoring.reachable is not False`) — the plan's calm-by-default rule (§29.2):
  an unreachable critical still appears in the list with its "not reachable" tag, but doesn't
  inflate the headline count.
- **"Since previous scan"**: not a literal 7-day window. `new`/`returned` come straight from
  `issue_counts` (already computed at sync time from ADR-0012's issue states); `fixed` is counted
  directly as issues that flipped to `fixed` after the previous scan's `finished_at`. Named
  `since_previous_scan` in the API; the UI still uses the plan's own wireframe wording ("Since
  previous scan") since for a roughly-weekly scan cadence the two coincide.
- **Open-issue trend**: reconstructed per historical scan from `IssueRow.first_seen_at`/`fixed_at`
  (nothing snapshots this today), not stored separately.
- **What was scanned**: the latest scan's real `tool_runs` (tool, status, finding count). Detecting
  *gaps* — "not scanned: Terraform" the way the plan's own wireframe shows — would need repository
  language/content detection this codebase doesn't have yet; that's explicitly not attempted here
  rather than faked.
- **PR gate status**: also not attempted. There's no real policy engine yet (that's Week 39,
  "Policy-as-code" per the plan itself) — a look-alike "passing" indicator not backed by real policy
  evaluation would be worse than omitting the section.

**`tests/unit/test_project_overview.py`** (6 tests, all passing against real SQLite, run through
the actual API via `TestClient`, not by calling repo functions directly) exercises: a fresh
single-scan project (everything "new"), a second scan with a real fixed/new/returned mix, org
isolation (404, never 403 — ADR-0013), and auth/scope enforcement. Building this test caught two
real bugs in the *test fixtures themselves* before they could mask a real bug in the endpoint:
`core.issues`' fallback-key matching (used when a finding's primary fingerprint is new) treats an
empty or generically-token-normalized snippet as equal across unrelated findings, silently merging
them onto the same Issue — the fix was giving each test finding a placeholder-marker snippet (the
same one production code uses for a redacted secret), which makes `fallback_key()` return `None`
outright and match purely on the fingerprint the test controls. Full backend suite: **859 passed, 2
skipped** (`pytest`), `ruff`, `black --check`, and `mypy` all clean on every changed file.

## A real collision, caught before any real page loaded

`design-system/tokens.css` (Week 32) originally defined `--ink`, `--muted`, `--surface`, `--raised`,
`--rule`, `--brand`, `--sev-critical/high/medium/low/info`, `--font-sans`, `--font-mono`, and
`--ease-out` directly. `app/globals.css` — the existing app's own theme — already defines `--muted`,
all five `--sev-*` names, and (via `next/font` on `<html>`) `--font-sans`/`--font-mono`, each with
**different values**. Storybook renders each story in its own isolated iframe with no root layout,
so this was invisible there through all of Week 32. The moment a real page loads both stylesheets at
once — which is exactly what a project-overview screen inside the existing Next.js app does — the
last one in cascade order would have silently overwritten the other's values, corrupting either the
old theme's severity colors and fonts, or the new one's, depending on load order. Caught by actually
wiring the design system into a real route rather than assuming Storybook's isolation would hold
forever; fixed by prefixing every design-system custom property with `--ds-` (`design-system/`,
`.storybook/preview.tsx`, and `tests/design-tokens-contrast.test.ts` all updated), re-verified with
`npm run typecheck`, `npm test` (137 passed), `npm run build`, and `npm run build-storybook`, all
clean afterward.

## Frontend — built, then actually clicked through, not just built

`components/shell/AppShell.tsx` (nav bar: brand, breadcrumbs, project switcher, ⌘K, ?),
`ProjectsList.tsx`, `ProjectOverview.tsx` (Layout A from the Week 31 sketch, collapsing to Layout
B's stacked shape below ~900px per that write-up's own recommendation), and `why-ranked.tsx`'s
`WhyRankedTrigger` (a tooltip carrying the finding's real `risk_factors` text, C8: "a score without
a reason does not get trusted") at `/app/projects` and `/app/projects/[id]`.

To verify this for real without ever typing a credential into the browser for anything but a
disposable local test instance: a throwaway FastAPI server (SQLite, a freshly `secrets.token_hex`-
generated test token — never the user's real `BULWARK_API_TOKEN`) was started on `localhost` and
seeded with two realistic multi-tool scans, then driven by hand in the built-in browser:

- Signed in with the generated test token (this session's own, on a disposable localhost server —
  never the user's real credential).
- **Projects list** rendered both seeded projects with real open-issue counts and status.
- **Project overview** rendered the verdict ("2 issues put this project at real risk"), a risk-sorted
  fix-first list with real severity shapes and locations, "Since previous scan: 0 fixed · 3 new · 0
  returned," and "What was scanned" reflecting the real tool statuses (including Checkov's real
  "skipped" state) — this caught two real bugs before either shipped:
  1. **`Tooltip must be used within TooltipProvider`** — the app crashed to its error boundary on
     first load. `WhyRankedTrigger` uses the Radix Tooltip primitive, but nothing wrapped the real
     app's shell in a `TooltipProvider` (only Storybook's preview decorator did). Fixed by wrapping
     `AppShell`'s render tree in one.
  2. **"1 findings"** — a hardcoded plural in the "what was scanned" line. Fixed to pluralize
     correctly; re-verified live (both "1 finding" and "3 findings" render correctly).
- **Command palette** (⌘K): opened, typed "checkout" to filter down to one project, pressed Enter,
  navigated to that project's real overview — a real, working keyboard-driven flow, not a mock.
- **Shortcuts dialog** (?): opened, shows the full §30.1 keymap; rows genuinely wired on this screen
  (⌘K, ?, Esc) are visually distinguished from rows honestly marked "Not on this screen yet" (j/k,
  x, f, n, a, g-then-i — all reserved for the issues table, Week 34). Esc closed it.
- **The why-ranked tooltip**: hovering a fix-first item's title showed its real
  `scoring.risk_factors` text ("Flagged by 2 scanners, confidence 80%") — confirmed live, not just
  that the component compiles.

All throwaway server state (SQLite db, work directories, the two dev processes) was torn down after
verification; nothing from it is part of the committed change.

## What Week 33 does not claim

- **Organization switcher**: the IA's top level (`Organization → Projects`) isn't built — there's
  still no multi-org membership/identity model for a person to switch between (the plan's own
  Organization/role work is explicitly deferred, noted in earlier weeks' verification docs). The
  project switcher is real; an org switcher would need real org membership first.
- **Command palette scope**: only jumps to a project by name today. Issue search, settings, and
  other actions the plan's §27 sidebar lists arrive as those screens get built (Weeks 34-35), not
  invented now as dead menu items.
- **j/k and the rest of the issues-table shortcuts**: deliberately not wired on this screen. The
  existing scan report's `FindingsTable.tsx` already has its own j/k handling, scoped to that table
  — the Week 31 heuristic evaluation found a real desync bug where the "Top 10 by risk" widget
  doesn't share it. Half-wiring j/k onto this screen's fix-first list would risk recreating exactly
  that bug pattern; the real fix is unifying keyboard navigation once, in Week 34's issues
  experience, not here.
- **"Not scanned: X" gap detection** and **PR gate status**: both omitted rather than faked, for the
  reasons given above.
