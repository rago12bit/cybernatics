# Week 74 verification: the third usability study's automated half (plan §58)

The plan's Week 74 row:

- **Study with five security leads or pen testers on J6–J10.** **Not run.** It needs five real
  people. Everything a moderator needs is ready: [ux-study-v3-protocol.md](ux-study-v3-protocol.md)
  (the script, with tasks, hints and targets), `scripts/ux-study-seed.py` (the same scenario for
  every participant, through the public API) and `scripts/ux-study-score.py` (SUS and time on task
  into [ux-study.md](ux-study.md)). The two earlier studies were never run either, and ux-study.md
  says so. **M16 (`v2.5.0`) waits for the study.**
- **Fix the top problems found.** The study's are still to come. Writing the journeys as tests found
  eight, fixed below.
- **Playwright tests for J6–J10; visual regression for every new screen.** Done, and axe-core now
  runs in the real browser too (§58: "axe-core in CI").

## The journeys (web/tests-e2e/journeys-v3.spec.ts)

Each runs on the real app against the real API. scripts/e2e_server.py stands in only for what the
CI job cannot reach, and now also for the parser sandbox (no Docker), the advisory feeds (two real
OSV records are stored at start-up) and GitHub's Issues API (in memory).

| Journey | What the test does |
|---|---|
| J6 Import a report | Uploads a real Nessus CSV export to a project. The preview names the format and shows 29 new and nothing closed; nothing is saved. Import says "Imported: 29 new, 0 reopened, 0 closed". The project's Issues list shows them. |
| J7 New-CVE morning | The project has an SBOM with log4j-core 2.14.1 and GitHub ticket settings. The test searches `log4j-core` in Components and presses Enter at once, opens CVE-2021-44228 from the result, and sees the project with 2.14.1 → 2.15.0. It creates the grouped Issues, sees a ticket filed, and checks the Issue's ticket is on `acme/security`. |
| J8 Risk acceptance | The existing test, now titled J8: the expiry is required, another person (their own token, their own browser) approves, and the acceptance can be ended early. |
| J9 Pen test | Creates an engagement, starts testing, and records five findings, each by CVSS 4.0 vector with route, steps, impact and recommendation. It moves to reporting, closes with a summary, downloads the Markdown report and finds all five plus the summary in it. |
| J10 Monthly report | Builds a report from the weekly template, renames it and makes it cover 30 days. It schedules it monthly on the 1st with a recipient and saves. After a reload, the next send time and the schedule are still there. |

axe-core (WCAG 2.2 A/AA tags) runs on the import preview, the component result, the advisory impact
view, the manual finding form, the closed engagement, the scheduled report, and on J1's verdict and
J3's Issues table and issue page.

The plan's targets (J6 under a minute, ...) are a person's pace, so the tests do not assert them;
the study measures them.

Visual snapshots (web/tests-e2e/visual.spec.ts) were added for the import preview, component search,
advisory impact, engagement, manual finding form and report builder. Each has fixed names and dates,
masks for times, and its own data: the advisory snapshot uses lodash's CVE-2021-23337, which no
journey touches. The Linux baselines were made in `mcr.microsoft.com/playwright:v1.63.0-jammy`
against the e2e API in `python:3.12`, on a copy of the repository.

**Result: all 17 Playwright tests (8 journeys, 9 snapshots) pass on Linux against a fresh API. The
8 journeys also pass on macOS.**

## What writing the journeys found, and fixed

1. **Imported Issues were missing from the project's Issues list** (J6). The list showed only the
   latest scan's occurrences. An imported report's Issues -- the screen's own "View issues" button
   leads there -- never appeared, and a project fed only by imports showed none. The list now covers
   every current snapshot: the latest scan, then each Test's latest applied import, one row per
   Issue (`repo.open_snapshot_scan_ids`; regression test in tests/unit/test_api_ingest.py).
2. **The import file picker greyed out the files J6 imports.** `accept=".json,.xml,.sarif"` hid
   `.csv`, `.nessus` and `.jsonl`; a test sets the file directly, so only a person would hit it. The
   filter is gone (the format is detected from the contents).
3. **The import screen listed four formats** when the server reads fourteen. It now lists the
   server's own.
4. **Component search said "No library in use is named like 'log4j-core'"** above the very library,
   for the screen's own placeholder example, when Search was pressed before the 200 ms suggestions
   arrived. Search now asks for matches itself, and `log4j-core` matches Maven's
   `org.apache.logging.log4j:log4j-core` (npm's `@scope/name` by its name too).
5. **Every metric block in a report was called "Metric"**, so the weekly template had five identical
   "Move Metric up" and "Remove Metric" buttons for a screen-reader user. Blocks are now named by
   their metric ("Metric: SLA adherence").
6. **The advisory's text could not be scrolled from the keyboard** (axe in the real browser,
   scrollable-region-focusable, WCAG 2.1.1). It now takes focus, with a visible focus ring.
7. **Severity filter chips failed contrast** (axe in the real browser: 3.2–4.3:1 against 4.5:1, at
   11 px) on the scan verdict in dark mode, because unselected chips were dimmed with `opacity:
   0.6`. Their text is now full colour and the border marks the state; light and dark were both
   re-measured clean. The unit tests' jsdom cannot measure contrast, which is why this survived
   since v2.
8. **"Starts" defaulted to yesterday** after local midnight east of UTC (seen at 02:40 IST: 7
   October on the 8th), and the risk-acceptance expiry picker's bounds were UTC days while its
   meaning was the local day. Both now use the person's calendar day (`localDay`).

Noted for the study, not changed: the advisory's details are OSV Markdown shown as plain text
(scanner and feed text is never rendered as markup, by design), so `#` headings show as text.

## Tests

- Web: 449 unit tests (55 files) pass, run with `TZ=Asia/Kolkata` deliberately; `tsc` clean. New
  unit tests cover the file picker, component search pressed before suggestions, block names and
  `localDay`.
- Backend: `ruff`, `mypy` clean. New: the project Issues list with imports
  (tests/unit/test_api_ingest.py) and the study scorer (tests/unit/test_ux_study_score.py: SUS as
  Brooke defines it, J9 timed per finding, bad data refused, only the generated section rewritten,
  and the page always matching the recorded sessions).
- The seed script ran against a throwaway API on port 8800: three projects, log4j affecting
  billing-service only, J6's file and J9's list written out.

## Not proven

- Anything a participant would tell us. The SUS, the times and the problems people hit come from
  the study, which needs five people.
- That the journeys meet the plan's time targets for a person: a script is faster than anyone.
