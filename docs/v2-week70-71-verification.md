# Weeks 70–71 verification: metrics, dashboards, role homes (plan §48.1, §48.2, §55.4, §55.6)

Weeks 70 (metrics layer) and 71 (dashboards) were done together, as four tasks, on 2026-10-06
and 2026-10-07. The design and the measurements are in
[ADR-0054](adr/0054-metrics-layer.md), and every metric's definition is in [metrics.md](metrics.md).

## What was built

1. **Metrics with definitions.**
   - Six summary tables under forced RLS (migration 0042), refreshed one project at a time:
     - when a scan or import finishes;
     - every 2 minutes for anything else;
     - every hour for everything.
   - Projects are marked for refresh automatically whenever something they depend on changes.
   - Twelve metrics, each defined in one place (`core/metrics/definitions.py`). That one source
     feeds both the widget tooltips and `docs/metrics.md`.
   - API: `/v2/metrics`, `/v2/metrics/{id}`, and `/v2/metrics/issues` (the Issues behind a number).
2. **One million Occurrences.**
   - Every widget is under 300 ms at p95 on Postgres under RLS. The slowest metric is 99 ms and
     the slowest request 124 ms ([results](https://github.com/Rag2102/cyberimp/blob/main/benchmarks/metrics/one-million-occurrences.json)).
3. **Dashboard builder** (`/app/dashboards`, migration 0043).
   - A catalogue of 12 widgets, each with its own filters.
   - Drag and resize with react-grid-layout 2.2.4.
   - The keyboard alternative: focus a widget's Move button; arrows move it, Shift + arrows resize
     it, and each change is announced.
   - View as table on every chart; counts with every percentage.
   - Every count of Issues opens exactly those Issues, and each widget's title opens its definition.
   - Dashboards are saved per person and shared with a role: others view or copy them, and a stale
     save is refused. A built-in program overview is always available.
4. **Role homes and the portfolio overview.**
   - A person picks a role (until Week 75's user accounts) and lands on its home:
     - leads: the program dashboard and every business unit's sentence;
     - engineers: the Issues assigned to them, the soonest SLA deadline first;
     - testers: the engagements naming them as lead or tester.
   - The shared token is nobody, so it keeps the scan page. Scanning is at `/app/scan` for everyone.
   - `/app/portfolios/{id}` opens with the sentence the plan asks for, e.g. "3 projects need
     attention: 4 issues are past SLA, a new advisory affects partner-gateway and reporting-svc
     hasn't been scanned in 19 days. The other project is on track."
   - Projects are then sorted by need, with open P1s, Issues past SLA, the last scan, "Scanners N of
     M", an 8-week trend, and what each one needs. Projects on track beyond the fourth row fold
     under "Show all".

## Found and fixed along the way

- **Advisory impact** took up to 634 ms with a project filter. It is now a single join.
- **The Issues behind a number** took up to 294 ms, because Postgres can't estimate a join on
  `assets` under RLS. It now takes 2 ms (open) and 124 ms (fixed).
- **Keyboard moves undid themselves** in an update loop: a widget resized to 12 columns was saved
  as 11. react-grid-layout's `onLayoutChange` also reports its *previous* layout when it is given a
  new one. Layouts are now taken from it only when a mouse drag or resize ends.
- **The grid laid out at a width it never measured**, 24 px wider than the page. The width hook
  attached before its container existed.
- **"51 still open past the deadline" opened all 104 overdue Issues.** The link now carries the SLA
  period. A test checks that every link lists as many Issues as its number says, and in the
  browser all eight numbers on the Payments overview matched.
- **Three text styles were below the WCAG AA contrast minimum in light mode** (2.6–2.8:1). They are
  the site's dark-only global label and eyebrow colours, used on theme-following panels. On these
  pages they now use the theme's own colours.
- **Smaller fixes:**
  - assignees showed as `token:…` ids instead of names;
  - "11 fixeds";
  - the definition popup had no Close button;
  - copies of the built-in dashboard had the same name as it;
  - the overview table wrapped into tall rows on a phone. It now scrolls sideways, and its scroll
    area can take keyboard focus.

## Checked in the browser

These were checked against a seeded API on SQLite: 7 projects in 3 portfolios, a year of history
and three personal tokens.

- **Desktop width (1024 px).**
  - Edit mode, keyboard moves and resizes, with each announcement read from the live region.
  - A mouse drag by the Move button.
  - Filters, saving, reloading and deleting.
  - The definition dialog, View as table, the drill-down page.
  - Each role's home: Priya as a lead, Arjun as an engineer, Meera as a tester.
  - "Change role" reopens the picker with the current role selected.
  - The shared token still gets the plain scan page.
- **Phone width (375 px).**
  - The dashboard stacks its widgets in reading order.
  - The homes and the overview have no sideways page scroll.
- **Light and dark mode.**
  - Every text element on the dashboard (view and edit mode, and the filters dialog), the lead
    home and the overview meets WCAG AA. That is 134–188 elements per page, computed in the
    browser.
- **Production build** (`next build`, the nonce-only CSP).
  - No CSP violations and no console errors.
  - The grid's own positioning styles are set from JavaScript, which the policy allows.
- **Draw time once a widget's data arrives:** 7–16 ms in the production build and 10–34 ms in
  development, against the 300 ms budget (§60).

## Tests

- **Backend:**
  - 2,684 unit tests pass, and 63 row-level-security tests on Postgres 16 at migration 0043. The
    new ones cover dashboards and roles (each table's test fails when its policy is removed),
    and overviews and homes.
  - ruff, black and mypy are clean.
- **Web:**
  - 362 vitest tests pass, with axe on the widget, the editor, the drill-down, the role picker,
    each home and the overview; `tsc` is clean.
  - The keyboard rules are tested as pure functions.
- **End to end (Playwright):**
  - 3 of 7 pass, including J1, which signs in on the changed `/app` with the shared token and
    submits a scan.
  - The 4 failures predate these weeks:
    - J3 still clicks "Accept risk until…", which Week 62 replaced with two-person approval;
    - the visual tests have Linux baselines only, last regenerated in Week 35 before most of the
      navigation existed, so on macOS there was nothing to compare against.
  - Both are left for a separate task.

## Not done, or not proven

- **SLA "met" and "due" counts don't open their Issues.** The summary holds daily totals, not
  Issues. "Still open past the deadline" does open its Issues.
- **"Scanners N of M" counts scanner runs, not scanner categories.** The plan's mock-up counts
  categories ("6 of 7" categories that apply). Skipped scanners don't count as applicable.
- **Portfolios have no owner field**, so the overview leaves out the mock-up's "owned by @priya".
- **Roles are chosen by each person** and only decide the home page and what is shared with
  them. They are not permissions, which come with Week 75.
- **A dashboard can be up to two minutes behind a triage change**, as ADR-0054 says. Widgets say
  so when projects are waiting to refresh.
- **Not tested with real assistive technology.** The live-region announcements were read from the
  DOM, not from VoiceOver or NVDA. The Week 74 study is the place for that.
