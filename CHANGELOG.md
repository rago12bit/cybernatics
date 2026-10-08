# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com), versions follow
[SemVer](https://semver.org).

## [Unreleased]

## [3.0.0] - 2026-10-08

Weeks 75–78: sign-in and access ([Week 75](docs/v2-week75-verification.md)), the MCP server and
`/fix` ([Week 76](docs/v2-week76-verification.md)), the public website
([Week 77](docs/v2-week77-verification.md)), and the v3 benchmark table, write-up and release notes
(Week 78: [docs/evaluation-v3.md](docs/evaluation-v3.md),
[docs/release-notes-v3.0.0.md](docs/release-notes-v3.0.0.md)). Released without the third usability study,
which has not run; what else is unproven is under "Known limits" in the release notes.

### Added
- **`bulwark mcp`, an MCP server for your own agent (Week 76; plan §50, ADR-0059).** Tools
  `list_issues`, `get_issue` (taint path, evidence), `get_verified_fix`, `search_components`, and
  `run_scan` only with `--allow-scans` and a token that may write scans. It calls the API with the
  person's own token (`BULWARK_MCP_TOKEN`), so roles, project limits and RLS apply; the shared token
  is refused. Untrusted text comes back wrapped as `untrusted_text`, default-deny, with hidden
  characters shown as codes. [docs/mcp.md](docs/mcp.md).
- **`/fix` on pull requests (Week 76; plan §50, ADR-0059).** A member comments `/fix`; Bulwark
  previews up to five findings the pull request introduced and the token cap, and runs nothing until
  `/fix confirm <code>`. Owners, members and collaborators linked by an admin to a Member or higher;
  never for forks; every check repeated on confirm, including that the pull request has not moved.
  Verified patches are posted as comments. People and access gains a GitHub account field (admins
  only). Migration 0050. [docs/fix-on-pull-requests.md](docs/fix-on-pull-requests.md).
- The integrations catalogue lists both, generated from the code.
- **The public website (Week 77; plan §57).** See the [Week 77 verification](docs/v2-week77-verification.md).
  - The home page shows a recorded scan of one release of OWASP Juice Shop (v17.3.0), done two
    ways: its source by the default scanners, and its running container by a passive web
    campaign behind the campaign's egress proxy. `scripts/record-juiceshop.py` makes it and
    records the commit, the image digest, the date and the Bulwark version. The page says what
    the recording leaves out: dependencies (the release has no lockfile), Nuclei, every URL (ZAP
    lists at most five per alert), runtime confirmation (Express routes are not read), and how
    many Issues the findings become. `/sample` shows both halves.
  - New pages: How it works, Integrations, Security, Compare, Migration guides and Community,
    each citing the files that do what it says. A test fails if a cited file is missing.
  - The integrations catalogue is generated from the code's registries (scanners, DAST tools,
    parsers, connectors, ticket systems, notification channels) by `scripts/gen-integrations.py`;
    `tests/unit/test_integrations.py` fails when it is stale or misses a registry entry.
  - Compare is Bulwark against DefectDojo, from facts checked against DefectDojo's repository on
    2026-10-07, including where DefectDojo is ahead. The migration guides cover both directions
    through the DefectDojo connectors, with what does and does not carry over.
  - The landing page's "Roadmap" no longer lists multi-user accounts (they shipped in Week 75),
    and the self-host page no longer says "no user accounts yet".
- **Accounts, single sign-on, SCIM and scoped roles (Week 75; plan §51, ADR-0058).** See
  [Sign-in, people and access](docs/identity.md) and the [Week 75 verification](docs/v2-week75-verification.md).
  - People with an organization role (admin, member, viewer, or only granted projects) and higher
    roles on business units or projects. A person's scopes are decided per project from the request.
    Migration 0048; `bulwark users add|list|disable`.
  - Sign-in with OIDC (PKCE, strict ID-token checks) or SAML 2.0 (pysaml2 with xmlsec1, signed
    assertions only), tested against forged tokens and signature-wrapping, comment-injection,
    unsigned, replayed and unsolicited responses, and against a real Keycloak. Migration 0049.
  - Short, HttpOnly session cookies with a CSRF token for every change.
  - SCIM 2.0 Users for identity providers; turning someone off ends their sessions and tokens in the
    same request.
  - Someone limited to some projects sees nothing else, enforced by Postgres: their requests run as a
    guest role with restrictive policies on every table that names a project. Two-project test.
  - Personal API tokens that act as their person and never exceed their role.
  - Web: a sign-in screen by work email, People and access, Sign-in and provisioning, My API tokens.
  - Requires Postgres 16 or later.

### Changed
- **JIT compilation is off for the app's database transactions.** It took 116 of a 153 ms count;
  without it, counting 100,000 Issues went from 93 ms to 44 ms (ADR-0058).
- **The app now looks like the public site.** Every screen uses the site's dark "blueprint" style:
  warm near-black, hairline borders, sharp corners, Geist headings, uppercase monospace labels and
  buttons, and the emerald accent.
  - One header instead of two. Signed in, the site header carries the app's sections (Home,
    Projects, Inbox, Dashboards, Advisories, Approvals, Reports, and the rest under More), so it no
    longer wraps onto a second row. Under it, a slim bar holds the breadcrumbs, the project
    switcher, the command palette and shortcut help.
  - The design tokens carry the site's palette and fonts, so all screens changed together. The
    app's separate light theme is gone: it made the app look unlike the site around it.
  - Older screens referred to colour names the tokens never defined, so they fell back to
    light-theme colours, dark red and grey text on a dark background. They now use the tokens.
  - On-screen references to the project plan ("plan §28.1", "Week 30") are replaced with plain
    wording.
  - Seven screens that had no main heading now have one. Calendar days of the neighbouring
    months are readable (they were faded below 4.5:1). The cost and SLA tables scroll on a phone
    instead of widening the page.
  - Code on the issue page is always highlighted dark; it used to follow the operating system's
    light/dark setting and could show a white box in the dark app.
  - The Linux visual snapshots are regenerated for the new design. The dev server's floating badge
    is now off when Playwright starts it, so a snapshot can't catch "Compiling..." on some runs.

### Fixed
- **The verified-fix agent now spends within a budget (Week 76).** It counted its model tokens but
  never charged them to the organization's monthly budget, and never checked it; each attempt now
  does both, and a run can carry a token cap.
- **A cut-off CSV report can no longer close Issues.** Nessus, OpenVAS and universal-mapper CSVs
  cut so the last row stays full width (after a quoted field, inside an escaped quote, after the
  delimiter that follows an empty field, or inside an unquoted last field) read as whole and could
  close every Issue they no longer listed. A last row ending on a quoted field with no line break is
  now refused, and any other last row with no line break is read but closes nothing -- real Tenable
  exports end that way and cannot be told apart from a cut one. Every cut of every vendored Nessus
  and OpenVAS CSV was checked (199,038): none can close; before, 29 dropped or garbled a finding and
  could still close it.
- **The fix agent no longer rejects a correct patch next to another finding.** Verification compared
  findings by fingerprint, which shifts when a nearby line changes (Bandit quotes three lines) and
  when correlation moves a rule into the neighbouring finding -- so an untouched neighbour looked
  like a regression, and an edit beside the flagged line could look like a fix. Both steps now also
  recognise a finding by the text of the lines it flags and the rules that fire, and refuse any rule
  firing more often than before. Tested on recorded real Bandit output; the Week 76 live case
  (PyCQA/bandit#2, `examples/ciphers.py:30`) now passes, and a patch swapping in `eval` still fails.
- **The fix-agent worker now acts for the run's organization.** Under forced RLS its activities could
  not see their own run, so on Postgres every attempt, patch and final status was silently dropped.
  Found live while verifying Week 76.
- **A web finding's location read ":0".** The scan report, the Issues list and the project
  overview printed a file and line, which a DAST finding does not have. They now show the host and
  route it was reached at.
- **The findings table logged duplicate-key errors** when a scanner reported one rule twice in
  one place, giving two findings one id (Semgrep on one line, ZAP with different evidence on one
  URL). Rows are now keyed by position as well; the duplicate findings themselves are not changed.
- **The recorded scan's banner** used an inline style, which the production CSP drops, and linked
  to "a smaller sample" that was the same page.
- **SECURITY.md** said the supported version was `1.x`.
- **End-to-end tests could collide when run in parallel.** Two tests starting in the same
  millisecond on different workers got the same "unique" repository URL. The URL now has a random
  part.

## [2.5.0] - 2026-10-08

Milestone M16 (plan Phase 17, Weeks 70–74): metrics, dashboards, reports and filters at scale
([Weeks 70–71](docs/v2-week70-71-verification.md), [Week 72](docs/v2-week72-verification.md),
[Week 73](docs/v2-week73-verification.md)), and journeys J6–J10 as tests
([Week 74](docs/v2-week74-verification.md)). **Tagged without the milestone's usability study:** it
needs five security leads or pen testers and has not run, so SUS and time on task for J6–J10 are not
measured ([docs/ux-study.md](docs/ux-study.md)). Weeks 75–77 were built before Week 74, so this
tag's code also contains them; they are described under 3.0.0.

### Added
- **Journeys J6–J10 as Playwright tests, and the third usability study ready to run (Week 74;
  plan §58).** Import a report, the new-CVE morning, risk acceptance, a pen test to its report, and
  a scheduled monthly report, each on the real app; axe-core now runs in the real browser; visual
  snapshots for six more screens. The study itself needs five people and has not run:
  [docs/ux-study-v3-protocol.md](docs/ux-study-v3-protocol.md), `scripts/ux-study-seed.py` and
  `scripts/ux-study-score.py` are ready. [Week 74](docs/v2-week74-verification.md).
- **Issues across every project, by query (Week 73, task 1; plan §56).**
  - `GET /v2/issues?q=` lists the organization's Issues filtered by a query such as
    `priority:P1 sla:breached project:payments-* -status:accepted`: fifteen filters, exclusions,
    `*` in names and paths, dates as an age or a day, free text in titles. See
    [Finding Issues](docs/issue-search.md).
  - The query language is parsed by the API and by a twin in the browser; both must pass the same
    31 shared cases, so the filter panel (task 4) and the query bar cannot disagree.
  - Pages by cursor, so deep pages cost the same as the first. Migration 0045 adds ordered
    indexes: at 500,000 Issues a page went from 0.23-0.61 s to 6-10 ms.
  - Counts are exact while they are quick, else "more than 10,000". Postgres's own estimate was
    off by 2 to 7 times, so the plan's "about 48,000" is not used (ADR-0056).
  - Measured on Postgres under row-level security: within 300 ms at 100,000 Issues for every query;
    at 500,000, free text is the exception (0.5 s with its count). Benchmarks in
    `benchmarks/issues/`.
- **The Issues list across every project (Week 73, task 4; plan §56).** `/app/issues`, "Issues"
  in the header. See the [Week 73 verification](docs/v2-week73-verification.md).
  - A grouped, collapsible filter panel (each group shows how many filters are on), removable
    chips with Clear all, and a query bar with suggestions. The panel and the query stay in step
    both ways, and the address carries the list.
  - Pages by cursor; a column chooser and density toggle remembered per person; saved views.
  - "Select all N matching", then a bulk change previewed as counts and undoable for 10 seconds.
  - The per-project table saves its views to the server and links to the new list.
- **Saved views and table settings (Week 73, task 2; plan §56).**
  - Save the Issues list's query, sort and columns under a name; personal, or shared with a role
    to view or copy, like dashboards. Six built-in views. Queries are checked and stored
    canonically. `/v2/issue-views`, migration 0046.
  - Views saved in the browser before are imported once, each as a query for its project.
  - Columns and density are remembered per person (`/v2/me/tables/issues`).
  - A report's Issues block can show a saved view, as it is when the report is generated. This
    closes the gap noted in Week 72.
- **Bulk changes across pages, previewed and undoable (Week 73, task 3; plan §56, ADR-0057).**
  - Assign or unassign, mark not a risk, reopen, add or remove a tag, for up to 10,000 Issues: the
    ones picked, or every one matching the query.
  - A preview first, as counts: what changes, what already is as asked, what is left alone and
    why. Applying names the count the preview showed; if the list changed since, nothing changes.
  - One audit entry per Issue and one for the batch, in one commit. Undo for 10 seconds puts back
    every Issue nobody changed since.
  - Risk acceptance stays in its own four-eyes flow: the preview groups the selection by project
    for one request each. Migration 0047.
  - At 100,000 Issues, 6,000 tagged in 0.7 s and undone in 1 s.
- **Metrics layer (Week 70, plan §48.1, ADR-0054).**
  - Twelve metrics, each with a written definition kept in one place. The same text is each
    widget's tooltip and `docs/metrics.md`.
  - Read from summary tables under forced RLS (migration 0042), never from Occurrences on page
    load. Tables are refreshed after every scan and import, every 2 minutes for triage and policy
    changes, and hourly in full; changes mark their project automatically.
  - Every number comes with its counts and the Issues behind it.
  - API: `/v2/metrics`, `/v2/metrics/{id}`, `/v2/metrics/issues`.
  - CLI: `bulwark metrics refresh`.
- **One million Occurrences (Week 70, plan §60).** `scripts/bench-metrics.py` seeds 250,000
  Issues and 1,000,000 Occurrences on Postgres. Every metric is under 100 ms at p95, and the
  slowest request is 124 ms ([results](benchmarks/metrics/one-million-occurrences.json)).
- **Dashboards (Week 71, plan §48.2, §55.4).**
  - A catalogue of 12 widgets with per-widget filters (portfolio, project, tag, period, grouping).
  - Drag and resize (react-grid-layout 2.2.4), with a keyboard alternative: arrows move a widget,
    Shift + arrows resize it, and each change is announced.
  - View as table on every chart; percentages always with their counts. Every count of Issues
    opens exactly those Issues, and each widget's title opens its definition.
  - Several saved dashboards per person, shared with a role, which can view or copy them. A stale
    save is refused, and every change is audit-logged.
  - A built-in program overview.
  - Migration 0043. API: `/v2/dashboards`, `/v2/me`.
- **Role homes and the portfolio overview (Week 71, plan §48.2, §55.6).**
  - A person picks lead, engineer or tester (until Week 75) and lands on their home:
    - leads: the program dashboard and each business unit's sentence;
    - engineers: their Issues, the soonest SLA deadline first;
    - testers: their engagements.
  - Each business unit opens with a sentence naming what needs attention and why: Issues past SLA,
    a new advisory, a project nobody has scanned in 14 days. Projects follow, sorted by need, with
    "Scanners N of M" and a trend.
  - API: `/v2/me/assigned`, `/v2/me/engagements`, `/v2/portfolio-overviews`.
- **Report builder (Week 72, plan §48.3, ADR-0055).**
  - Blocks: cover, executive summary, metric, issue table, issue detail, risk acceptances,
    compliance mapping, engagement scope, appendix. Three templates.
  - PDFs are rendered by headless Chromium in a locked-down, network-less container on the worker,
    kept with their SHA-256, and signed with cosign when a key is set up.
  - Links need no sign-in, expire in 1 to 90 days, and can be revoked. Only their hash is stored,
    and each opening is audit-logged.
  - Weekly or monthly schedules email recipients a link.
  - The executive summary can be drafted by a model from the report's own numbers. It is labelled
    AI-written, and nothing is generated or sent until a person confirms it.
  - Migration 0044. API: `/v2/reports`, `/v2/report-runs`, `/r/{token}`.
  - Settings: `BULWARK_API_PUBLIC_URL`, `BULWARK_PDF_IMAGE`, `BULWARK_LLM_ROUTE_REPORT`.
  - [docs/reports.md](docs/reports.md), [verification](docs/v2-week72-verification.md).

### Changed
- **`/app` for a person is now their role home.** The shared token, which is nobody in particular,
  still lands on the scan page. Scanning is also at `/app/scan`.

### Fixed
- **Found by writing journeys J6–J10 (Week 74):**
  - A project's Issues list now shows imported Issues: it listed only the latest scan's, though
    the import screen links there, and a project fed only by imports showed none.
  - The import file picker no longer greys out `.csv`, `.nessus` and `.jsonl` reports, and lists
    the fourteen formats the server reads instead of four.
  - Component search no longer says "No library in use is named like log4j-core" above that very
    library when Search is pressed before the suggestions arrive; a short name finds Maven's
    `group:artifact`.
  - Report blocks are named by their metric, not five identical "Metric" buttons.
  - The advisory text can be scrolled from the keyboard; severity filter chips meet 4.5:1 contrast
    (they were dimmed to 3.2–4.3:1).
  - An engagement's start date and a risk acceptance's expiry use the person's calendar day, not
    UTC's (after midnight east of UTC, "today" was yesterday).
- **End-to-end tests had gone stale.**
  - The J3 risk-acceptance journey still used the one-person accept button removed in Week 62. It
    now requests, approves as a second person, and ends early.
  - The Linux visual baselines dated from Week 35. They are regenerated in the pinned Playwright
    image.

## [2.4.0] - 2026-10-06

Milestone M15 (plan Phase 16, Weeks 65-69): the new-CVE morning -- rules and tickets for the
routine, the component inventory, the advisory engine and VEX; journey J7 in under five minutes
([docs/v2-week69-verification.md](docs/v2-week69-verification.md)).

### Added
- **Rules engine (Week 65, plan §45, ADR-0049).** WHEN a trigger (Issue found, back, fixed,
  assigned; retest requested or decided; SLA due soon or breached; risk acceptance expiring or
  expired; scan or import completed; no scan for N days; a schedule), IF a Rego condition (evaluated
  in batches by OPA with network and environment builtins removed), THEN assign, set a priority band,
  tag, mark ready for retest, request a verified fix, or notify. Every rule has a dry run over the
  last seven days; a cause that would touch more Issues than the rule's threshold waits for an Admin;
  chains stop at depth 3; fix requests respect the AI budget and a daily cap; writing rules needs the
  new `rules:write` scope; every change and every run is audit-logged. The outbox now has a
  dispatcher (every 10 s on the worker, one org at a time under an advisory lock). An Automation page
  shows held runs, rules and run history; the issue page shows who owns the fix and a priority set by
  hand or by a rule. API: `/v2/rules`, `/v2/rule-runs`, `/v2/issues/{id}/assignee` and `/priority`.
  Migration 0037. OPA 1.21.0 ships in the app image, checksum-verified.

- **Rules editor, notifications and two-way tickets (Week 66, plan §49, §55.7, ADR-0050).** A rule
  editor with trigger, condition and action builders, a Rego view of the module OPA runs, "Test this
  rule" on the unsaved draft, and a gallery of nine templates; rules can also put Issues in a group,
  file or update their ticket, and notify named people. Notifications: watchers (taking part makes
  you one), an in-app inbox with an unread count, email through the operator's SMTP server
  (`BULWARK_SMTP_*`), and for each kind of event and channel off, at once or a daily digest -- for
  each person, and for the team channels (Slack, Discord, Microsoft Teams, the outbound webhook).
  Tickets in Jira or GitHub Issues per project, both ways: Bulwark owns the summary and severity
  label, the ticket owns the status (mapped per project to nothing or "ready for retest"; Bulwark
  never marks an Issue fixed because a ticket closed) unless the project gives the status to Bulwark,
  which then closes and reopens it. Issue groups map to one ticket. Webhooks and a ten-minute poll.
  API: `/v2/rules/templates`, `/v2/notifications`, `/v2/notification-prefs`, `/v2/issues/{id}/watch`,
  `/v2/projects/{id}/tickets`, `/v2/projects/{id}/groups`, `/v2/issues/{id}/ticket` and `/group`.
  Migration 0038. A native scan's completion event now carries its counts, like an import's.
- **Calendar (plan §49).** Engagements, SLA due dates and expiring risk acceptances for a month, by
  project and kind, from data Bulwark already has: `GET /v2/calendar` and a Calendar page (a month
  view, and a day-by-day list on phones).
- **Component inventory (Week 67, plan §46.1, ADR-0051).** Every package of every SBOM -- a full
  scan's Syft SBOM, and every imported CycloneDX or SPDX file -- stored by library and version per
  project, one row per library per organization, the latest SBOM of each source marked current.
  "Where do we use this?": `GET /v2/components?purl=&version=<2.17.1` and `GET /v2/libraries`, and
  a Components page with suggestions as you type. Versions are compared in each ecosystem's own order
  (PyPI, npm, Go, Maven; Maven's checked against Maven 3.9.16 itself, npm's against npm's `semver`),
  and a version that cannot be compared is said, not guessed. Each component records whether the
  application's code imports it. Under 30 ms at the 95th percentile across 1,000 projects and 1.5
  million current components. Migration 0039; an hourly task fills in projects scanned before.
- **Advisory engine (Week 68, plan §46.2, §55.5, ADR-0052).** OSV's data for PyPI, npm, Go and Maven
  (GitHub's advisories, the PyPI and Go databases, malicious-package reports), CISA KEV and recent
  NVD CVEs, fetched every six hours (the full dump once, then only what changed). Matched against
  the component inventory the way osv-scanner matches -- checked against osv-scanner 2.6.0 on the
  same data and SBOMs: 21,619 of 21,721 package versions agree, and in every one of the 102
  differences Bulwark follows the ecosystem's own rules and reports more, never less
  (`docs/evaluation-advisory-matching.md`). Impacts are kept per vulnerability, version and project
  and follow every SBOM. An Advisories page (the newest first, known-exploited and most severe
  first), an impact view per vulnerability (version, fix, whether the code imports it, owner,
  exposure), and Issues in one click: grouped per vulnerability, assigned to the project's owner,
  filed where the project has ticket settings, deduplicated with osv-scanner's, and closed when an
  SBOM no longer has an affected version. A new vulnerability tells the team channels and the
  owners once. Projects have an owner. Component search shows each version's advisories. API:
  `/v2/advisories`, `/v2/advisories/{key}`, `/v2/advisories/{key}/issues`, `/v2/advisory-feeds`,
  `/v2/projects/{id}/owner`. Migration 0040.
- **VEX (Week 69, plan §46.3, §55.5, ADR-0053).** A dependency Issue marked not a risk can say why
  in OpenVEX's vocabulary. "Draft VEX for the others" on an advisory proposes "not affected: the
  vulnerable code is not executed" where the code shows it: for Go, none of the vulnerable functions
  Go's database names is used by the application's code (read from the Go source at scan time); for
  Python and JavaScript, the package is not imported. Each proposal carries its evidence and its
  limits; a person confirms it with a personal token, which also dismisses the Issue; reopening the
  Issue withdraws it. A project's VEX as OpenVEX v0.2.0 or CycloneDX 1.6 (both schema-valid;
  `vexctl` reads them), and a VEX page. Go components now record whether application code imports
  them. API: `/v2/advisories/{key}/vex-drafts`, `/v2/vex/{id}/confirm|reject|withdraw`,
  `/v2/projects/{id}/vex`, `/vex/openvex`, `/vex/cyclonedx`.
- **Compliance and evidence packs (Week 69, plan §47, ADR-0053).** Mappings as versioned data that
  cite their source: OWASP Top 10 and ASVS 4.0.3 (OWASP's own data), PCI DSS v4.0 Requirement 6, ISO
  27001:2022 A.8.8 and SOC 2 CC7.1 (numbers and paraphrases only). An ASVS checklist per project in
  which only a person marks a requirement met. Evidence packs for a period: SLA adherence, risk
  acceptances with their approvals, scan coverage, open Issues by priority, VEX, assessments, each
  framework's controls against that evidence, and the audit-log extract -- a signed zip with a PDF
  and a standard-library `verify.py` that checks the files and the hash chain without Bulwark. API:
  `/v2/compliance/frameworks`, `/v2/projects/{id}/asvs`, `/v2/evidence-packs`. Migration 0041.
- **Audit log per organization (Week 69).** New entries carry their organization inside the hash,
  so an organization's extract shows its own entries in full and every other entry as hashes that
  still recompute. `bulwark audit checkpoint --rekor-url` publishes checkpoints to a private Rekor;
  `bulwark audit verify --pub [--trusted-root]` verifies every checkpoint's signature and Rekor entry.

### Security
- Notification titles are one line wherever they go, and email headers are stripped of line breaks,
  so an issue title cannot add an email header or fake a line in a digest. Teams cards escape
  Markdown.
- Jira's address now passes the SSRF guard when saved and before every sync call.
- Rule notifications escape Slack markup and disable Discord mentions, so an issue title cannot ping
  a channel or post a disguised link.
- An evidence pack shows another organization's audit entries as hashes only, and is never produced
  unsigned when signing was configured and failed. Confirming VEX needs a personal token.

### Fixed
- Every vulnerability adopted in a project matched the same Issue: advisory findings (Week 68)
  skipped the import path's identity step and all had an empty fingerprint. They now take the same
  steps as any imported report, so each is its own Issue and joins osv-scanner's for the same
  package and CVE.
- The Rekor log index of an audit checkpoint was never recorded with cosign 3, whose bundles write
  it as a string (and leave out an index of 0). `bulwark audit verify` now also checks that each
  checkpoint names the hash at its position.

## [2.3.0] - 2026-10-06

Milestone M14 (plan Phase 15, Weeks 61-64): governance -- SLAs, risk acceptance with four-eyes
approval, priority v3, and a pen test run end to end inside the platform, every decision in the
audit log ([docs/v2-week64-verification.md](docs/v2-week64-verification.md)).

### Added
- **SLA engine (Week 61, plan §44.1, ADR-0046).** A versioned SLA policy per project: days to fix
  each severity from first detection, and a "due soon" window (off until saved; starter values
  offered). The clock is first detection, which reimport never resets. Every issue response carries
  its SLA (on track, due soon, breached; met or missed once fixed; paused while triaged away), the
  issues table filters by it, and a sweep every five minutes announces each crossing once -- an
  outbox event and one message per project to Slack, Discord and the outbound webhook. New: the
  **SLA** page per project, an SLA column and filter, the deadline on the issue page. Migration 0033.
- **Risk acceptance with four-eyes approval (Week 62, plan §44.2, §55.3, ADR-0046).** Accept,
  mitigate, transfer or avoid one or more Issues with a justification, compensating controls, proof
  (links and encrypted files) and an expiry capped at 90 days
  (`BULWARK_RISK_ACCEPTANCE_MAX_DAYS`). The Issues stay open until someone else approves: the server
  refuses the requester and the shared token. Expire now, reinstate (within the approved dates),
  extend (a new request needing its own approval); the expiry job reopens the Issues and can restart
  their SLA. Every step is in the audit log and the Issue's history. New: the request form, the
  **Approvals** queue, a page per acceptance. Migration 0034.
- **Priority engine v3 (Week 63, plan §44.3, §55.7, ADR-0047).** The risk score becomes a policy per
  project: a weight per factor (severity, EPSS, KEV, reachability, taint and runtime confirmation,
  tool agreement, path context, the triage assistant, business context) and the project's business
  context (internet-facing, data sensitivity, criticality; unset is the worst case, so it can only
  lower scores). The **Priority** page shows how the top 50 would reorder, and which Issues leave
  it, before saving. Saving re-ranks every Issue in the background, and another change is refused
  (409) until that finishes. Each Issue carries its priority score, band (P1-P4) and every factor
  with its weight. The issues table sorts by priority and filters by band (`?priority=P1`). With no
  saved policy, priority is the v2 score unchanged. Migration 0035.
- **SLA deadlines by priority band** (§44.1's alternative basis): an SLA policy can key on P1-P4
  instead of severity.
- **Pen-test engagements (Week 64, plan §43.1, §55.2, ADR-0048).** An assessment has a scope
  (targets, routes, what is out of scope), a lead and testers, dates, a lifecycle (planned, in
  progress, reporting, closed) and an optional OWASP checklist (WSTG 4.2, or ASVS 4.0.3 at L1, L2 or
  L3; CC BY-SA 4.0, credited). Its screen lists every finding its uploads reported, with what else
  reports it ("Also found by …") and where its retest stands, its tests, "Add a finding" and "Import
  results" into it, and "Close and write the report": a Markdown or HTML report frozen at closing.
  Migration 0036.
- **Retests (Week 64, plan §43.3).** Mark an issue ready for retest; a tester confirms it fixed (the
  issue is fixed) or reproduces it (a note is required; it stays open). For a scanner's issue the
  next scan or upload decides, and undoing that upload undoes it. A **targeted retest** re-runs only
  the one rule against the one file on a fresh checkout -- or the one DAST template against the one
  URL of a verified target -- without touching the scan history.
- **Notes, mentions and tags (Week 64, plan §49).** Threaded notes on issues, as plain text, with
  @mentions of named API tokens (a Mentions page lists yours) and files on notes. Tags on
  portfolios, projects and issues inherit downward; the issues table filters by tag (`?tag=`). A
  project can be put in a portfolio.

### Changed
- **Triage can no longer accept a risk alone** (HTTP 409): use a risk acceptance request. Issues
  accepted that way before are migrated into *legacy* acceptances, with every expiry date kept and
  marked as never approved by a second person. "Not a risk" and "reopen" are unchanged.

### Fixed
- **Files could be served from the API's own host even with a separate attachments origin
  configured** (threat T24). With `BULWARK_ATTACHMENTS_ORIGIN` set (now in Compose and Helm), that
  host serves only signed downloads and the API host refuses them.
- **A long issue title widened the issue page past the window**, so it scrolled sideways (titles from
  Opengrep are full sentences). It now truncates as designed.
- **A promoted hypothesis had no risk score stored**, so it sorted last in the issues table. It now
  stores the score it was given and gets a priority.
- **Saving from the web app failed for every PUT, PATCH and DELETE** when the web app and API are on
  different origins (the default): CORS allowed only GET and POST. That broke saving the threat
  model, retention, plugin allowlist and integration settings, and turning off or deleting a
  connector. Every method a route uses is now allowed.
- **Times read from SQLite were shown in the wrong zone.** SQLite drops the time zone, so timestamps
  came back without one, the API sent them without an offset, and browsers read UTC as local time:
  in IST a run from seconds earlier showed as "6 hours ago", on every screen. Every timestamp column
  now uses one UTC-aware type (`core/persistence/utc_type.py`) that stores UTC and reads UTC on any
  database, so the API always sends an offset. PostgreSQL deployments were not affected (their DDL is
  unchanged, no migration), except that times now always come back in UTC rather than the database
  session's zone. Local development, the end-to-end server and SQLite self-hosting are fixed.

## [2.2.0] - 2026-10-05

Milestone M13 (plan Phase 14, Weeks 57-60): more formats, your own formats, findings by hand, and
connectors -- with a recorded round trip through a real DefectDojo
([docs/v2-week59-60-verification.md](docs/v2-week59-60-verification.md)).

### Added
- **Connectors (Week 60, ADR-0045).** Scheduled pulls from GitHub code scanning and Dependabot (through
  the GitHub App, no stored credential), GitLab vulnerability reports (GraphQL, checked against
  gitlab.com's schema) and DefectDojo, each applied through the ingest path into the connector's own
  Test so a fixed or dismissed alert closes here; and an export of a project's open Issues to
  DefectDojo as SARIF (`import-scan`, then `reimport-scan` into the same Test). A partial pull is never
  applied, and an empty pull after a non-empty one closes nothing unless `close_on_empty` is set. Health
  per connector -- `ok`, `empty` ("connected but fetched nothing"), `failing`, with backoff -- on a new
  **Connectors** screen, with run history. Credentials go to OpenBao when configured and are never
  returned; base URLs pass an SSRF guard on every request. Migration 0032; Celery beat schedules them.
- **Manual findings (Week 59, ADR-0044).** A pen tester or reviewer records what no scanner found:
  title, a searchable CWE, severity from a CVSS 4.0 calculator (scored by the `cvss` library behind
  `POST /v2/cvss/v4`, checked against FIRST's calculator; the vector is kept beside the score), a
  route picked from code intelligence or a file, steps, impact, recommendation and evidence. It
  enters through the ingest path (source `manual`) and becomes an ordinary, revertible Issue. A
  picked route places it at its handler and, when a static finding there has a related CWE, links
  the two and carries that finding's taint path. Every scan now stores its HTTP entrypoints for the
  picker (migration 0031). Evidence is type-sniffed, encrypted at rest with OpenBao, and only ever
  downloaded through a five-minute signed link with `Content-Disposition: attachment`, `nosniff` and
  a sandboxing CSP. New: the **Record a finding** screen, and a "Recorded by hand" panel on the
  issue page.

- **The universal mapper (Week 59, ADR-0043).** A JSON, CSV or XML report with no parser can be
  imported through a saved **mapping**: where each field lives, in a deliberately small path language
  (`$.a["b"][*]`, `child/@attr`, a column name). A mapping is a deterministic parser that runs in the
  parser sandbox and is imported with `parser=universal:<id>`, with every reimport guarantee a built-in
  parser has. `POST /v2/mappings/analyze` describes a sample (inside the sandbox) and drafts a mapping
  -- by the model when one is configured, checked against the sample so no invented path survives, or
  by field-name matching -- `POST /v2/mappings/preview` shows the issues it would produce, and
  `POST /v2/mappings` saves it, versioned (migration 0030, tenant-isolated, audit-logged). The model
  never sees the file and never runs during an import. Saved mappings are suggested when an upload
  is not recognised, never picked. Three fixed mappings and the sample analysis join the fuzz matrix;
  the mapping prompt has its own evaluation set (`core/llm/prompts/mapper/`).
- **Deduplication strategies per source, with a dry run (Week 58, ADR-0042).** A project can choose,
  per source, what makes two findings one Issue: `fingerprint_v2` (the existing fingerprint, and the
  default, so nothing changes until someone chooses), `tool_id`, `hash_fields`, `tool_id_or_hash`
  and `package`. Settings are versioned by insertion (migration 0029, tenant-isolated) and applied to
  imports and native scans before findings are matched to Issues. Changing one for existing Issues is
  previewed first -- "would merge 75 issues into 9 and split none" -- and then applied exactly as
  previewed (a digest refuses a stale preview) in one transaction: occurrences, tickets and fix runs
  are never lost, and a merge never hides an open Issue behind a triage decision. New
  `GET/POST /v2/projects/{id}/dedup[/preview|/apply|/history]`, a **Matching** screen on each project,
  a live Matching row on the import screen, `wait_for_dedup` that actually waits, and
  `dedup_complete` that follows the import's status.
- **Ported parsers, batch 2: Grype, Trivy, Snyk, GitLab security reports, Checkov.** `gitlab` is
  one parser for GitLab's SAST, dependency, container, secret-detection and DAST/API-fuzzing reports
  (classified by where each record is, GitLab's own `id` not used as identity); `checkov` reads a
  report with `CheckovAdapter.to_finding`, one framework or a list, and Checkov 2's counters-only
  output (nothing scanned) closes nothing. `grype` and `trivy` read a report with the
  very function a native scan uses (`GrypeAdapter.to_finding`, `TrivyAdapter.result_findings`), so an
  uploaded report and a scan cannot disagree; `snyk` reads `snyk test --json` for Open Source and
  Container projects, one or many. A Trivy finding now carries the CVSS score of the source that set
  its severity (NVD's 9.8 no longer sits beside a GitHub-decided HIGH), and Trivy secrets are read when
  present.
- **Ported parsers, batch 1 (Week 57, ADR-0041): ZAP, Nuclei, Burp, Nessus, OpenVAS.** `zap` reads
  ZAP's XML (including the requests-and-responses variant) and JSON reports; `nuclei` reads JSONL and
  the JSON array; `burp` the XML issue export (the one parser that admits Burp's internal DOCTYPE, and
  nothing more); `nessus` the `.nessus` XML and Nessus Pro / Tenable.io CSV; `openvas` the GMP XML and
  CSV. A scan that did not finish, scanned no hosts, or is an empty CSV closes nothing. Both are derived from DefectDojo's parsers (BSD-3-Clause, notice in
  `THIRD_PARTY_LICENSES.md`, generated from each parser's `ported_from`) and run against DefectDojo's
  own sample reports and the results its tests expect (`scripts/sync-dd-fixtures.py` vendors them from
  a pinned commit). They share one reading of an alert with the native DAST campaigns
  (`core/dast/mapping.py`), run in the parser sandbox and are in the nightly fuzz matrix. An empty
  Nuclei file closes nothing.

### Fixed
- **The DefectDojo import connector pulled every product's findings, not the one configured.**
  Found in the M13 round trip against a real DefectDojo (3.3.300): its findings API silently ignores
  a filter it does not know, and `?product=<id>` is not one of its filters, so a connector for one
  product imported the findings of every product its key could read (and would have closed them
  here as they changed there). It now filters by `test__engagement__product`, checks the product
  exists first (a wrong id is "not found", not "fetched nothing"), and asks for each finding's
  `related_fields`: a finding from another product refuses the whole pull, so an ignored filter can
  never widen what is imported again.
- **The DefectDojo export could not create its product.** DefectDojo refuses to auto-create a product
  without a product type (HTTP 400); the export now sends one (`product_type_name`, default
  "Bulwark", settable on the Connectors screen), and a connector's error now carries the reason a
  server gave for a 4xx instead of a bare "HTTP 400".
- DefectDojo findings now also read the newer `cwes` list (where a ZAP finding's CWE is) and turn a
  `fix_version` into the remediation.
- The issue page answered "issue not found in the latest scan" for any Issue only an import (or now
  a person) reported; it shows the Issue's most recent occurrence instead.
- **DAST findings were merged and collapsed (found importing a real ZAP report; also affected native
  DAST campaigns).** Two different alerts sharing a CWE were merged into one finding (which survived
  depended on input order); the fingerprint ignored the route, so one alert on fifty URLs was one
  Issue; and the location-independent fallback key matched every URL to the first Issue made for the
  alert -- 130 findings of one real report became 15 Issues. A finding's host and route are now its
  identity (new `Location.host`), DAST findings are never merged, and correlation no longer compares
  every DAST finding to every other (it was quadratic). **One-time effect:** DAST Issues recorded
  before this release have route-free fingerprints, so the next DAST campaign closes them as fixed and
  reports the same defects as new, per place; triage marks on the old Issues do not carry over.
  Details in [ADR-0041](docs/adr/0041-dast-and-network-identity.md).

## [2.1.0] - 2026-10-04

### Added
- **Import anything standard, and reimport it correctly (Weeks 54-56, plan Phase 13, ADR-0040).**
  `POST /v2/ingest` takes a SARIF, CycloneDX (JSON or XML), OSV-Scanner or SPDX report and compares it
  with that Test's previous upload: **new, unchanged, reopened, closed** (plus `detached`: no longer
  in the file but still reported by another source, so not fixed). The same file twice is a no-op, the
  latest import can be undone, and a preview shows the counts before anything is saved -- they are the
  same computation as the import itself. Reports are untrusted input: they are parsed inside the scanner
  sandbox (no network, read-only, no capabilities), limits are enforced while reading, XML entities are
  refused, a truncated file is an error and never a smaller report, and an SBOM cannot close anything.
  New scopes `ingest:read` / `ingest:write` (importing can close Issues; starting a scan cannot). New
  **Import a report** screen on each project. Migrations 0027 (persistent Tests, import records, event
  outbox) and 0028 (import lifecycle). Native scans now go through the same reimport decision and
  writer, so a scan no longer closes an Issue an imported report still lists. Fuzzing: an Atheris
  harness for the parsers (nightly CI job; `scripts/fuzz-ingest-docker.sh` runs it on a Mac).
  Verification record: [docs/v2-week54-verification.md](docs/v2-week54-verification.md).

### Fixed
- **Cross-tenant leak: a database session could run as another organization after a commit.**
  Row-Level Security reads `app.current_org` from the *connection*, but a session returns its
  connection to the pool on every commit and takes whichever is free next; the org was set once per
  session, so it could land on a connection the session never saw again and stay there for the next
  session to inherit. Reproduced on real Postgres: with two overlapping sessions for different orgs the
  first one's next statement after a commit ran as the second org. Only reachable with concurrent
  requests from different organizations (so single-org self-hosting was unaffected, and every
  single-session test missed it). The org is now re-applied, transaction-local, at the start of every
  transaction. Regression tests interleave sessions on a two-connection pool; all five fail without the
  fix.
- **Taint engine: a resolved call to an unrelated, same-named function could silently erase real
  taint** (`core/taint/python_flow.py`, `js_flow.py`, `go_flow.py`), found expanding v2's own taint
  engine spot-check from 1 repository to the full Python/JavaScript corpus
  ([docs/v2-gap-closure-taint-corpus.md](docs/v2-gap-closure-taint-corpus.md)): a textbook
  `request.POST.get(...)` → `eval(...)` case in pygoat went unconfirmed because `.get`'s only
  project-wide name match was an unrelated Django view's own `get` handler, whose irrelevant summary
  silently overrode the correct taint-preserving fallback. Also added `subprocess.Popen` (previously
  only `os.popen`) to the Python catalog's command-injection sinks. Taint confirmations across the
  corpus's 8 Python/JavaScript repositories went from 3 (one repository) to 9 (five repositories),
  all hand-verified true positives.

### Changed
- **The opening screen is now the product page.** `/` shows the hero, results and scanners
  (previously at `/about`, which now redirects there); the real Juice Shop scan replay moved to
  `/sample`, and `/demo` redirects to it. The header reads Home, Results, Scanners, Sample scan, App,
  and clicking a section from another page now scrolls to it and highlights it (the router's one-shot
  hash scroll used to land at the top of the page and leave the wrong item highlighted).
- **Incremental-scanning benchmark expanded from 1 corpus repository to 7** (NodeGoat plus pygoat,
  vulpy, dvna, VAmPI, Vulnerable-Flask-App, dvpwa), closing part of the same gap
  `docs/evaluation-v2.md` already disclosed. 6 of 7 show a real cache speedup (2.0x-13.1x); one
  repository showed only 1.2x, plausibly linked to a Semgrep per-rule timeout observed on that same
  repository, disclosed rather than smoothed over:
  [docs/v2-gap-closure-incremental-corpus.md](docs/v2-gap-closure-incremental-corpus.md).

### Added
- **Gate and hierarchy (Week 53, plan Phase 13/§39.5/§40, ADR-0038, ADR-0039):** the first week of
  v3. Re-running v2's own pre-v3 gate found that "the two-tenant RLS test passes on every endpoint"
  covered 4 of this API's 50+ endpoints, a scope that hadn't grown since Week 29/30 -- closed with a
  new cross-org test covering every `/assets/{asset_id}/...` and remaining `/scans/{id}/...` route
  against real Postgres. **Hosted mode** now runs Opengrep instead of Semgrep for SAST
  (`BULWARK_HOSTED_MODE`, default off -- self-host is unchanged), closing the plan's own licensing
  gate item: Semgrep's community rules are internal-use-only, and Opengrep's own bundled ruleset
  turned out to carry the identical restriction on inspection, so hosted mode ships a small,
  originally-written starter ruleset instead. New **Portfolio** and **Engagement** tables (plan §40:
  "teams group projects by business unit"; "pen tests and audits are time-boxed engagements") with a
  real data migration giving every existing project one "ci" Engagement and linking its scan history
  to it -- "Test" (one tool's results within an engagement) is deliberately not a third new table,
  since `ToolRun` already was exactly that. RLS and a two-tenant leak test cover both new tables,
  live-verified against real Postgres.

## [2.0.0] - 2026-10-02

Weeks 27-52 of the plan, Milestone M11: "v2.0 public launch." See
[docs/release-notes-v2.0.0.md](docs/release-notes-v2.0.0.md) for the organized-by-theme summary,
[docs/evaluation-v2.md](docs/evaluation-v2.md) for the measured numbers (and an honest list of what
still needs a live model to measure), and [docs/blog-v2.0.0.md](docs/blog-v2.0.0.md) /
[docs/technical-report-v2.md](docs/technical-report-v2.md) for plain-language and technical
write-ups. Everything below is the full week-by-week record since `v1.0.0`.

### Fixed
- **`docs/api.md` and `docs/openapi.json` had been stale for several weeks, with nothing to catch
  it.** Regenerating them while building Week 51's documentation site surfaced that the Week
  48-50 asset/threat-model/copilot/cost endpoints, and Week 51's own `/plugins` and
  `/settings/integrations`, were all missing from the published docs -- unlike
  `docs/severity-matrix.md`, which `tests/unit/test_correlation.py` already checks for freshness,
  nothing checked either of these two files against the live app. Fixed the drift, then closed the
  gap: `scripts/gen-api-docs.py` now exposes `openapi_spec()`/`api_doc()` as standalone functions so
  a new test (`tests/unit/test_api_docs_freshness.py`) can re-derive each file's expected content
  from the running app and compare, instead of a second hand-maintained copy of the derivation that
  could itself drift. Verified the test actually catches drift by deliberately staling one file,
  confirming the failure, and reverting.
- **`reap_stale_scans` silently reaped nothing in production (found during Week 50's own
  connection/RLS work, plan §23).** The housekeeping task that fails scans stuck in `queued`/`running`
  after a worker dies queried `scans` on a session with no `app.current_org` ever set. Under real
  Postgres RLS (`FORCE ROW LEVEL SECURITY`, ADR-0013) that query sees zero rows, not every org's --
  it only ever worked in the SQLite-backed unit tests, which have no RLS to enforce. Fixed by having
  it iterate one organization at a time with `core.tenancy.set_session_org` set explicitly, the same
  pattern `core.retention.shred_expired_scans` already used (and had already documented
  `reap_stale_scans` as needing). Verified against real Postgres, connected as the real worker's
  `bulwark_worker` role: a stuck scan in each of two organizations is now reaped correctly by one
  call with no org context set beforehand, which the old implementation could not do
  (`tests/integration/test_maintenance_rls_docker.py`, new).

### Added
- **Launch: benchmark v2, a live landing page, the v2.0.0 release (Week 52, plan §33-34):** four
  tasks closing out the v2 plan, none of them new architecture -- this week compiled, measured, and
  wrote up what the previous 25 weeks already built.
  [docs/evaluation-v2.md](docs/evaluation-v2.md) fills in every row of the plan's own evaluation
  table: four rows were real measurements scattered across earlier weeks and collected here for the
  first time (ranking, scale, platform security, OWASP/Juliet detection); the taint engine row is new
  real work -- a hand-verified spot-check against NodeGoat's own documented `eval()` injection
  vulnerability, confirming the engine's actual contribution over a plain pattern rule (proving the
  argument flows from the HTTP request, not just that `eval()` exists); five rows (verified fixes,
  triage assistant, hypotheses lane, Copilot, LLM attack-success-rate) are marked not measured --
  each needs a live model, already individually disclosed in Weeks 41-44's own verification docs, just
  collected here. The homepage's first screen is now a replay of a real scan of the real, public OWASP
  Juice Shop (271 real findings) instead of a static small-fixture report, reusing the exact
  `ScanReport`/`ToolCards` components the authenticated app's live WebSocket scan already uses, with
  every number shown real and only the wall-clock pacing compressed for a visitor's sake. Closed with
  [docs/release-notes-v2.0.0.md](docs/release-notes-v2.0.0.md), a plain-language
  [blog post](docs/blog-v2.0.0.md), an arXiv-style
  [technical report](docs/technical-report-v2.md) on correlation, taint-based ranking and verified
  fixes, a [demo-video script](docs/demo-script-v2.md) and a
  [conference-talk outline](docs/talk-outline-v2.md) (the video and the talk itself are explicitly
  left to the user), and the `v2.0.0` tag.
- **Ecosystem: Plugin SDK, Integrations, pre-commit hook, documentation site (Week 51, plan §23,
  ADR-0037):** four tasks extending where findings come from and go to, not scanning itself. The
  **Plugin SDK** (`core/plugins/`) lets a third-party scanner run through the same sandboxed
  `docker run` and golden-file conformance kit a built-in adapter does, discovered via a standard
  `bulwark.scanner_adapters` entry point and trusted only after a real keyless Sigstore signature
  check (re-verified on every use, not cached at allow-time) and a per-org allowlist; a real,
  installable example package (`examples/bulwark-plugin-demo`) proves the whole chain outside this
  repository's own source tree. **Integrations** (`core/integrations/`) adds Slack/Discord
  notifications, HMAC-signed generic outbound webhooks, and two-way GitHub Issues/Jira sync that is
  deliberately asymmetric -- an external close/reopen only updates sync metadata, never Bulwark's own
  authoritative issue state, so a real vulnerability can't be hidden by closing the wrong ticket --
  all sharing the same DNS-resolve-and-reject SSRF guard git ingestion already used (newly extracted
  into `core/netsafety.py`). The **pre-commit hook** (`core/precommit/`) is a native, no-Docker
  complement to Gitleaks/Bandit -- ~15 high-confidence secret patterns and 7 `ast`-based Python SAST
  checks, fast enough to run on every commit (`bulwark precommit run/install/uninstall`, plus a
  `.pre-commit-hooks.yaml` for the `pre-commit` framework); a real 238-file commit's timing found a
  genuine performance bug (one `git show` subprocess per staged file, 1.93s) fixed by batching every
  blob into one `git cat-file --batch` call (0.45s on the same commit). The new **documentation
  site** (`mkdocs.yml`, MkDocs Material) curates the existing `docs/` folder into a real nav --
  quickstart, a new architecture overview, a new plugin-authoring guide, the policy cookbook, and the
  API reference generated from the live app's own OpenAPI document -- rather than forking a separate
  site-source tree. Also fixed along the way: two of the four `tests/integration/*_rls_docker.py`
  files were silently never run in CI (`tenancy-rls`'s job only listed two by name).
- **Scale: Helm chart with KEDA autoscaling, k6 load testing, cost-per-scan dashboard (Week 50, plan
  §23, ADR-0036):** a new `helm/bulwark/` chart deploys the core product to Kubernetes (Postgres,
  Redis, object storage, OpenBao, the API, the worker, a new single-replica Celery beat split out of
  the worker specifically so it's KEDA-scale-safe, and the web app), with an optional KEDA
  `ScaledObject` that scales the worker on real Celery queue depth -- live-verified against a real
  `kind` cluster: a real 3,000-task backlog scaled the worker from 1 to 5 replicas in 16 seconds and
  drained it in under 30. New `k6/scan-submission.js` and `k6/browse-results.js` load tests, run for
  real against the dev stack, found and drove the fix for two genuine capacity bugs: a single uvicorn
  process couldn't serve 500 concurrent users (fixed with `--workers 4`), and the default SQLAlchemy
  connection pool combined with Postgres's default `max_connections` couldn't support that many
  processes at once (fixed by raising both, sized to add up correctly together). A new cost-per-scan
  dashboard (`core/observability/cost.py`, `GET /scans/{id}/cost`, `GET /costs/summary`, a new
  `/app/costs` page, and two new Grafana panels) estimates cost from data already tracked -- scanner
  compute seconds and LLM tokens used -- computed fresh on every call rather than stored, since a
  scan's LLM spend keeps growing after the scan itself finishes. Two more real, pre-existing bugs were
  found and fixed along the way: an `openbao` healthcheck that resolved `localhost` to `::1` first
  and never passed even against a healthy server, and three missing per-service Postgres roles from
  earlier historical drift that silently blocked every write.
- **DAST egress proxy wired into real campaign execution (Week 49b, plan §22.4 follow-up,
  ADR-0035):** a standalone task inserted before tagging `v1.5.0`, since Week 49's own M10 milestone
  claims "scope enforced at the network layer" and that wasn't true until now. `core.dast.pipeline.
  run_dast_campaign_job` starts a real `core.dast.proxy.BackgroundProxy`, scoped to exactly the
  campaign's one verified host, before running ZAP/Nuclei and tears it down after; both adapters gained
  a `proxy` parameter pointing the real tool at it (ZAP via its Network add-on's `httpProxy` config,
  Nuclei via its native `-proxy` flag). Blocked egress attempts (ZAP's own background telemetry calls,
  proven live) are now recorded on the campaign itself, as a `tool_runs` row and an audit-log entry,
  not just a log line nobody reads. Two real findings came from making this actually work: ZAP's
  proxy-config keys had moved to `network.connection.httpProxy.*` (the commonly-documented legacy keys
  are silently ignored by the shipped image's add-on version), found by inspecting its own compiled
  option class; and Nuclei's default templates legitimately contact third parties (a DNS resolver, a
  domain registry's RDAP API) that a single-host allow-list can't permit, fixed by restricting every
  campaign to `-pt http` unconditionally. Still disclosed as not done: this is cooperative, application-
  layer enforcement only -- the nftables backstop that would deny a scanner's direct egress at the
  network-namespace level regardless of its own cooperation is still Linux-only and untested on any
  real namespace, the same boundary Week 46 already drew.
- **DAST: ownership verification, scope-enforcing egress, safe scanning tiers, SAST/DAST
  correlation (Week 49, plan §22.4, ADR-0035):** registering a web target (`POST /assets/web`, or
  `bulwark asset add-web`) issues a DNS TXT or `.well-known` proof-of-control challenge; nothing can
  scan it until that passes a LIVE check, re-run (never cached) every time a campaign starts. A
  campaign is just a `Scan` row with `source_type="web"`: passive mode (ZAP baseline, spiders and
  observes only) runs unconditionally once verified; active mode (adds curated Nuclei, with
  `dos`/`fuzz`/`intrusive`/`bruteforce` templates excluded unconditionally in the adapter itself) is
  opt-in and rate-limited to one campaign per asset per 24h. A new `/app/projects/[id]/campaigns`
  screen starts campaigns and lists past ones; results render on the existing `/scans/{id}` report
  screen, unchanged. A real `bandit` scan's findings can now be marked "confirmed at runtime"
  (`core/dast/correlate.py`) when a DAST finding lands on the same route (extracted from real
  FastAPI/Flask decorators, `core/dast/routes.py`) and a related CWE -- verified against this
  project's own `api/main.py` (44 real routes found) and end to end against a real vulnerable Flask
  app. Also built and independently verified in this week, and wired into real campaign execution in
  the Week 49b follow-up above: a scope-enforcing allow-list egress proxy (`core/dast/proxy.py`) and
  the nftables policy (`core/dast/egress.py`). Three real bugs were found by testing against real
  infrastructure rather than mocks and fixed, each with a regression test: two scanner-report id
  collisions (ZAP's rule 90004, Nuclei's repeated-template reports) and a SQLite naive-datetime
  comparison that would have made every active campaign instantly rate-limit itself.
- **Verifying the platform itself: fuzzing, DAST self-scan, ASVS, supply-chain hardening (Week 48,
  plan §22.3, ADR-0034):** an Atheris fuzzing harness per scanner adapter plus a nightly CI job
  (written and reviewed, never executed -- Atheris needs a real Clang+libFuzzer build macOS doesn't
  ship) and three Hypothesis property tests for fingerprinting, fully local. A real ZAP baseline
  scan of the web app now runs in CI on every push; running it against the actual production build
  found three missing cross-origin isolation headers, fixed and re-verified. A full OWASP ASVS
  Level 2 self-assessment (`docs/ASVS-SELF-ASSESSMENT.md`), citing real code for every row, drove
  three more fixes: HSTS was only ever set for the public demo build (now an explicit
  `BULWARK_FORCE_HTTPS` opt-in), Bulwark had no vulnerability scanning of its own dependencies
  despite shipping that as a product feature (now a `dependency-audit` CI job plus Dependabot), and
  SECURITY.md's claimed archive "depth limits" didn't actually exist in `core/ingest.py` (now they
  do, tested). Two real gaps were found and left open, disclosed rather than hidden: no
  authentication rate limiting, no general API abuse-prevention. GitHub Actions are now SHA-pinned
  with least-privilege `permissions:` blocks; OpenSSF Scorecard runs weekly; a new release workflow
  generates SLSA Build Level 3 provenance and a keyless cosign signature for the app image, written
  but never triggered -- cutting a real release wasn't part of this pass.
- **Envelope encryption, crypto-shredding, mTLS, and secrets in OpenBao (Week 47, plan §22.2,
  ADR-0032/0033):** raw scanner output is now encrypted per scan with an OpenBao-held,
  per-organization key, AEAD-bound to its own storage key so a ciphertext can never be silently
  swapped onto a different scan's data; off by default, wired into the real production path
  (`core.tasks.run_scan_task`). An hourly sweep destroys a scan's data key once its organization's
  configurable retention window passes (default 7 days, a new Settings screen) --
  "deletion by crypto-shredding," never touching the scan or its issues. Every network connection to
  Postgres now requires a client certificate matching the connecting role: `api`/`worker`/
  `fixagent-worker` each get their own identity (inheriting the previously-shared `bulwark_app`'s
  grants via role membership, not duplicated by hand) instead of one shared credential; Temporal's
  third-party image is the one disclosed, deliberate exception. The GitHub App private key, its
  webhook secret, the API token, and the LLM API key all prefer a value from OpenBao's secret store
  now, falling back to their plain environment variable unconditionally (`bulwark secrets
  migrate-env` moves existing values over). Two real bugs were caught and fixed by testing against
  real Postgres/OpenBao rather than by inspection: a SQLite-only naive-datetime comparison that
  would have silently shredded nothing, and a cross-organization query that would have seen zero
  rows under real Row-Level Security instead of every organization's own rows. A third, pre-existing
  instance of that same RLS-scoping bug was found in the older `core.maintenance.reap_stale_scans`
  and flagged separately, out of scope for this week. See `docs/data-protection.md` for what's
  genuinely least-privilege today versus disclosed as deferred.
- **SandboxRuntime interface, a gvisor backend, and egress denial for fix verification (Week 46,
  plan §22.1, ADR-0031):** `core/sandbox/` introduces a `SandboxRuntime` protocol so the OCI runtime
  a scanner container runs under is a configuration choice, not a call-site change; `core.runner`
  defaults to the existing `DockerRuntime` (a pure refactor, full suite unchanged) with a `gvisor`
  backend written and argv-tested alongside it, though never yet executed -- `runsc` has no macOS
  build and no Linux dev host exists for this project yet. `core/fixagent/sandbox.py`'s
  test-execution sandbox now denies egress to the cloud metadata range and RFC1918 networks by
  default, applied by a purpose-built sidecar (`docker/egress-sidecar`) joined to the target's
  network namespace rather than from inside its own arbitrary image. Live-tested against real
  Docker, catching two real bugs first: a blanket RFC1918 deny broke DNS resolution (Docker's own
  embedded resolver lives in that range), and an unmirrored IPv6 allow let traffic bypass every IPv4
  deny rule. Firecracker itself, and a real Linux host to run any of this on for real, are explicitly
  deferred -- see `docs/sandbox-runtimes.md` for the honest gap and the runbook to close it.
- **Attack paths, threat model draft, and an LLM red-team suite (Week 45, plan §21.6/§21.7/§21.9,
  ADR-0030):** a ranked attack-path graph chains an asset's own open issues into a narrative from
  entry point to impact -- one rule is call-graph-verified (SSRF reachability), two are disclosed
  co-location heuristics. A Mermaid data-flow diagram plus a STRIDE table (`core/threatmodel/`)
  generates from code intelligence with no model call at all, editable and versioned per asset.
  `tests/redteam/` finally wires up a 20-payload adversarial corpus that had sat unused since an
  earlier week, running it against the real fix/triage/copilot pipelines -- caught and fixed a real
  bug along the way: `core/llm/prompt.py` and `core/triage_assistant/prompt.py` scrubbed secrets
  from a finding's code but never its title/description. Live-verified RLS isolation on the new
  `threat_models` table against a real disposable Postgres container, `bulwark_app`, not a
  superuser.
- **Security copilot (Week 44, plan §21.5, ADR-0029):** tool-grounded chat about one project.
  `core/embeddings/` chunks a checkout at function granularity off `core.codeintel`'s real parsers
  and embeds with the remediation knowledge base's own model-free `HashingEmbedder` (ADR-009) rather
  than adding a new embedding capability to the LLM gateway — checked first: no `LLMClient`
  implementation can embed today. New `code_chunks`/`code_chunk_indexes` tables (migration `0015`,
  RLS via `assets`); the pgvector/JSON column type was extracted from `core.rag.store` into
  `core.persistence.vector_type` so both tables share one implementation. `core/copilot/` reuses
  `core.fixagent.agent.propose_patch`'s tool-calling loop shape (bounded turns, native tool use,
  hosted-only per ADR-0027): five read-only tools (`query_issues`/`compare_scans` wrap the existing
  issues-table/scan-comparison repo functions, not new logic) plus a terminal `give_answer` tool
  whose citations are checked against real issue ids and files before an answer is ever returned
  (`core/copilot/contract.py`) — an invalid citation is rejected and retried, proven end to end
  against a fake client. Retrieval is automatic pre-loop grounding, not a sixth tool, matching the
  plan's own separate treatment of the two mechanisms. `core/copilot/session.CheckoutCache` clones
  an asset's latest scan once per conversation and reuses it for later messages (idle-TTL eviction,
  a per-conversation lock preventing two concurrent first-messages from double-cloning — proven with
  a real multi-threaded test). New `copilot_conversations`/`copilot_messages` tables (migration
  `0016`); the message table's RLS is a two-hop `EXISTS` through the conversation into `assets`,
  verified live and separately from the simpler one-hop case. Three endpoints
  (`POST .../copilot/conversations`, `POST .../conversations/{id}/messages`,
  `GET .../conversations/{id}/messages`) and a slide-in `CopilotPanel`, mounted on the issue detail
  and project overview pages — issue citations are real links, code citations render as plain text
  (this frontend has no jump-to-line view yet). A local backend routed to the copilot is rejected
  with a `409` rather than crashing (tool-calling stays hosted-only). 56 new backend tests (1370
  total, 93.0% coverage) and 6 new frontend tests (179 total); mypy/ruff/black and
  `tsc --noEmit`/`next build` all clean; both migrations validated live (up/down/up, plus a real
  cross-org RLS proof including the two-hop policy) on a disposable Postgres; the panel driven
  through a real browser against a real, disposable API server on both pages it's mounted on. Honest
  gaps (no live hosted-model run, no promptfoo suite for the tool-calling prompt — consistent with
  `core/fixagent`'s own, no measurement against the plan's 100-question reference set, the
  scan-comparison page's copilot context not wired up) disclosed in
  `docs/v2-week44-verification.md`.

- **Triage assistant and Hypotheses lane (Week 43, plan §21.3/§21.4, ADR-0028):** two related LLM
  features. The **triage assistant** reads one Issue's taint path and code and returns an advisory
  verdict (`likely_real`/`likely_false_positive`/`unsure` + rationale + supporting lines,
  `core/triage_assistant/`) — a deliberately separate JSON contract from remediation's (which must
  never dismiss a finding) so both guarantees hold without either trusting the other. The verdict
  feeds `core.risk.score` as a bounded multiplier (0.6-1.15, never past a KEV floor) starting with
  the asset's *next* scan (`core.pipeline` looks it up by fingerprint before scoring) — proven end to
  end by running two real scans of the same asset through the real pipeline. It never touches the
  human `triage_status`. New `POST/GET /assets/{asset_id}/issues/{issue_id}/triage-assistant` and an
  issue-detail panel. The **Hypotheses lane** (`core/hypotheses/`) is a separate, off-by-default tab
  for flaws pattern-based scanning can't express — v1 detects one type, a route with no recognized
  authorization marker in a file where a sibling route has one, found by an entirely deterministic
  pass over `core.codeintel` (new `Entrypoint.auth_markers`, populated for Python decorators and
  Express middleware). The model's only job is judging each deterministic candidate, never inventing
  the pattern itself. Off by default, excluded from the risk score, and never in the main issue list
  until a person promotes one (`source="llm-confirmed"`, a new `IssueRow` column) — promotion is a
  direct insert, deliberately not `core.issues.sync` (which would misread every other open issue as
  fixed if handed one synthetic finding; proven with a real second Issue left untouched). New
  `hypotheses` table (migration `0014`, RLS via `assets`) and
  `POST /assets/{asset_id}/hypotheses/generate`, `GET .../hypotheses`,
  `POST .../hypotheses/{id}/promote|dismiss`, plus a new `/app/projects/[id]/hypotheses` tab. Two new
  promptfoo suites (`core/llm/prompts/triage/`, `core/llm/prompts/hypotheses/`). 79 new backend tests
  (1295 total, 92.4% coverage) and 10 new frontend tests (173 total); mypy/ruff/black and
  `tsc --noEmit`/`next build` all clean; both migrations validated live (up/down/up) with a real
  cross-org RLS proof on Postgres; both new panels driven through a real browser against a real,
  disposable API server. Honest gaps (no live hosted-model run for either feature, no OWASP
  Benchmark/Juice Shop measurement, IDOR/mass-assignment not implemented, no Go/Django auth-marker
  extraction) disclosed in `docs/v2-week43-verification.md`.

### Added
- **Verified-fix agent (Week 42, plan §21.2, ADR-0027) — "the flagship v2 feature":** proposes a
  patch for an Issue, verifies it for real (reruns the originating rule, reruns every scanner on the
  changed file, optionally runs the project's own tests in an opt-in, verified-GitHub-Installation-
  owner-only sandbox), then waits for a human to approve or reject before ever opening a pull
  request -- never auto-merged. Implemented as a Temporal workflow (`core/fixagent/workflow.py`),
  the first one in this codebase (everything else uses Celery); durability validated live (killed
  the worker mid-run, a fresh worker resumed correctly from Temporal's own history). The propose-
  patch step is this repository's first tool-calling code (`core/fixagent/agent.py`,
  `read_file`/`search_code`/`get_call_path`/`propose_patch`; hosted/Anthropic only), scrubbing and
  redacting every tool result through Week 41's existing secret/PII layers before it reaches the
  model. Pull requests open through a new GitHub Contents-API integration
  (`core/fixagent/github_pr.py`) -- no local git needed, since `core.gitfetch.clone_repo` already
  strips `.git` from every checkout. New `verified_fix_runs` table (migration `0012`, RLS-protected)
  and `POST/GET /assets/{asset_id}/issues/{issue_id}/verified-fix[/approve|/reject]`; two new scoped-
  token scopes, `fixes:read`/`fixes:write`. `docker-compose.yml` gains `temporal`/`temporal-ui`/
  `fixagent-worker` behind a new `--profile fixagent`. The fix-review screen
  (`web/components/VerifiedFixPanel.tsx`, plan §28.4) shows the verification record before the diff
  ("trust before content") and failed attempts, not just the final patch. ADR-0015's three safety
  limits (a per-attempt timeout, an overall timeout excluding the human-approval wait, a per-org
  concurrency cap) got real numbers this week, plus a distinct `inconclusive` terminal state so a
  timeout is never shown as "this fix doesn't work." 65 new backend tests (1216 total) and 8 new
  frontend tests (163 total); mypy/ruff/black and `tsc --noEmit`/`next build` all clean. Honest gaps
  (no live GitHub App or hosted-model run in this environment, no MLX tool-calling, no "Edit" action,
  no precise sandbox capability set) disclosed in `docs/v2-week42-verification.md`.

### Added
- **Model gateway and LLMOps (Week 41, plan §21.1, ADR-0026):** a real local backend (`core/llm/ollama_client.py`,
  plain HTTP to Ollama, no SDK) alongside the existing hosted Anthropic one, chosen per task through a new
  `core/llm/gateway.py` (`Task`/`Backend` enums, per-task route overrides). Privacy mode
  (`BULWARK_LLM_PRIVACY_MODE=1`, or `bulwark llm suggest --privacy`) forces every task onto the local backend and
  refuses outright, never falling back to hosted, when no local model is ready. Token budgets, in real tokens (not
  call counts): a running per-scan counter (`Scan.llm_tokens_used`, migration `0011`) and a per-organization
  per-month counter (`llm_usage`, RLS-protected), both a hard `429` stop before a call, both fed by the provider's
  own reported usage (`LLMClient.complete` now returns a `Completion(text, tokens)`). A second redaction layer
  (`core/llm/pii.py`, optional `bulwark-scan[pii]` extra, Microsoft Presidio) removes free-text personal data after
  the existing secret scrubber runs; a path denylist (`core/llm/pathguard.py`: `.env`, `*.pem`, `id_rsa*`, ...)
  withholds code by path alone, regardless of a finding's scanner category. A rejected reply now gets one repair
  attempt (a fixed, generic instruction, never the rejected reply itself) before falling back to static text. The
  system prompt moved from an inline string to a versioned file (`core/llm/prompts/fix/v1.md`), with a real
  `promptfoo` evaluation suite (`core/llm/prompts/fix/promptfooconfig.yaml`) that runs through the actual gateway
  and the actual contract validator against pre-rendered real prompts. 34 new backend tests (1151 total, up from
  1117; 94.3% coverage); mypy/ruff/black clean. Full account, including two integration bugs the promptfoo suite itself
  caught, in `docs/adr/0026-model-gateway.md` and `docs/llm-remediation.md`.

### Added
- **Dependencies screen (plan §20.5), a follow-up to Week 40's supply-chain risk work (ADR-0025):**
  Week 40 built SBOM parsing, typosquat detection, and OpenSSF Scorecard enrichment as pure library
  code, reachable only via CLI commands, with the hosted screen explicitly deferred. This closes that
  gap: `core/sbom/syft.py::SyftAdapter` is now registered in `core/scan.py`'s `ADAPTERS`, selectable
  via `Scan.tools` (and the web UI's own scan-creation form) exactly like any other optional tool.
  `core/pipeline.py::_process_sbom` reshapes its raw CycloneDX output into typosquat Findings (folded
  into the normal correlate/finalize/persist pipeline -- they get real Issue tracking for free) and a
  JSON summary on a new `Scan.sbom_summary` column (migration `0010`; one nullable JSON column, no
  new table, matching `FindingRow.data`'s own pattern). `GET /assets/{asset_id}/dependencies` serves
  it, empty rather than 404 when no scan has opted in, mirroring `/assets/{id}/issues`. The new
  `/app/projects/{id}/dependencies` page renders a filterable package table (direct/transitive/root,
  license, Scorecard) with each row expandable to its own path-from-root -- a client-side BFS over
  the same graph `core.supplychain.dependency_view.path_to` walks server-side, deliberately not a
  drawn graph, since no graph-drawing library exists in this codebase and the actual need (a small
  tree, shortest-path) didn't warrant adding one. 7 new backend tests (1117 total), 5 new frontend
  tests (155 total). Full account in `docs/adr/0025-dependencies-screen.md`.

### Fixed
- **Nine issues from a code review of Weeks 37/38's code-intelligence and taint-analysis work
  (`core/codeintel/`, `core/taint/`), none previously fixed:**
  - Django `urlpatterns` entries were keyed by the enclosing list's own line, not each route's own
    line, so two routes sharing a path string in one list collided on `symbol_id` and one silently
    lost all its taint findings (`core/codeintel/python_lang.py`). Now keyed per entry.
  - `core/codeintel/resolve.py`'s name-resolution index was built from the already
    id-deduplicated symbols dict, so a rare `symbol_id` collision resolved a call confidently to
    whichever symbol survived instead of correctly staying ambiguous. `CodeGraph` now also carries
    every symbol as originally emitted (`all_symbols`), and the index is built from that.
  - Python taint re-exposure only checked `call.args[tag]`, silently missing a callee's tainted
    parameter passed as a keyword at the call site (`helper(x=user_input)` instead of
    `helper(user_input)`) — a real false negative. `FunctionSummary` now also carries
    `param_names`, letting the call site resolve a tag to a keyword argument by name.
  - Python `try`/`else` was walked as a branch starting from the state *before* the `try` block,
    not after its body completed, so `else` could not see taint the `try` body introduced — `else`
    only ever runs once `try` succeeds, so this was a real missed detection.
  - JavaScript compound assignment (`x += y`) is its own tree-sitter node type
    (`augmented_assignment_expression`), distinct from plain assignment, and matched no branch at
    all — a silent no-op that never updated `x`'s taint.
  - A C-style `for` loop's initializer clause was never visited in either JavaScript or Go
    (independently, in each language's own tree-sitter grammar) — only the loop body was walked, so
    `for (let i = tainted(); ...)` / `for i := tainted(); ...` lost `i`'s own taint entirely.
  - The branch-merge/union algorithm central to all three languages' analyses was reimplemented
    identically three times (plus a fourth, separate inline copy in Go's `else if` handling);
    extracted into `core/taint/models.py::merge_taint_states`/`union_taint`, used by all three.
  - `CodeGraph.callers_of`/`calls_from` did an O(edges) linear scan on every call, and
    `core.taint.engine`'s worklist calls `callers_of` once per changed function summary per pass —
    now backed by a lazily-built reverse/forward index.

  8 new regression tests, one per confirmed bug (the merge-algorithm and index fixes are
  behavior-preserving). Full test suite (1110 tests) and mypy/ruff/black all clean.

### Added
- **Week 40 — Supply-chain risk (plan §20.5), closing Milestone M8 (`v1.3.0`):** a `MAL-` id (an
  OSSF malicious-packages report) already flowed through `osv-scanner`'s own offline OSV database as
  an ordinary `Finding`, but with no CVSS score or severity label it normalized to `INFO` — the
  *lowest* severity, exactly backwards. `core/adapters/osv_scanner.py` now forces `CRITICAL`
  severity and full confidence for one, and `core/policy/input.py` exposes it as `malicious` (a
  sixth starter policy rule: no malicious packages, ever). `core/sbom/syft.py` now parses each
  CycloneDX component's license and derives a direct/transitive dependency graph from Syft's own
  `dependencies` array (validated against a real `bulwark/syft:1.52.0` run); `core/sbom/enrich.py`
  joins that license onto a finding's package, and `bulwark ci compare --sbom PATH` (also wired into
  the Action's existing `sbom: true` input) feeds it to policy evaluation — closing the `license`
  field ADR-0023 left wired but unpopulated. New: `core/supplychain/typosquat.py` (edit-distance 1–2
  from a curated popular-package seed per ecosystem), `core/supplychain/scorecard.py` (OpenSSF
  Scorecard for direct dependencies via deps.dev + the Scorecard REST API, both validated live,
  cached a week), and `core/supplychain/dependency_view.py::path_to` (which path in the graph pulls
  in a package), tied together by `bulwark supply-chain analyze`. Also fixed a real, if minor,
  pre-existing bug found while building this: `osv_scanner.py`/`grype.py` picked a scanner's
  *first-listed* fixed version, not the smallest (`core/scoring/versions.py::smallest_safe_upgrade`)
  — confirmed unchanged output on this repo's own golden fixtures, which mix git-hash and real-version
  entries for the same finding. The Dependencies screen UI is deliberately deferred — full reasoning
  in `docs/adr/0024-supply-chain-risk.md`. 52 new tests. Full account in
  `docs/v2-week40-verification.md`.
- **Week 39 — Policy-as-code (plan §20.4):** a new `core/policy/` package embeds the real Open
  Policy Agent binary, matching the plan's own worked example (`opa eval` with a JSON input document
  built from existing `Finding` fields, no new data collection). The five starter policies the plan
  names — no reachable KEV vulnerability, no secrets, no new critical-severity issues, a license
  denylist, accepted risk capped at 90 days — are real, tested Rego (`core/policy/starter/`), with a
  full `opa test` suite run both in the project's own CI and inside the normal `pytest` run.
  `bulwark ci compare` gained `--policy PATH`, folding policy denials into the exact same exit-code,
  markdown-comment, and `$GITHUB_OUTPUT` contract the severity threshold already used, not a second
  one; `action.yml` gained a `policy-file` input (OPA is only installed when it's actually set) and a
  `policy-violations` output. The license-denylist and 90-day-acceptance rules are real and tested
  but currently unreachable in practice — their data sources (Week 40's SBOM/license work; an
  org-scoped `triage_expires_at`, only available to the hosted pipeline, not the standalone CLI/Action)
  don't fully exist yet, and the input builder omits the field entirely rather than sending a
  fabricated value. The plan's own policy-editor UI (Monaco, live evaluation, save gated on
  `opa test`) is deliberately deferred — full reasoning in `docs/adr/0023-policy-as-code.md`. 25 new
  tests, `tests/integration/test_policy_opa.py` skips gracefully without `opa` on `PATH`. Full account
  in `docs/v2-week39-verification.md`.
- **Week 38 follow-up — Taint paths attached to Issues, feeding scoring and the UI (plan §20.3,
  §28.3):** closes the three items deferred from the taint engine's initial landing. A `Finding`
  now carries a `taint_path` (`core/models/finding.py`), attached by
  `core/taint/reachability.py::attach_taint_paths()` when a SAST finding's own location matches a
  real taint-confirmed sink — enrichment only, never a new finding. This raises the finding's
  `scoring.confidence` (reusing `core/risk/score.py`'s existing confidence-driven likelihood for
  non-CVE findings, rather than a second scoring rule) and sets `scoring.reachable = True` through
  the same `Assess` composition `core.reachability` already uses in `core/postprocess.py::finalize()`
  — measured effect on a HIGH-severity SAST finding: risk_score 56 → 71. No new database table: the
  path persists through the existing `findings` table's JSON column. Per-step code snippets are
  captured from the scanned workspace at attach time (the one point the checked-out source is
  guaranteed to still exist), so the UI's taint-path stepper — built in an earlier week, deliberately
  "static until Phase 9 supplies real paths" — now renders every real hop, defaults to opening on the
  sink rather than step 1, and moves the code view to each step's own file and line as it's clicked.
  Full account in `docs/adr/0022-taint-issue-scoring-ui.md`.
- **Week 38 — Taint analysis (plan §20.3):** a new `core/taint/` package traces concrete
  source-to-sink data-flow paths from real HTTP entrypoints, built on Week 37's call graph.
  Per-language intra-procedural flow analysis (Python via `ast`, JavaScript/TypeScript and Go via
  tree-sitter) tracks tainted variables through assignments, branches, and calls; YAML catalogs
  per language name sources (request parameters, per the plan's own wording), sinks
  (`cursor.execute`, `subprocess.run`, `eval`, unescaped template rendering), and sanitizers
  (parameterized queries, escaping functions). Function summaries are computed once per function
  and propagated over the call graph via a bounded worklist (`core/taint/engine.py`), so a handler
  that calls a helper that calls the real sink is analysed once per function, not once per call
  site, with a full hop-by-hop chain from entrypoint to sink. Validated against three real,
  independently-known-vulnerable applications, not synthetic fixtures: Vulnerable-Flask-App's
  SQL injection in `/search`, NodeGoat's own `eval()` injection in `/contributions` (its own code
  comment: *"Insecure use of eval() to parse inputs"*), and Snyk's nodejs-goof command injection
  in `exports.create` — all three confirmed present before trusting the tool's own output.
  Cross-checked against Semgrep's own taint mode as the plan requires: exact agreement on
  NodeGoat's `eval()` lines, and a fully explained anchor-line difference (sink call vs.
  string-construction site) on the same SQL injection, not a silent disagreement. Real-world
  testing also surfaced and fixed a serious, previously-invisible bug: tree-sitter-typescript
  wraps every function parameter differently than plain JavaScript, so every TypeScript handler's
  request parameter was silently never seeded as a taint source at all until this was caught by a
  deliberate `.ts` smoke test (neither of the two JS benchmark repos used to validate this week
  contains any TypeScript). Postgres persistence and Issue/UI integration are deliberately
  deferred, per ADR-0021. Full account in `docs/v2-week38-verification.md`.
- **Week 37 — Code intelligence: symbols, call graph, entrypoints (plan §20.2):** a new
  `core/codeintel/` package builds, per repository, a `Symbol` table, a resolved call graph, and
  a list of framework `Entrypoint`s (FastAPI, Flask, Django, Express, Next.js App/Pages Router,
  Go `net/http`) — foundation for Week 38's taint analysis, not yet wired to it. Python parses
  with the standard `ast` module (matching `core/reachability/imports.py`'s existing precedent);
  JavaScript/TypeScript and Go parse with tree-sitter (`tree-sitter-go` added this week). Call
  resolution is intra-file-first, then repo-wide only if the name is unique, leaving ambiguous or
  unmatched calls unresolved rather than guessed — the same "unknown stays unknown" discipline
  `core/reachability/index.py` already established. Validated against a real application
  (NodeGoat), not just synthetic snippets, which surfaced and fixed three real gaps: Express
  routes registered as an object method (`app.get('/login', sessionHandler.displayLoginPage)`)
  weren't recognized as entrypoints at all (2 of NodeGoat's ~19 real routes detected before the
  fix, 19 after); the pre-ES6 "constructor function" idiom
  (`this.method = (req, res) => {...}`) — NodeGoat's entire route-handler layer — had no matching
  case, so those handlers were never registered as symbols and every call to them was permanently
  unresolvable (fixing it raised NodeGoat's resolved-edge rate from 3.6% to 12.9%); and a
  three-site `("arrow_function", "function")` type check never actually matched a plain
  `function () {}` expression, because tree-sitter's own JS grammar names that node type
  `function_expression`. Postgres persistence of the graph (the plan's literal wording) is
  deliberately deferred to Week 38, whose taint engine will be the graph's first real consumer and
  should inform the schema rather than it being guessed at now — recorded in
  `docs/adr/0020-code-intelligence-call-graph.md`. Full account, including the honest limits of
  name-based resolution, in `docs/v2-week37-verification.md`.
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
- **The opening screen is now the product page.** `/` shows the hero, results and scanners
  (previously at `/about`, which now redirects there); the real Juice Shop scan replay moved to
  `/sample`, and `/demo` redirects to it. The header reads Home, Results, Scanners, Sample scan, App,
  and clicking a section from another page now scrolls to it and highlights it (the router's one-shot
  hash scroll used to land at the top of the page and leave the wrong item highlighted).
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
