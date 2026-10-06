# Week 66 verification: rules editor, notifications, tickets (plan §49, §45, §55.7)

A factual record of what was built, run and measured. The decision is
[ADR-0050](adr/0050-notifications-and-ticket-sync.md).

## What was built

- **The rules editor** (§55.7). Trigger, condition and action builders; a Rego view showing the
  module OPA runs; "Test this rule" on the unsaved draft; OPA's errors by the condition; editing an
  existing rule. A gallery of nine templates on the Automation page, each saying what it still needs.
- **New rule actions:** put in a group, file or update its ticket; notify can name people.
- **Notifications** (§49). Watchers (automatic from taking part, or by hand). An inbox with an unread
  count in the header. Email through the operator's SMTP server. For each of eight kinds of event,
  in-app off or instant and email off, instant or daily digest, per person, with an address and a
  digest hour. For the team channels -- Slack, Discord, Microsoft Teams (new) and the outbound
  webhook -- four kinds, each off, instant or digest. A settings page for both.
- **Tickets** (§49). Per-project settings: Jira or GitHub Issues, who owns the status, and a status
  map. Filing (an Issue, or its group), syncing both ways by webhook, a ten-minute poll, and "Sync
  now". A ticket panel on the issue page with its status, assignee and group.
- **Issue groups**, one ticket each, made on the issue page or by a rule.
- **Migration 0038.** `notifications`, `issue_watchers`, `notification_prefs`, `issue_groups` and
  `ticket_configs` under forced RLS; `issues.group_id`; what a ticket last said on its link; a Teams
  webhook in integration settings.
- **Deployment.** `BULWARK_SMTP_*` and `BULWARK_PUBLIC_URL` in Compose and the Helm chart (password
  in the chart's secret); `helm lint` passes.

## Found and fixed along the way

1. **Found by sending real email to Mailpit:** an issue title containing a line break stayed out of
   the headers (Python's email package folded it into the Subject, no `Bcc` header was added), but in
   the plain-text body it started a new line, so a title could fake a line of a digest. Titles are now
   one line wherever they go.
2. **Found in the browser:**
   - A native scan's completion event carried no counts (only an import's did), so a rule reading
     `input.scan.counts.new` -- which the catalogue advertises -- never matched a scan. Scans now
     count their new, reopened and closed Issues.
   - After a ticket sync marked the Issue ready for retest, the retest panel on the same page still
     said "no retest requested". The panels that show it now reload.
   - A new ticket showed "not read yet, synced never" until someone pressed Sync. Filing now reads it
     once (a first read never acts).
   - When a ticket asked for a retest, the watcher got two notifications saying the same thing, one
     of them naming the actor as `ticket:PAY-1`. Now one, in words; the retest panel says "asked by
     its ticket, PAY-1".
   - The editor's dropdowns were each a full line wide (a global stylesheet sets every select to
     100%); rows now sit on one line. The settings table's row labels had the global table-header
     style. The template hint read "action 1, to"; it now says "choose who action 1 assigns to".
     "No rules yet." appeared twice.
   - The assignment email's body said "Critical in the project."; it names the project.
3. **Found by the tests:**
   - The GitHub webhook handler reused the name of the app state for the issue state (mypy).
   - Typing a second tag or person in the editor was impossible: the input dropped the trailing space.
4. **Found while reading the code:** Jira's address was never checked by the SSRF guard (only the
   webhook URLs were), and the new poll calls it on a schedule. It is now checked when saved and
   before every call.

## Checked against real systems

- **Email, through a real SMTP server** (Mailpit v1.31.4 in Docker, `axllent/mailpit@sha256:b68349e3…`):
  an instant mention email, a daily digest with the pending assignment, and in the browser run the
  rule's assignment email to Priya. Raw messages read back: `text/plain`, `Auto-Submitted:
  auto-generated`, a link built from `BULWARK_PUBLIC_URL`, and no injected header.
- **In a browser against the real API** (SQLite, a beat thread, Mailpit for email, three named
  tokens; Jira answered by the recorder below; Slack and Teams captured locally, nothing posted):
  - As Meera (Admin): opened "Critical issues go to the on-call" from the gallery; "Test this rule"
    without a person showed "Name a person by their @handle." under that action; with Priya chosen,
    "This rule would have matched 1 issue in the last 7 days"; the Rego view showed the module;
    saved.
  - As Priya: set email at once for assignments. A scan brought a new critical Issue: the rule
    assigned it to her and set P1; her inbox showed it with the unread count, and Mailpit received the
    email. On the issue page: watching (as assignee), "File a ticket in Jira" made PAY-1 and showed
    "To Do" at once; the ticket moved to "In Review" (mapped), "Sync now" showed it, the Issue became
    ready for retest "asked by its ticket, PAY-1", the history said "Marked ready for retest by its
    ticket, PAY-1", and her inbox said so once. A new group "Secrets in settings" from the panel.
  - A "scan completed" rule with the message `<!channel> look at these` reached Teams as an Adaptive
    Card with `\<!channel\>` and Slack as `&lt;!channel&gt;`: no channel was pinged.
  - At phone width the editor has no element wider than the page (the shell header still overflows,
    as before).
  - Native dropdowns in the browser pane could not be driven by clicks; two were set by script,
    which fires the same change handler.
- **Postgres under forced RLS** (throwaway pgvector container, worker role): 56 integration tests
  pass, one new. Notifications are made from the outbox on Postgres; another org sees none of the new
  rows, its inbox for the same token handle is empty, and its dispatcher finds nothing. With RLS
  turned off on `notifications`, the new test fails.
- **Migration 0038 on Postgres:** up, down (tables and `issues.group_id` gone), up again.
- **Totals.** Backend unit tests: 2,628 pass (18 new: 16 for notifications and tickets, 2 for the
  templates and scan counts), coverage 92%; `ruff` (apart from the older import-order warning), `black`
  and `mypy` clean. Web: 321 tests (9 new, with axe), `tsc` clean.

## What this does not prove

- **Jira and GitHub Issues were never called.** Every ticket test and the browser run used a recorder
  answering in the documented response formats (Jira Cloud REST v3: create, read with status
  category and assignee, transitions, edit with label verbs, comment; GitHub REST: create, read,
  update, comment). A real site may differ; the first real sync should be watched.
- **Microsoft Teams was never posted to.** The card follows the Workflows webhook format.
- **Slack and Discord** were captured, not posted.
- **No Celery worker ran.** The digest and ticket poll tasks wrap `run_digests` and `sync_due`, which
  the tests call directly. The browser run's digest was not reached (the hour was not due).
- People are tokens until Week 75; an inbox belongs to a token.
- The calendar's SLA list reads up to 5,000 Issues per project and says when it stopped there; it
  was not measured at that size.

## Added after the week: the calendar (plan §49)

The week's schedule did not list §49's "calendar of engagements, SLA due dates, and expiring risk
acceptances", so it was built separately, on request.

- **What it is.** `GET /v2/calendar?from=&to=&project_id=&kinds=` (UTC days, at most 100 at a
  time) gathers each assessment from its start to its close or planned end, each open Issue's SLA due
  date in the range (as its project's policy computes it; exempt Issues left out), and each approved
  risk acceptance, or waiting request, whose date falls in the range. A Calendar page in the header
  shows a month, Monday first, with filters by kind and project, and the same entries day by day
  beneath, which is all a phone shows. No migration: it reads data Bulwark already has.
- **Tests.** 3 backend tests (one compares every SLA date with the date the issues table shows for
  the same Issue; another org sees nothing; exempt, fixed and withdrawn things leave it) and 3 web
  tests (weeks laid out Monday first in UTC, engagements spanning days in the grid but named once in
  the list, the request covering the whole grid, filters, axe).
- **In the browser** (two projects, starter SLA, issues aged 1 to 60 days, a planned pentest, an
  expiring acceptance): the month showed 4 breached SLAs in red, 8 still to fall due, the pentest
  across its 12 days and the acceptance on its day; the project filter cut it to the 6 storefront
  dates; at phone width the grid gives way to the list with nothing wider than the page; an entry
  opened its engagement.
- **Fixed on the way:** the filter toggles had a global label margin; breached SLAs were red in the
  grid but not in the list.
