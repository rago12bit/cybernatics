# ADR-0050: Notifications by kind and channel; tickets with one owner per field; groups on one ticket

Status: Accepted (2026-10-06), Week 66 (plan §49, §45, §55.7). Builds on
[ADR-0049](0049-rules-engine.md) (the outbox dispatcher, rules), the Week 51 integrations
(`core/integrations`, one-way filing and status metadata) and
[ADR-0048](0048-engagements-retests-collaboration.md) (mentions as outbox events, people as tokens).

## Context

Plan §49 asks for watchers and "notification preferences per event and per channel (in-app, email,
Slack, Teams, webhook), with a daily digest option so notifications don't become noise", and for
"ticketing sync with Jira and GitHub Issues in both directions. Issue groups map to one ticket.
Status mapping is configured per project. For each field, one side is the source of truth (status
from the ticket, severity from the platform) instead of last-writer-wins." Week 64 left mentions
and retests as outbox events nobody delivered. Week 51 could file a ticket per new Issue and record
a ticket's open or closed state, but never acted on it. §55.7 asks for a rules editor with a Rego
view, "Test this rule", and a template gallery.

## Decision

**Two audiences, two sets of channels.** A person hears through the in-app inbox and email; the team
through the organization's Slack, Discord, Microsoft Teams and outbound webhook together. For each
kind of event each channel is off, instant or in the daily digest, at the hour the person or team
chose (UTC). A missing preference is the default -- in-app instant and email in the digest for
people; instant for the team, which is what every organization already had -- so a new kind needs no
migration. The existing team notifiers (scan summaries, SLA crossings, risk acceptances, a rule's
notify) ask one gate first: instant sends as before and now to Teams too, digest stores the line,
off drops it.

**Who hears what is decided from the outbox**, by a second subscriber to the dispatcher: mentions to
the person mentioned; new notes, retests, SLA crossings and ticket status changes to the Issue's
watchers (and its assignee); assignments to the assignee; risk acceptances to the named approver and
then the requester; a held rule run to every person who can confirm it. Taking part makes you a
watcher (assigned, mentioned, wrote a note, asked for a retest), and anyone can watch or stop. The
person who caused something is not told about it. Each notification is written once per (person,
event, kind), so a redelivered batch never notifies twice.

**Text is plain everywhere.** The inbox renders text; email is text/plain with header values stripped
of line breaks; a notification's title is collapsed to one line, so an issue title cannot add an
email header or fake a line in a digest. Slack text is escaped and Discord mentions are off (Week
65); Teams cards escape the Markdown characters that make links and emphasis.

**Email goes through the operator's SMTP server**, configured for the deployment (`BULWARK_SMTP_*`)
because it is a server the operator runs or rents, not something an organization should point
anywhere. No host: email is off and the settings page says so; digest items that cannot be sent are
marked skipped, not retried forever. An address is stored per person, set by that person; the audit
log records that it changed, not what it is.

**Tickets: one source of truth per field.** A project's ticket settings name Jira (project key) or
GitHub Issues (repository), using the organization's stored credentials.
- *Summary, severity, description:* Bulwark's. Severity is a `bulwark-severity-*` label; labels
  someone added by hand are kept (Jira by `add`/`remove` verbs, GitHub by merging). A sync writes only
  when what Bulwark owns changed (a digest of what it last pushed).
- *Status:* the ticket's, by default. Each ticket status maps to nothing or to "ready for retest"
  (defaults: Jira's `done` category and GitHub's `closed` -> ready for retest; `closed (not
  planned)` -> nothing). **Bulwark never marks an Issue fixed because a ticket closed**: a scan, a
  targeted retest or a tester decides, as before. When the Issues on a ticket are all fixed or one
  comes back, Bulwark comments. A project may instead give the status to Bulwark: then it closes
  and reopens the ticket (Jira by status category, so no per-workflow transition ids) and ignores
  what the ticket says.
- *Assignee:* the ticket's, shown on the Issue, never written. Mapping Jira or GitHub accounts to
  Bulwark people waits for real user accounts (Week 75).
Changes arrive by the existing webhooks and by a poll every ten minutes of tickets not synced for
ten minutes, so a Bulwark that Jira cannot reach still syncs. Every call to Jira passes the SSRF
guard first (its address is an operator setting, now also checked when saved); GitHub is always
api.github.com. A project with ticket settings is no longer filed issue by issue by the Week 51 path.

**Groups.** An Issue belongs to at most one group in its project. Filing a grouped Issue files the
group: one ticket titled with the group's name and count, a link row for each member; an Issue that
joins later is added to the same ticket with a comment. Rules gain "put in a group" and "file or
update its ticket", and notify can name people.

**The editor writes Rego.** Trigger, condition and action builders produce the condition's Rego
lines; the Rego view shows them inside the fixed module OPA runs, and editing there makes the
condition hand-written -- the builder takes over again only if every line is one it can show.
"Test this rule" runs the server's dry run on the unsaved draft, and OPA's own errors appear by the
condition with the condition's own line numbers. The gallery ships nine whole drafts, each with what
it still needs from you; a test saves every one.

## Consequences

- Jira and GitHub were exercised only against responses in their documented formats, never a live
  site; that is recorded as unproven until a real site is used.
- Teams' Workflows webhook format follows Microsoft's documentation; nothing was posted to Teams.
- "A person" is still a token: one person with two tokens has two inboxes.
- The digest is per person or team, once a day; there is no weekly digest and no per-project
  routing of team channels.
- The §49 calendar (engagements, SLA due dates, expiring risk acceptances) was added after this week
  as a read of existing data (`core/calendar.py`, `GET /v2/calendar`, the Calendar page): no table
  of its own, and SLA dates the same as the issues table's because both compute them from the policy
  in force.
