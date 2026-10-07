# ADR-0057: Saved views as named queries; bulk changes previewed, count-checked and undoable

Status: Accepted (2026-10-07), Week 73 (plan §56). Builds on [ADR-0056](0056-issue-search.md)
(the query language) and follows the dashboards' sharing model (Week 71).

## Context

Plan §56 asks for saved views "personal or shared with a role", a column chooser and density
"remembered per person", and "bulk actions across pages ('Select all 1,204 matching'), with a
preview of the effect first (principle 9) and Undo for 10 seconds on reversible actions.
Irreversible actions, such as risk acceptance, go through their own flow."

Until now saved views lived in each browser's localStorage, one project's filters at a time
(`web/lib/saved-views.ts`), so a report could not use one (ADR-0055), and bulk triage worked on
the rows ticked on one page of one project.

## Decision

**A saved view is a name for a query.** It stores the query (written back canonically, so panel
and query-bar views look the same), the sort and, optionally, columns. A query that cannot be
parsed is refused with its span, never stored. Sharing copies the dashboards' rules exactly: the
owner edits; a role it is shared with sees it read-only and can copy it; the shared token, being
nobody in particular, sees and edits all; a save names the version it started from and a stale one
is refused. Six views are built in ("Assigned to me", "Past their SLA", ...), read-only and
copyable. `assignee:me` means whoever is looking, so one shared view serves a whole team.

**Browser-saved views are imported once, by the browser.** Only the browser knows the old views
and which project each belonged to, so it turns each into a query (`project:<name>` plus its
filters) and sends them together. The import is all or nothing; a name already taken gets
"(imported)"; a view identical to one the person has is skipped, so importing twice adds nothing.

**Table settings are a small per-person record** (`person_prefs`, keyed by table): which columns,
in what order, and the density. Not audit-logged: it changes only how one person's table looks.

**A report's issues block can show a saved view**, as it is when the report is generated, with
`me` meaning the report's owner. The editor must be able to see the view when they pick it; a block
left as it was is not re-checked, so unsharing a view never locks a report. A deleted view makes
the block say so, as a deleted Issue already does.

**Bulk changes: preview, then apply with the count the person saw.** A selection is a query,
optionally narrowed to Issues picked by id (an id that does not match, or is another
organization's, is simply not selected). The preview counts what would change, what already is as
asked, and what is left alone and why, by project and severity, in one sentence. Applying sends
`expected_count`, the preview's selected count; if the list changed since, nothing is changed and
the new count comes back (409). At most 10,000 Issues a batch.

Reversible actions: assign or unassign, mark not a risk (with a reason each Issue keeps), reopen,
add or remove a tag. One transaction writes every changed Issue, one audit entry per Issue (the
same action names a single change writes, so each Issue's history shows it), one for the batch,
and, for assignment, the same `issue.assigned` events rules listen to. The audit entries are
chained in one commit (`repo.stage_audit_entries`); if another append takes the same sequence
numbers meanwhile, the whole change is rolled back and run again.

**Undo restores only what is still as the batch left it.** The batch keeps each changed Issue's
previous values (`issue_batches`). Undo, by the person who made the change, puts back those Issues
that nobody has changed since and says how many it left alone. The screen offers it for 10 seconds;
the server allows 5 more for a slow network.

**Left alone, with the reason:** Issues under a risk acceptance (that is decided in its own flow),
fixed Issues for assign and not-a-risk, and dependency Issues carrying a VEX justification for
reopen: reopening those withdraws their VEX statement, which Undo could not put back, so they are
reopened one at a time.

**Risk acceptance is never a bulk change.** It needs a second person (principle 10) and is made
per project, so "accept" is preview-only: it groups the selection by project (up to 500 Issues
each, the acceptance limit) and the screen opens each project's request form with them. Applying
it is refused.

## Consequences

- At 100,000 Issues, tagging one business unit's 6,000 open Issues took 122 ms to preview, 708 ms
  to apply and 977 ms to undo, on Postgres under forced RLS
  (`benchmarks/issues/search-and-bulk-100k-2026-10-07b.json`).
- A bulk assignment of thousands raises thousands of `issue.assigned` events, as thousands of
  single assignments would; rules and notifications see each one.
- An Undo that comes too late is refused with what to do instead: another bulk change.
- Saved views and table settings are per organization (forced RLS, migrations 0046 and 0047).
