# Week 73 verification: filters at scale (plan §56)

Design: [ADR-0056](adr/0056-issue-search.md) (the query language, cursor pages, counts) and
[ADR-0057](adr/0057-saved-views-and-bulk-changes.md) (saved views, bulk changes). How to use it:
[Finding Issues](issue-search.md).

## What was built

- **One list of every Issue in the organization** (`/app/issues`, "Issues" in the header).
  - A grouped, collapsible filter panel: Status; Severity and priority; Location; Source;
    Ownership and SLA; Dates. Folded, each group says how many of its filters are on.
  - Removable chips for every active filter, and Clear all.
  - A query bar for experts, with suggestions as you type: keys, then values (the fixed values,
    and projects, business units, people, tags and sources from the server). A mistake is
    underlined where it is, with what was expected, and the list is not run.
  - The panel and the query say the same thing: ticking a box rewrites the query, and typing fills
    the panel as soon as the query reads. The address carries it (`?q=&sort=&view=`).
  - Pages by cursor ("Show 50 more"); the count is exact, or "more than 10,000".
  - A column chooser (which columns, in what order) and a density toggle, remembered per person.
- **The query language and the search API** (`/v2/issues`, task 1): fifteen filters, exclusion,
  `*`, dates, free text; parsed in Python and in the browser, both held to 31 shared cases.
  Migration 0045 adds the ordered indexes.
- **Saved views** (task 2): a name for a query, sort and columns; personal or shared with a role,
  like dashboards; six built in; views saved in the browser before are imported once. A report's
  Issues block can show a saved view. Migration 0046.
- **Bulk changes across pages** (task 3): assign or unassign, mark not a risk, reopen, add or
  remove a tag, for the Issues picked or "Select all N matching" (up to 10,000). A preview first,
  as counts; applied only with the count the preview showed; Undo for 10 seconds. Risk acceptance
  is never a bulk change: its preview groups the selection by project and opens each project's
  request. Migration 0047.
- The per-project Issues table now saves views to the server too, and links to the same project
  on the new list.

## Checked against real systems

- **Postgres 16 under forced row-level security** (a throwaway container):
  - Migrations 0046 and 0047 go down to 0045 and back up; `saved_views`, `person_prefs` and
    `issue_batches` come back with RLS enabled and forced.
  - The new isolation test (another organization's views, settings and batches are invisible even
    by id; a bulk change picked by id cannot reach another organization's Issues; the audit chain
    verifies after a batch and its undo) passes, and fails when the policy on `saved_views` or on
    `issue_batches` is dropped. All 66 RLS tests pass.
- **At 100,000 Issues** (`scripts/bench-issue-search.py`): tagging one business unit's 6,000 open
  Issues took 122 ms to preview, 708 ms to apply (one audit entry per Issue, one commit) and 977 ms
  to undo. Undo first took 6.3 s: it removed tags one statement per Issue; now a thousand at a
  time. That afternoon every search query ran 2-3 times slower than in task 1's run. Task 1's own
  code, run straight after against the same database, was just as slow, so this was the machine,
  not the change. Both runs are kept as measured (`benchmarks/README.md`).
- **In the browser**, against the real API seeded with six projects in two business units and
  about 240 Issues:
  - the address's query filled the panel, the chips and the count (66 Issues);
  - "Select all 66 matching", Assign to @samk: the preview said 55 would change and 11 already
    were, by project; applied, the rows showed Sam K.; Undo put all 55 back;
  - axe found nothing on the list (with a query, with a broken query), the per-project table and
    the reports list, at 1,440 and 375 px; at 375 px nothing scrolls sideways and the filters fold
    behind one button. An h3 straight after the page's h1 was found this way and fixed.

## Tests

- **Backend:** 42 search tests (task 1); 8 saved-view tests (sharing and copying, checked queries
  with the span at fault, stale saves, limits, other organizations, imports all or nothing, table
  settings, a report showing a view as its owner sees it and saying so once it is deleted); 7 bulk
  tests (preview counts, the count check, per-Issue and batch audit entries with the chain
  verified, Undo keeping later changes, the window, picked ids only, risk acceptance refused, input
  checks, the read-only scope). 2,750 pass in all, at 91.7% coverage.
- **Web:** 12 tests of the Issues list (both-way sync, the address, the underlined mistake,
  suggestions by keyboard, select all matching through preview, apply and undo, picked ids only,
  risk acceptance per project, show more, columns and density saved, views opened and saved,
  browser views imported), each with axe where it renders; one report-builder test for the view
  picker. 412 pass in all.
- **Visual baselines** for the three existing screens were regenerated, because the header gained
  "Issues"; see below.

## Not done, or not proven

- **"About 48,000" is not shown.** Postgres's estimate was 2 to 7 times off, so a count past
  10,000 is exact when it can be counted in 200 ms, else "more than 10,000" (ADR-0056).
- **Free text is slow at five times the plan's scale** (0.5 s with its count at 500,000 Issues):
  under row-level security no index can serve "the title contains".
- **No visual baseline for the new screen yet.** Week 74 adds visual regression for every new
  screen, with the study's fixes.
- **Bulk changes of thousands raise thousands of events** (`issue.assigned`), as single changes
  would. Rules and notifications see each one; nothing batches them yet.
- **The shared token has one set of table settings**, shared by everyone using it: it is nobody
  in particular.
