# Finding Issues

Every Issue in your organization, across projects, is on one list: **Issues** in the header. Filter
it with the panel or with a query.
The two always say the same thing: change one and the other follows. The query is in the page's
address, so any list can be bookmarked or shared.

## The query language

Write filters as `key:value`, separated by spaces. Every filter must match.

```text
priority:P1 sla:breached project:payments-* -status:accepted
```

| You write | It means |
|---|---|
| `severity:critical,high` | critical **or** high (a comma is "any of these") |
| `-status:accepted` | leave out accepted Issues (`-` excludes) |
| `project:payments-*` | `*` matches anything; a pattern without `/` also matches the last part of a project's name, so this matches `acme/payments-api` |
| `project:"acme/payments api"` | quotes keep spaces in a value |
| `first_seen:>30d` | first seen more than 30 days ago |
| `last_seen:<7d` | seen within the last 7 days |
| `fixed:>=2026-01-01` | fixed on or after 1 January 2026 |
| `first_seen:2026-01-01..2026-01-31` | first seen in January 2026 (both days included) |
| `sql injection` | the title contains "sql" and "injection" |
| `"open redirect"` | the title contains the phrase |

With no `status`, the list is the **active queue**: Issues still to deal with, including accepted
ones whose acceptance has run out.

### Filters

| Key | Values |
|---|---|
| `status` (`state`) | `open`, `accepted`, `not_a_risk`, `fixed` |
| `severity` (`sev`) | `critical`, `high`, `medium`, `low`, `info` |
| `priority` (`prio`) | `P1`, `P2`, `P3`, `P4`, `none` |
| `sla` | `breached`, `due_soon`, `on_track` (each project's own SLA policy) |
| `project` | a project's name; `*` allowed |
| `portfolio` (`unit`, `bu`) | a business unit's name; `*` allowed; `none` for projects in no unit |
| `path` | a file path; `*` allowed (`path:src/*.py`) |
| `category` | `sast`, `sca`, `secrets`, `iac`, `container`, `dast` |
| `source` | where the Issue came from: `scanner`, `manual`, `llm-confirmed`, ... |
| `assignee` (`owner`) | a person's handle or name, `me`, or `none` |
| `tag` | a tag on the Issue, its project or its business unit |
| `retest` | `requested`, `passed`, `failed` |
| `first_seen`, `last_seen`, `fixed` | a date or an age, as above |

Keys and listed values are not case-sensitive. A mistake is underlined where it is, with what was
expected ("“huge” is not a severity. Choose from: critical, high, medium, low, info.").

## Counts and pages

The list shows how many Issues match. Up to 10,000 the number is exact, and past that it is still
exact when it can be counted quickly. When it cannot, the list says "more than 10,000" rather than
guess. Pages follow each other by position in the list, not by page number, so moving deep into a
long list is as fast as the first page, and an Issue that changes while you page cannot make another
appear twice. See [ADR-0056](adr/0056-issue-search.md) for why.

## Saved views

Save the list as it is (its filters, sort and columns) under a name. A view is yours; share it with
a role (lead, engineer, tester) and everyone who picked that role sees it, read-only, and can copy
it. A few views are built in, such as "Assigned to me" and "Past their SLA". A view stores the
query, so `assignee:me` means whoever opens it.

Views saved in your browser before Week 73 are offered for import the first time you open Issues:
each becomes a query for its project. Importing twice adds nothing.

A report's Issues block can show a saved view (choose "A saved view of the Issues list"): the PDF
lists what the view shows when the report is generated, and `me` is the report's owner.

## Columns and density

Choose the columns and their order, and comfortable or compact rows. Bulwark remembers your choice
for you, on any device.

## Changing many Issues at once

Tick Issues on the page, or "Select all N matching" for every page. Choose what to do: assign or
unassign, mark not a risk (with a reason), reopen, add or remove a tag. Before anything changes you
see what will happen, as counts: how many change, how many already are as asked, and how many are
left alone and why. If the list changes before you confirm, nothing is changed and you see the new
count. Up to 10,000 Issues at a time.

For 10 seconds afterwards you can undo it. Undo puts back every Issue nobody has changed since, and
tells you about any it left alone.

Some Issues are left alone on purpose:

- Issues under a risk acceptance: change them through that acceptance.
- Fixed Issues, for assign and not a risk.
- Dependency Issues with a VEX justification, for reopen: reopening one withdraws its VEX
  statement, so do it on the Issue's own page.

**Risk acceptance** is not a bulk change: it needs a second person to approve and is requested per
project. "Request risk acceptance" shows the selection by project and opens each project's request
with those Issues. See [ADR-0057](adr/0057-saved-views-and-bulk-changes.md).

## API

```text
GET /v2/issues?q=<query>&sort=priority|severity|newest|oldest|last_seen&limit=50&after=<cursor>
GET /v2/issues/parse?q=<query>          the query as filters, and written back
GET /v2/issues/suggest?key=project&prefix=pay
```

```text
GET    /v2/issue-views                      yours, those shared with your role, the built-in ones
POST   /v2/issue-views                      {name, query, sort?, columns?, shared_with?}
PUT    /v2/issue-views/{id}                 {version, ...}; 409 if someone saved it since
DELETE /v2/issue-views/{id}
POST   /v2/issue-views/{id}/copy
POST   /v2/issue-views/import               {views: [{name, query, sort?}]}
GET    /v2/me/tables/issues                 your columns and density
PUT    /v2/me/tables/issues                 {columns?, density?}
POST   /v2/issues/bulk/preview              {q, ids?, action, params}
POST   /v2/issues/bulk                      {q, ids?, action, params, expected_count}
POST   /v2/issue-batches/{id}/undo
```

A query that cannot be read is a 422 with `{"message", "start", "end"}`. Each page carries `next`,
the cursor for the page after it (`null` on the last page), and `count`:
`{"value": 1204, "exact": true}`, or `{"value": 10000, "exact": false, "at_least": true}`.
