# Finding Issues

Every Issue in your organization, across projects, can be filtered with the panel or with a query.
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

## API

```text
GET /v2/issues?q=<query>&sort=priority|severity|newest|oldest|last_seen&limit=50&after=<cursor>
GET /v2/issues/parse?q=<query>          the query as filters, and written back
GET /v2/issues/suggest?key=project&prefix=pay
```

A query that cannot be read is a 422 with `{"message", "start", "end"}`. Each page carries `next`,
the cursor for the page after it (`null` on the last page), and `count`:
`{"value": 1204, "exact": true}`, or `{"value": 10000, "exact": false, "at_least": true}`.
