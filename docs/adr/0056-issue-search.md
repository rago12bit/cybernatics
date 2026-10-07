# ADR-0056: One query language, parsed twice; pages by cursor; counts exact or a true lower bound

Status: Accepted (2026-10-07), Week 73 (plan §56). Builds on [ADR-0054](0054-metrics-layer.md)
(the org's projects as a list, not a join) and [ADR-0013](0013-tenancy-row-level-security.md) (RLS).

## Context

Plan §56: "v3 organizations have tens of thousands of issues. The filter experience decides whether
the product is usable at that size." It asks for a grouped filter panel, chips, filters in the URL,
saved views, and

- a query language for experts, with autocomplete (`priority:P1 sla:breached project:payments-*
  -status:accepted`), where "the panel and the query stay in sync: changing either updates the
  other";
- cursor-based pagination on the server;
- "counts above 10,000 shown as estimates ('about 48,000') instead of slow exact counts".

Until now each project had its own Issues table, paged by offset (`/assets/{id}/issues`), and
nothing listed Issues across projects.

## Decision

**A small, written-down language.** Terms separated by spaces: `key:value[,value...]`, `-key:value`
to exclude, `"quoted values"`, `*` in project, business unit and path, dates as an age (`>30d`) or a
day (`>=2026-01-01`, or a range `a..b`), and free words matched against the title. Fifteen keys, a
few aliases (`sev`, `prio`, `bu`, `owner`, `state`). No OR between keys and no parentheses: the
panel cannot show them, and the panel and the query must say the same thing. Errors carry the span
of text at fault, so the query bar underlines it.

**Parsed twice, on purpose, held together by shared cases.** `core/search/language.py` is the
authority: the API parses `q` and runs it. `web/lib/issue-query.ts` is its twin, so the browser can
keep the panel and the query in step as you type, underline mistakes and know which key autocomplete
is in, without a request per keystroke. The two cannot drift silently: both run every case in
`tests/fixtures/issue_query_cases.json` (31 queries with their filters, canonical text, or error
span), in pytest and in vitest. A query is always written back in one canonical order (the panel's
group order), so "panel to query to panel" is lossless.

**With no status in the query, the list is the active queue** (`status:open`: untouched, or accepted
with the acceptance run out), as the per-project table always was.

**Pages by keyset cursor.** A page ends with an opaque cursor: the sort, the last row's key and its
id. The next page starts strictly after it. Ties break on the id in the same direction as the key,
so one index on (key, id) serves an order both ways. Migration 0045 adds those indexes (priority as
`coalesce(priority_score, -1)`, first seen, last seen). A cursor from another order, or one that
does not decode, is a 422 that says to start again.

**Counts: exact while quick, else "more than 10,000".** This is where the build departs from the
plan's letter. Postgres's row estimate (EXPLAIN) was tried first, and on these filters it was off
by 2 to 7 times: "about 24,000" for 100,000 Issues, "about 30,000" for 60,000. An estimate that far
off misleads more than no number. Exact counts, on the other hand, took 65-225 ms even at 500,000
Issues. So: exact up to 10,000 (a capped count); past that, the full count runs inside a savepoint
with a 200 ms `statement_timeout`. Done in time, it is exact; not, the response says
`{"value": 10000, "exact": false, "at_least": true}` and the list says "more than 10,000", which is
always true. The time limit is set and restored inside the savepoint, so nothing else in the
request is cut short.

**The org's projects as a list.** Project and business-unit filters are resolved to project ids in
Python (globs match a label or its last part, so `payments-*` matches `acme/payments-api`), and the
query filters `issues.asset_id IN (...)`, as the metrics layer does: a join on `assets` under RLS
cannot be estimated and walks every Issue.

**SLA state across projects.** Each project has its own policy. Projects that share a policy are
grouped and get one SLA clause per group, so a hundred projects on the starter policy cost one
clause, not a hundred.

## Consequences

- At 100,000 Issues (twice the plan's 50,000), every page with its count is under 115 ms and every
  count is exact (`benchmarks/issues/search-100k.json`). Page 25 costs what page 1 does.
- At 500,000 Issues a page alone is 6-64 ms, but **free text is slow (0.24 s a page, 0.52 s with
  the count)**. Under row-level security Postgres applies a non-leakproof predicate such as `LIKE`
  only after the policy, so no index can serve "the title contains": a trigram index was built and
  measured, and the planner did not use it. Free text therefore scans the organization's matching
  Issues. A search index outside the RLS boundary would fix it; not needed at the plan's scale.
- Spans count code points in Python and UTF-16 code units in the browser. They differ only for
  characters outside the Basic Multilingual Plane (emoji), and only the browser underlines.
- `assignee:` takes a person's handle or name, `me` (a personal token only: the shared token is
  nobody) or `none`. A name nobody has matches nothing rather than failing, so a saved view keeps
  working after someone leaves.
