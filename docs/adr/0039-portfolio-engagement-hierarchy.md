# ADR-0039: Portfolio and Engagement -- "Test" is a ToolRun, not a new table

Status: Implemented (2026-10-02), Week 53 task 3 (plan §40 change C11, "ADR-016"/"ADR-017" in the
plan's own numbering -- renumbered to this repository's real, sequential ADR series, the same
renumbering ADR-0038 already explains).

## Context

Everything built through v2 is Organization -> Asset -> Scan -> Finding/Issue: flat, one scan at a
time. v3's own stated model (plan §40 change C11) adds structure above and around that: "teams
group projects by business unit" (Portfolio) and "pen tests and audits are time-boxed engagements;
imported reports need a home that isn't a scan" (Engagement). The plan also names "Test" -- one
tool's results within an engagement -- as a concept the rest of v3 (reimport semantics, the import
screen's "new/unchanged/reopened/closed" counts, SLAs, dashboards) is built on top of.

## Decision

Two new tables, `Portfolio` and `Engagement`, scoped by `org_id` directly (same RLS shape as
`Asset`/`Scan`). An Engagement belongs to one Asset and optionally one Portfolio; `engagement_type`
is `ci | pentest | audit | adhoc`.

**"Test" is not a third new table.** `ToolRun` (migrations 0001/0005) already is exactly that: one
row per tool per scan, with its own status, duration, exit code, and error. Adding a `Test` table
with the same shape next to it would mean two places holding what's structurally the same fact,
with no way to guarantee they'd ever agree once either one changed independently -- the exact
"parallel reimplementation instead of one shared mechanism" failure mode this codebase has
consistently avoided elsewhere (the plugin conformance kit, the pre-commit hook's shared scan
logic, `core.netsafety`'s single SSRF primitive). Instead, `ToolRun` gains one new column,
`engagement_id`, and every existing and future ToolRun is "the Test" the plan's later weeks (ingest,
reimport, the import screen) will read and write.

### The migration is data, not just schema

`migrations/0026_portfolio_engagement.py` does what the plan's own wording asks literally: "one CI
engagement per project with one Test per scanner." For every existing Asset, it creates one `"ci"`
Engagement (`"active"` if the asset has ever been scanned, `"completed"` if not) and links every one
of that asset's existing ToolRun rows to it. Verified live against a real, freshly migrated
Postgres: a seeded asset with a real scan and two real ToolRuns got exactly one Engagement, with
both ToolRuns correctly linked; a seeded asset with no scans at all got one `"completed"` Engagement
with nothing linked to it (correctly empty, not an error).

`core.persistence.repo.get_or_create_ci_engagement` keeps this invariant going forward: `add_tool_run`
calls it for every new ToolRun, so an Asset created after this migration gets the exact same
lazily-created, singleton `"ci"` Engagement an Asset that existed before it got eagerly. Verified
live: two scans of the same Asset (by its own computed identity, `core.assets.asset_key`, not a raw
id) share one Engagement, never create a second; `create_engagement` explicitly refuses
`engagement_type="ci"` from anyone else, so a person (or a later v3 import flow) can't accidentally
split a project's standing CI history across two competing "ci" engagements.

## Consequences

- No API surface yet (`GET/POST /portfolios`, `/engagements`, a "Tests" tab on the project screen).
  This week's scope is the data model and the migration it depends on; the v3 UI/API work that reads
  and writes it is later weeks' own tasks, not pulled forward here.
- `ToolRun.engagement_id` is nullable, and stays that way: `tool_runs`' own RLS policy (migration
  0005, an EXISTS join through `scans.org_id`) is unchanged and remains the real tenancy boundary.
  A null `engagement_id` is a historical/edge-case state (a scan with no asset -- `create_scan`
  always resolves one in practice, but the column is nullable), never a leak.
- Growing Engagement types later (e.g. a dedicated "import" type for a report that didn't come from
  a Bulwark scan at all, per the plan's own C13 "manual findings as a first-class source") needs no
  schema change -- `engagement_type` is already a free-text column, not an enum constraint.

## What is NOT done

- Portfolios are created but nothing assigns an Asset's Engagements to one automatically, and
  nothing in the UI surfaces them yet -- purely organizational scaffolding for now.
- SLA tracking, risk acceptance, and the configurable priority engine (plan §40 changes C15-C17)
  are separate, later decisions; nothing here anticipates their schema.
- RLS *on the new tables themselves* (as opposed to the existing, unchanged `tool_runs` policy) and
  the two-tenant leak test covering them is Week 53 task 4, verified separately.
