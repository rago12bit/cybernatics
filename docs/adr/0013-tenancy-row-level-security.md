# ADR-0013: Multi-tenancy enforced by Postgres Row-Level Security

Status: Implemented (2026-09-27, Week 29). Verified live end to end; see
docs/v2-week29-verification.md.

## Context

Every table in `core/persistence/models.py` (`Scan`, `ToolRun`, `FindingRow`) is global: there is one shared
bearer token (`SECURITY.md`, "known limits") and no concept of who a scan belongs to. That is fine for a
single-user, self-hosted tool, which is what v1.0 is and remains (the self-host page is explicit: one token,
one machine, not for untrusted multi-user hosting).

v2's collaboration features (§19.1: organizations, projects, roles) need real isolation between tenants sharing
one deployment. The risk if that isolation lives only in application code — a query handler that forgets a
`WHERE org_id = ...` clause — is a cross-tenant data leak, which for a security-findings product is about as
bad a bug class as exists.

## Decision

Enforce tenancy at the database layer with Postgres Row-Level Security, not only in the application:

```sql
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;  -- FORCE: applies even to the table owner

CREATE POLICY tenant_isolation ON scans
  USING (org_id = current_setting('app.current_org')::uuid);

-- per request, inside the transaction, before any query:
SET LOCAL app.current_org = '<the authenticated org id>';
```

- `org_id` is added to `Scan` (and cascades to `ToolRun`/`FindingRow`/`Occurrence` through the foreign key, so a
  join can never cross tenants even if a query forgets to filter).
- The API's database role has **no** `BYPASSRLS`. Only a separate, narrowly-scoped migration role does.
- `SET LOCAL app.current_org` is set once per request from the authenticated identity, inside the same
  transaction as every query that request makes, so there is no window where the session has no tenant context.

### The test that proves it, not just documents it

An automated test creates two organizations, authenticates as the first, and requests every resource ID
belonging to the second across every endpoint. Every request must return 404 (never 403 — a 403 confirms the
resource exists, which is itself a leak of information about another tenant). This runs on every pull request,
not just once at ship time, because RLS policies are exactly the kind of thing a later migration can silently
weaken.

## Alternatives considered

- **Application-level filtering only** (every query handler adds `.filter(org_id == current_org)`). Rejected:
  one omitted filter in one endpoint, ever, is a full cross-tenant leak, and there is no structural way to catch
  a missing filter except by testing every endpoint — which is exactly what RLS makes unnecessary for the
  common case (the two-tenant test in the previous section is then a belt-and-suspenders check, not the only
  line of defense).
- **Separate database per tenant.** Rejected for v2: correct isolation, but no shared connection pool, migrations
  fan out per tenant, and it's a much bigger operational jump than a single self-hosted or small-multi-tenant
  deployment needs. Revisit if/when the project ever needs to scale past what one Postgres instance with RLS
  comfortably serves.

## What was actually built, and where it differs from the design above

- **`org_id` lives on `assets` and `scans` only, not on `tool_runs`/`findings`/`issues`.** Those
  three get a Row-Level Security policy that joins back to the table that does carry it (`EXISTS
  (SELECT 1 FROM scans WHERE scans.id = findings.scan_id AND scans.org_id = ...)`), which is what
  "cascades through the foreign key" in the original design actually means in a working policy, not
  a literal duplicated column. Application-level code enforces the same shape: every client-facing
  lookup resolves and org-checks the `Scan` first (`api/main.py`'s `_get_scan`), and everything else
  scoped by that `scan_id` is safe without its own check.
- **`assets` needed `org_id` too, which the original design didn't mention.** Two organizations
  scanning the same public repository would otherwise share one `Asset` row (identity is keyed on
  `(source_type, key)` alone, ADR-0012) — meaning one org's Issue lifecycle history and counts would
  leak into the other's. Caught by working through the design before writing code, not by a test
  failure. Fixed by scoping `Asset` identity to `(org_id, source_type, key)`.
- **The non-superuser API/worker role is real, not a stated intention.** `bulwark_app` (`NOSUPERUSER
  NOBYPASSRLS`) is created by the migration itself and is what `docker-compose.yml` now points the
  `api` and `worker` services at; `migrate` keeps connecting as the table-owning role so it can alter
  schema and manage that role. This is load-bearing, not cosmetic: this project's Postgres image
  makes its initial role a superuser, and `FORCE ROW LEVEL SECURITY` is a documented no-op against a
  superuser or any `BYPASSRLS` role regardless of policies — every policy below would have silently
  protected nothing if the app kept using the original role. Verified directly (see the verification
  doc): the superuser sees all rows regardless of `app.current_org`; `bulwark_app` with no org set
  sees zero rows (fails closed, not open); `bulwark_app` with the right org set sees exactly that
  org's rows.
- **No org-management API.** There is no endpoint to create an organization, list them, or assign a
  caller to one — matching the plan's own sequencing (real identity is §19.2). `organizations` rows
  exist only as the migration's bootstrap default plus whatever is inserted directly for now. A
  caller selects scope with an `X-Bulwark-Org` header (`core/tenancy.py`); the single shared bearer
  token still authenticates that a caller may use the API at all, so a caller that knows the token
  can claim any org id that exists. This is a known, explicit limitation, not an oversight — it
  proves the isolation mechanism is correct, and real org membership binds to it later without
  changing RLS or the application-level filtering at all. The header is also not part of the OpenAPI
  schema (it's read directly from `Request.headers`, not declared as a FastAPI `Header()` parameter),
  since it isn't a stable public interface yet.
- **Two real bugs found live, beyond the design itself:**
  1. `set_config(..., true)` (transaction-local) was the first implementation, matching the ADR's own
     `SET LOCAL` framing — and it broke the very first real request. Several `repo.py` functions
     commit internally more than once within one request/session (`create_scan` commits the asset,
     then commits the scan; the worker's completed-scan path commits issues via
     `sync_issues_for_scan`, then commits findings via `add_findings` in the same session). A
     transaction-local setting resets at the *first* of those commits, leaving the rest of the same
     request running with no org context — which RLS then reads as "see nothing," not "see
     everything." Fixed by switching to `set_config(..., false)` (session-scoped): safe because
     every consumer of a session sets it immediately after opening, before any other statement, so a
     stale value from a previous occupant of a pooled connection can never actually be read.
  2. The worker was still fully broken after that fix, for a different reason: nothing had ever
     told it which org a scan belonged to. It connects as the same non-bypass `bulwark_app` role as
     the API, so every write it made (`mark_running`, `add_tool_run`, `add_findings`, `finish_scan`)
     would be silently rejected or simply match zero rows under RLS. Reading the scan's own `org_id`
     first doesn't work either — the worker has no bypass privilege, so it can't `SELECT` a row it
     hasn't already identified the org for. Fixed by threading `org_id` through the dispatch path
     the API already has it on: `AppState.enqueue` gained a second argument, `run_scan_task` and
     `run_scan_job` both gained `org_id`, and `core.tenancy.scoped_sessions` wraps the worker's
     session factory to set `app.current_org` on every session it opens, the same job `api.deps.db`
     does for the API.

## Consequences

- Every new table added from Week 29 onward needs `org_id` and its own `FORCE ROW LEVEL SECURITY` policy from
  day one; this ADR is the checklist a reviewer should hold new tables to.
- The CLI's local, unauthenticated `scan()` path is unaffected — RLS only applies to the API/worker's database
  access. A self-hosted single-user deployment can run with exactly one organization and never notice the
  isolation exists.
- This does not, by itself, migrate v1.0's single-shared-token auth into real per-organization accounts; that is
  separate identity work (the plan's §19.2, GitHub sign-in / passkeys / TOTP), not part of this ADR.
