# ADR-0013: Multi-tenancy enforced by Postgres Row-Level Security

Status: Accepted (2026-09-27). Design only — implementation is Week 29.

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

## Consequences

- Every new table added from Week 29 onward needs `org_id` and its own `FORCE ROW LEVEL SECURITY` policy from
  day one; this ADR is the checklist a reviewer should hold new tables to.
- The CLI's local, unauthenticated `scan()` path is unaffected — RLS only applies to the API/worker's database
  access. A self-hosted single-user deployment can run with exactly one organization and never notice the
  isolation exists.
- This does not, by itself, migrate v1.0's single-shared-token auth into real per-organization accounts; that is
  separate identity work (the plan's §19.2, GitHub sign-in / passkeys / TOTP), not part of this ADR.
