# Week 29 verification: multi-tenancy via Postgres Row-Level Security (ADR-0013)

Run for real on 2026-09-27 against the same live Postgres, FastAPI and Celery worker used in Weeks
27-28 (rebuilt with this week's code), plus real HTTP requests, real `psql` sessions connected as
each role individually, and a full downgrade/upgrade cycle of the migration itself.

## What shipped

- `Organization` model, `core/tenancy.py` (the org-selection header, the Postgres session-variable
  name, and `scoped_sessions` for the worker).
- `org_id` on `Asset` and `Scan`; `Asset` identity now scoped to `(org_id, source_type, key)`.
- `migrations/versions/0005_tenancy_rls.py`: the `organizations` table, the `org_id` columns and
  backfill, a non-superuser `bulwark_app` Postgres role, and Row-Level Security policies on `assets`,
  `scans`, `tool_runs`, `findings` and `issues`.
- `api/deps.py`: `current_org` reads the (optional) `X-Bulwark-Org` header; `db()` sets
  `app.current_org` on every session before yielding it.
- `api/main.py`: every client-facing scan lookup passes the request's org through `_get_scan`, which
  is now the single place that checks it.
- `core/persistence/repo.py`: `get_or_create_asset`, `create_scan`, `get_scan`, `list_scans` all take
  `org_id`, defaulting to the bootstrap org so every existing caller (and every existing test) is
  unaffected.
- The worker: `AppState.enqueue` now carries `org_id`; `run_scan_task` and `run_scan_job` thread it
  through to `core.tenancy.scoped_sessions`, so the worker's writes carry the right org context too.
- `docker-compose.yml` / `scripts/init-env.sh`: a generated `APP_DB_PASSWORD`; `api` and `worker`
  connect as `bulwark_app`, `migrate` keeps the table-owning role.

## Live proof, not just policy text

**The role separation actually matters — verified directly, not assumed:**

```
as bulwark (superuser), app.current_org unset:  13 scans visible   <- FORCE RLS is a documented no-op
                                                                        against a superuser or BYPASSRLS role
as bulwark_app,          app.current_org unset:   0 scans visible   <- fails CLOSED, not open
as bulwark_app,     app.current_org = <default>: 13 scans visible   <- correct org: everything
as bulwark_app,      app.current_org = <bogus>:   0 scans visible   <- wrong org: nothing, no error
```

This project's Postgres image makes its initial role a superuser; had the API/worker kept using it,
every policy below would have silently protected nothing regardless of how correct the SQL was.

**Full downgrade/upgrade cycle**, not just a forward apply: `alembic downgrade 0004` cleanly dropped
`organizations`, the `org_id` columns, the `bulwark_app` role and every policy (confirmed via `\dt`,
`\d assets`, `\du` showing only `bulwark` again); `alembic upgrade head` reapplied cleanly from there.

**Real cross-tenant HTTP requests**, not synthetic unit assertions: seeded two organizations
directly (there is no org-management API this week, by design — see the ADR), created a real scan
under one via `POST /scans` with `X-Bulwark-Org: org-a`, and let the real worker run it to
completion (`bandit` correctly skipped a Node.js project; status `completed`).

| Request | Result |
|---|---|
| `GET /scans/{id}` as `org-a` | 200, full scan view |
| `GET /scans/{id}` as `org-b` | **404** |
| `GET /scans/{id}/findings` as `org-b` | **404** |
| `GET /scans` as `org-b` | scan absent from the list |
| `GET /scans/{id}` with no `X-Bulwark-Org` header at all (the bootstrap default org) | **404** |
| Ground truth via `psql` as the superuser (bypasses RLS to check) | scan really does belong to `org-a`, has 1 real `tool_runs` row |

Test artifacts (`org-a`, `org-b`, their scan/asset) were deleted afterwards; the 13 real pre-Week-27
scans, their 5 assets and 1,468 backfilled issues from Week 28 are untouched (confirmed by row count
before and after).

## The three bugs this caught, in the order they were found

1. **`sa.func.now()` isn't bindable as a `bulk_insert` parameter value** — the first migration
   attempt failed inserting the bootstrap organization row. Fixed with a Python
   `datetime.now(timezone.utc)` instead. Alembic's DDL transaction rolled back cleanly; confirmed via
   `alembic current` still showing `0004` and no `organizations` table before retrying.
2. **The app role's password never reached the migration process as its own environment variable** —
   only baked into a different variable's connection-string value. `os.environ.get("APP_DB_PASSWORD")`
   read `None` inside the `migrate` container, so `bulwark_app` was created with an empty password,
   and the API's real connection (using the real password) got `password authentication failed`.
   Fixed by adding `APP_DB_PASSWORD` as its own bare container environment variable, and by making the
   migration's role step `ALTER ROLE ... PASSWORD ...` on every run (not just `CREATE` once), so a
   future password rotation actually takes effect on the next `alembic upgrade head` instead of
   silently keeping whatever the role was first created with.
3. **`SET LOCAL`-style scoping (`set_config(..., true)`) doesn't survive a mid-request commit**, and
   `create_scan` — one of the two most basic write paths — commits twice in one session (the asset,
   then the scan). The org context set before the first commit was gone by the second, and RLS reads
   "no context" as "see nothing," producing a `500` on the very first live scan creation attempt.
   Fixed by switching to session-scoped `set_config(..., false)`, safe because every session consumer
   (`api.deps.db`, `core.tenancy.scoped_sessions`) sets it immediately after opening a session, before
   any other statement — a stale value from a previous request on a reused pooled connection is always
   overwritten before anything could read it. This also revealed a deeper gap: the **worker** never
   set org context at all and, connecting as the same non-bypass role, would have had every write to
   a scan's tool runs, findings and issues silently rejected. Fixed by threading `org_id` through
   `AppState.enqueue` -> `run_scan_task` -> `run_scan_job` -> `core.tenancy.scoped_sessions`, learned
   from the API at enqueue time rather than looked up by the worker itself (which has no bypass
   privilege to look it up with in the first place).

## Automated tests

```
pytest -q --cov=core --cov=api   # 778 passed (6 new), 95.28% coverage
ruff check . && black --check .  # clean
mypy                              # clean (core/, api/)
```

New: `tests/unit/test_tenancy.py` (repo-layer org filtering, on SQLite — this is what actually
protects the fast test suite, since SQLite has no RLS equivalent at all) and two additions to
`tests/unit/test_api.py` for the `X-Bulwark-Org` header's application-level behavior. RLS itself has
no SQLite equivalent to unit-test; it is only proven by the live Postgres verification above.

## What's deferred, on purpose

- No org-management API (create/list/join an organization) — matches the plan's own sequencing
  (§19.1/§19.2 are separate, later identity work). Organizations exist today only via direct
  database access.
- No real per-organization authentication. The single shared bearer token from v1.0 still gates API
  access; `X-Bulwark-Org` only selects scope on top of it, so a caller holding the token can claim
  any org id that exists. This is the mechanism real org membership will bind to later, not a
  finished access-control story by itself.
- The web app has no organization switcher and doesn't send the header — it implicitly stays on the
  bootstrap default org, identical to v1.0 behavior.
- `remediation_cache`, `kb_chunks`, `kb_meta` are shared across every organization by design (a cached
  AI remediation for a public CWE, or the RAG knowledge base, isn't tenant-specific data) and carry no
  RLS policy.
