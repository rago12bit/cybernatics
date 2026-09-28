# Week 29/30 backfill verification: scoped tokens, audit log, automated tenant-leak test

Run for real on 2026-09-28, against the same live Postgres, FastAPI and Celery worker used
throughout this project, after reading the plan's actual §19.1–§19.3 text fresh (not the earlier
session-summary paraphrase, which had drifted from what the plan actually specifies for Weeks
29–30 — see the conversation for the discrepancy this surfaced before this backfill started).

## What this backfill covers, and what it deliberately doesn't

This closes: scoped/hashed/prefixed API tokens (ADR-0018), the tamper-evident audit log
(ADR-0019), and the automated cross-tenant leak test against real Postgres RLS that ADR-0013
committed to but never wired into CI.

This does **not** attempt: the full Organization/project/membership/role permission matrix
(Owner/Admin/Member/Viewer, plan §19.1's table), or GitHub OAuth sign-in + passkeys + TOTP + session
cookies + CSRF (plan §19.2). Both need a real human-identity foundation this project doesn't have
yet, and both are security-sensitive enough to deserve their own careful, unhurried pass rather
than being squeezed into an already-large backfill. Flagged explicitly, not silently dropped.

## Live proof, not just code review

**Scoped tokens, against real Postgres, connected as the real non-superuser `bulwark_app` role:**

```
$ docker compose exec api bulwark token create --org-id verify-org-30 --name live-verify \
    --scope scans:read --scope scans:write
token: bulwark_5c83e833d70a52ffa6b389d3d39d0c500c330056_34DXSx
```

| Request | Result |
|---|---|
| Create a scan with the scoped token, no `X-Bulwark-Org` header | 202, scan lands in `verify-org-30` |
| Same token, `X-Bulwark-Org: some-other-org` header also sent | Still lands in `verify-org-30` — header ignored |
| List scans with the same token | The scan is present |
| A read-only-scoped token tries `POST /scans` | **403** |
| The same read-only token does `GET /scans` | 200 |
| The legacy shared `BULWARK_API_TOKEN` | Unaffected — still full access, header-selected org |

All confirmed against Postgres directly (`SELECT org_id FROM scans WHERE id = ...`), not just the
API's word for it.

**The audit chain, against real Postgres — including a real tampering test:**

```
$ docker compose exec api bulwark audit verify
{"entries_checked": 2, "chain_ok": true, "checkpoints": 0}

$ docker compose exec postgres psql -U bulwark -d bulwark -c \
    "UPDATE audit_entries SET target = 'some-other-token-id' WHERE seq = 1;"
UPDATE 1

$ docker compose exec api bulwark audit verify
{"entries_checked": 0, "chain_ok": false, "broken_at_seq": 1,
 "reason": "entry_hash mismatch at seq 1"}
```

The tampered row was restored and `audit verify` confirmed clean again immediately after — this
was a deliberate, reversible test against real data, not a permanent change.

**The automated cross-tenant leak test, against real Postgres RLS** (not the SQLite
application-level test in `tests/unit/test_tenancy.py`, which is what protects the fast suite but
proves nothing about RLS itself):

```
tests/integration/test_tenancy_rls_docker.py::test_a_scan_created_in_one_org_returns_404_for_every_endpoint_under_another_org PASSED
tests/integration/test_tenancy_rls_docker.py::test_two_orgs_scanning_the_same_public_repo_get_separate_assets_and_issue_history PASSED
```

Run twice: once against a temporarily, locally-published Postgres port (reverted immediately after
— `docker-compose.yml`'s Postgres service is not published to the host in the committed config),
and confirmed to self-skip cleanly with no env var set (the normal state for every other
contributor's machine). Wired into `.github/workflows/ci.yml` as a new `tenancy-rls` job with its
own ephemeral Postgres service, so it now runs on every pull request as ADR-0013 originally
committed to.

Test artifacts (the `verify-org-30` organization, its tokens, scans, and assets) were deleted
afterward; the 13 real pre-existing scans and their 5 assets are untouched (confirmed by row count
before and after, as in every previous week's verification).

## Two real bugs found and fixed

1. **`row.expires_at <= datetime.now(timezone.utc)` crashed with `TypeError: can't compare
   offset-naive and offset-aware datetimes`.** SQLite hands back a naive `datetime` even for a
   `DateTime(timezone=True)` column. Fixed by treating a naive value as already UTC before
   comparing (every timestamp this codebase writes is UTC).
2. **The same root cause, more seriously, inside the hash chain itself**: `compute_hash`'s
   `timestamp.astimezone(timezone.utc)` on a naive value assumes the *local* timezone and silently
   shifts it, so `verify_chain` recomputed a different hash than the one written and would have
   reported an untampered chain as broken on any host not itself in UTC. Fixed the same way, and
   confirmed against both SQLite (unit tests) and real Postgres (the live tampering test above)
   afterward.

A third issue, structural rather than a bug: a CLI command that accessed an ORM attribute *after*
its `with get_session_factory()() as s:` block had closed raised `DetachedInstanceError` the moment
a prior `s.commit()` inside that block had expired the object. Fixed in `token create` and `audit
checkpoint` by reading the needed values into plain variables before the session closes.

## Automated tests

```
pytest -q --cov=core --cov=api   # 841 passed (30 new), 93.87% coverage
ruff check . && black --check .  # clean
mypy                              # clean (core/, api/; cli/ is not in this project's mypy scope,
                                  #  a pre-existing pyproject.toml decision, not new this week)
```

New: `tests/unit/test_tokens.py`, `tests/unit/test_audit.py` (pure logic), `tests/unit/
test_tokens_repo.py` (SQLite persistence), `tests/unit/test_scoped_tokens_api.py` (the real API
auth flow, including the org-header-override attempt), `tests/unit/test_token_audit_cli.py` (the
CLI commands, including the tampering-detection and detached-instance regressions above), `tests/
unit/test_audit_rekor.py` (Sigstore bundle parsing), and `tests/integration/
test_tenancy_rls_docker.py` (the new CI-run, real-Postgres leak test).

## What's explicitly not verified live

- **A real Rekor checkpoint publish.** `bulwark audit checkpoint` is real, working code
  (`core/audit_rekor.py`), tested with a mocked cosign invocation. Actually running it publishes a
  permanent, public entry to Sigstore's Rekor transparency log — an irreversible, outward-facing
  action to a third-party service, done only with explicit confirmation, not as a default part of
  this verification pass.
- The full Organization/project/role permission matrix and GitHub OAuth/passkey/TOTP sign-in
  (plan §19.1's table, §19.2) — explicitly deferred, see above.
- The custom Gitleaks rule for Bulwark's own token format (plan §19.2's last bullet) — deferred;
  see ADR-0018's "what was actually built" section for the specific sandboxing constraint that
  makes it non-trivial (Docker-outside-of-Docker mount paths).
