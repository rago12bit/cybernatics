# Week 47 verification -- envelope encryption, crypto-shredding, mTLS, secrets (plan §22.2)

Honest record of what was built, run, and measured. See [ADR-0032](adr/0032-envelope-encryption-and-crypto-shredding.md)
(tasks 1-2) and [ADR-0033](adr/0033-mtls-and-secrets-management.md) (tasks 3-4) for the design
decisions, including several real bugs found and fixed by live testing rather than caught later.

## What was built

- `core/secrets/openbao.py`, `core/secrets/envelope.py` (task 1): a Transit client minting/unwrapping
  per-org data keys, and AES-256-GCM encryption bound to each object's own storage key as AEAD
  associated data. New `scan_data_keys` table (migration 0018). `core.persistence.storage.
  EncryptingObjectStore`/`build_object_store` wire this into the real production path
  (`core.tasks.run_scan_task`), off by default.
- `core/retention.py` (task 2): an hourly Celery-beat sweep destroying a scan's data key once its
  org's retention window passes (default 7 days). New `data_retention_policies` table (migration
  0019), a `GET`/`PUT /settings/retention` API, and a settings screen at `/app/settings`.
- `docker/postgres/pg_hba.conf`, `docker-entrypoint-wrapper.sh`, `init-temporal-role.sh` (task 3): a
  rebuilt Postgres image requiring a client certificate matching the connecting role for every
  network connection. New `bulwark_api`/`bulwark_worker`/`bulwark_fixagent` roles (migration 0020),
  each inheriting `bulwark_app`'s grants via role membership; `bulwark_app` itself set `NOLOGIN`.
  `scripts/gen-mtls-certs.sh` generates the dev CA and per-service certificates.
- `core/secrets/resolve.py`, `bulwark secrets migrate-env` (task 4): four plaintext secrets (GitHub
  App private key, its webhook secret, the API token, the LLM API key) now prefer a value from
  OpenBao's KV store, falling back to their environment variable unconditionally when OpenBao isn't
  configured or doesn't have them yet.
- `docs/adr/0032-*.md`, `docs/adr/0033-*.md`, `docs/data-protection.md`.

## Validated against real, live things -- not mocks

- **The full OpenBao Transit round-trip, against a real `openbao/openbao:2.1` container**: mount the
  engine, create an org key (confirmed idempotent), mint a data key, unwrap it back to the identical
  plaintext, and two rejections confirmed live rather than assumed -- an undecodable ciphertext
  (HTTP 400) and unwrapping under the wrong org's key (HTTP 400, "encryption key not found").
- **`EncryptingObjectStore`'s AEAD binding, with a real key-swap attack attempted and blocked.** A
  ciphertext written under one storage key, then read back under a different key string, fails
  closed (`DecryptionError`) rather than silently decrypting into the wrong scan's data.
- **`scan_data_keys`' and `data_retention_policies`' RLS, and their `ON DELETE`/cascade behavior,
  against real Postgres as the actual `bulwark_worker` role** (not a superuser): one organization's
  data key and retention setting are both invisible to another organization, even when a call
  explicitly passes the other organization's id as an argument -- RLS is what actually enforces it,
  not application-level filtering alone. `ON DELETE CASCADE` from `scans` to `scan_data_keys` was
  confirmed only on real Postgres: SQLite (every unit test) does not enforce foreign keys by default,
  so this specific guarantee has no SQLite-backed test at all, by necessity.
- **`shred_expired_scans`, twice caught doing the wrong thing before it shipped.** First, comparing a
  SQLite-stored naive timestamp against a timezone-aware cutoff inside the SQL `WHERE` clause itself
  silently matched nothing; fixed by moving the comparison into Python against `_aware()`-normalized
  values, mirroring a fix `core.maintenance.reap_stale_scans` already needed. Second, discovering a
  cross-organization query run through the RLS-enforced `bulwark_app`-family connection would see
  *zero* rows for every organization, not every organization's own rows -- fixed by iterating
  organizations one at a time with `set_session_org` explicitly set for each.
- **The entire mTLS mechanism, against a real image built from `docker/postgres`, not designed from
  documentation alone.** In order: the exact ownership/permission Postgres requires for a
  bind-mounted private key (a plain bind mount is owned by the host user, which Postgres refuses
  outright as "group or world access"); `verify-full`'s server-hostname check, confirmed to reject a
  mismatched hostname and accept a matching one; a certificate's CN correctly authenticating as its
  matching role and being rejected for any other role, including a validly CA-signed certificate for
  an unrelated identity; a connection with no certificate at all rejected with a distinct, clear
  error. `tests/integration/test_postgres_mtls_docker.py` builds the real image and runs all of this
  automatically now, not just once by hand.
- **The full migration 0020 up/down/up cycle, against real Postgres**, confirming `bulwark_app`
  regains `LOGIN` on downgrade and the three service roles are recreated cleanly on re-upgrade.
- **Role-membership inheritance, proven functionally, not just by reading the grant.** A freshly
  created role made a member of another via `GRANT ... TO ...`, with no direct table grants of its
  own, successfully inserted into and read from a real application table (`organizations`) through
  its inherited privileges alone.
- **The real `docker-compose.yml`, not a hand-reconstructed equivalent.** The actual `migrate`
  service, using its actual environment-variable-interpolated `BULWARK_DATABASE_URL` (with the mTLS
  query parameters) and its actual certificate volume mount, ran the full migration chain --
  including migration 0020 -- to completion with no modifications to the compose file for the test.
  Also confirmed, incidentally: the new mTLS-enabled image starts correctly against an
  **already-initialized** data directory from before this week's changes, not only a fresh one.
- **Temporal's `temporal_svc` carve-out, against the same real image.** Password authentication with
  no client certificate succeeds for `temporal_svc` specifically; a wrong password is rejected; and
  `bulwark` (Bulwark's own owner role) is confirmed to still require a certificate even when given
  its correct password, proving the carve-out is scoped to exactly one role, not a general weakening.
- **CI's `tenancy-rls` job, re-verified end to end against the exact scenario it will actually run**:
  a plain `pgvector/pgvector:pg16` image with no custom mTLS configuration, migrated as the owner
  role, then the RLS test suite run connected as `bulwark_worker` over a plain password -- confirmed
  necessary and sufficient after discovering `bulwark_app`'s new `NOLOGIN` state would otherwise have
  broken this job outright.
- **The full OpenBao KV v2 path, against a real container**: enabling the engine (confirmed
  already-mounted in dev mode, and idempotent to call again), writing a secret, reading it back,
  rotating it, and confirming both a missing path and a missing field within an existing path return
  `None` rather than raising.
- **`Settings`/`LLMConfig` actually preferring OpenBao's value over a stale environment variable**,
  live: a secret written to OpenBao is what `Settings.from_env()`/`LLMConfig.from_env()` return, with
  a deliberately different, stale value left in the environment variable to prove which source won;
  removing `BULWARK_OPENBAO_ADDR` afterward confirmed the fallback to the environment variable still
  works.
- **`bulwark secrets migrate-env`, run against a real OpenBao container via the actual installed CLI
  entry point** (not `python -m cli.main`, which -- a pre-existing quirk of this file's structure,
  not something this week introduced -- only sees commands defined before its mid-file `if __name__
  == "__main__"` guard): migrated secrets confirmed present in OpenBao afterward by reading them
  back independently, and the missing-configuration guard confirmed to error cleanly.

## Verified

- `test_secrets_envelope.py` (8 tests), `test_secrets_openbao.py` (10), `test_persistence_storage.py`
  (9), `test_persistence_scan_data_keys.py` (5), `test_retention.py` (7), `test_persistence_retention_settings.py`
  (4), `test_retention_settings_api.py` (6), `test_secrets_resolve.py` (5), `test_secrets_cli.py` (3).
  `tests/integration/test_secrets_openbao_docker.py` (4), `test_postgres_mtls_docker.py` (5),
  `test_data_protection_rls_docker.py` (5, extended from task 1's 3). Full suite re-run clean after
  every task: 1475 unit tests passed. `black --check .`, `ruff check .`, `mypy` (project scope --
  `cli/` is outside `pyproject.toml`'s configured mypy `files`, unchanged by this week) all clean.
- Frontend: `retention-settings.test.tsx` (4 tests), full existing suite (191 tests) re-run clean,
  `tsc --noEmit` clean, the new `/app/settings` route confirmed to compile and render correctly in a
  real browser preview (falling through to the same sign-in gate every other page uses, with no
  server errors).
- Live Docker/Postgres/OpenBao runs, above -- covering every mechanism this week added, not just the
  application-level logic around them.

## What this does NOT prove (read before relying on it)

- **Database grants are not actually least-privilege per service.** `bulwark_api`/`bulwark_worker`/
  `bulwark_fixagent` each inherit the exact same privileges `bulwark_app` always had. Distinct,
  individually-revocable *identities* is the real, verified improvement; narrower *permissions* per
  service needs a function-by-function audit of `core.persistence.repo`'s call sites this pass did
  not attempt (ADR-0033).
- **No automated certificate rotation, and no real CA.** `scripts/gen-mtls-certs.sh` is dev/self-signed
  only; a real deployment needs its own CA and issuance process.
- **Crypto-shredding never touches the underlying ciphertext object.** Deleting a scan's data key
  makes that scan's data permanently unreadable, but the encrypted bytes themselves remain in object
  storage indefinitely, an intentional simplification (the plan's "backups included" framing implies
  exactly this: unrecoverable, not un-stored) rather than a real cleanup mechanism.
- **A concurrent first-use race for a scan's data key is unhandled.** Not triggered by the current
  sequential call pattern, but not structurally prevented either.
- **Only four secrets route through OpenBao.** Database passwords, Redis/S3 credentials, and the
  OpenBao token itself all remain plain environment variables -- protected at the connection layer by
  this week's mTLS work where applicable (Postgres), not moved into a secrets store.
- **Temporal's own database credential is password-only**, a disclosed, deliberate carve-out in an
  otherwise unconditional certificate requirement -- not a gap anyone should assume is closed.
- **The pre-existing `core.maintenance.reap_stale_scans` likely has the identical unscoped-RLS-query
  bug `shred_expired_scans` was caught and fixed for here**, discovered incidentally while building
  this week's work. It was not fixed as part of Week 47 -- it predates this week and is out of scope
  for it -- and was flagged separately instead.
