# ADR-0033: mTLS between services and secrets in OpenBao

Status: Implemented (2026-10-01), Week 47 tasks 3-4 (plan §22.2), the second half of "Data
protection" -- envelope encryption and crypto-shredding (tasks 1-2) are ADR-0032.

## Context

Every service connected to Postgres as one of two shared, password-only roles: `bulwark` (the
table-owning role, used by `migrate`) or `bulwark_app` (shared by `api`, `worker`, and
`fixagent-worker`). A leaked or misconfigured credential for one service was indistinguishable from
any other's, and nothing but the Docker network boundary stood between a connection and the
database. Separately, several real secrets (the GitHub App private key, its webhook secret, the API
bearer token, the LLM API key) lived only in plain environment variables, closing over from v1 and
never revisited once OpenBao existed as real infrastructure (ADR-0032).

## Decisions

### Every network connection to Postgres requires a client certificate, with no exceptions for Bulwark's own services

`docker/postgres/pg_hba.conf` requires Postgres's `cert` authentication method
(`clientcert=verify-full`) for every `hostssl` connection: a client must present a certificate signed
by the project's own CA, and that certificate's CN must exactly match the role it connects as. This
was verified against a real built image, not assumed from Postgres's documentation: the exact
ownership and permission Postgres requires for a bind-mounted private key (a bind mount from the
host is owned by the host user, which Postgres refuses outright), `verify-full`'s server-hostname
check against the actual compose service name, and that a certificate signed by the right CA but for
the wrong CN is rejected as cleanly as no certificate at all.

### Each service gets its own identity by role membership, not by duplicating grants

`bulwark_api`, `bulwark_worker`, and `bulwark_fixagent` (migration 0020) replace the single shared
`bulwark_app` connection every one of `api`/`worker`/`fixagent-worker` used before. None of the three
duplicates `bulwark_app`'s table grants: each is simply a *member* of `bulwark_app`
(`GRANT bulwark_app TO <role>`), which -- Postgres roles default to `INHERIT` -- gives it every
privilege `bulwark_app` already has, automatically, including whatever a *future* migration grants
to `bulwark_app` later. `bulwark_app` itself is set `NOLOGIN`: it still holds every grant, but
nothing can connect directly as it anymore. This was the deliberate alternative to actually auditing
and narrowing each service's specific table-level privileges: this codebase's `core.persistence.repo`
module is shared by both the API and the worker code paths, and confidently splitting exactly which
operations each one performs, table by table, without breaking production on a wrong guess, is real,
separate work this pass does not attempt. Distinct, individually-revocable identities is the genuine,
verified improvement shipped here; true least-privilege grants per service is disclosed as deferred,
not silently assumed to have happened.

### The one disclosed carve-out: Temporal's third-party image can't present a certificate

`docker-compose.yml`'s `temporal` service (`temporalio/auto-setup`, the opt-in `fixagent` profile) is
a third-party image with no support for client certificates. Rather than weakening the rule for every
service to accommodate one, it connects as its own dedicated role, `temporal_svc`
(`docker/postgres/init-temporal-role.sh`, created once at first init, `CREATEDB` for its own
`temporal`/`temporal_visibility` databases), authenticated by password and carved out by role name in
`pg_hba.conf` ahead of the catch-all certificate rule. Every role Bulwark's own code connects as --
`bulwark`, `bulwark_api`, `bulwark_worker`, `bulwark_fixagent` -- keeps the certificate requirement
unconditionally.

### The per-service roles also get a password, unused by production, so CI can keep testing RLS without a parallel mTLS setup

`docker/postgres/pg_hba.conf`'s `cert` method never checks a role's password, so setting one changes
nothing about what production actually enforces. It does mean `.github/workflows/ci.yml`'s
`tenancy-rls` job -- which needs real Postgres and real RLS, not the SQLite application-level
tests -- can keep running against a plain `pgvector/pgvector:pg16` image with no custom certificate
configuration, connected as `bulwark_worker` over an ordinary password, instead of `bulwark_app`,
which migration 0020 makes `NOLOGIN`. Building a full parallel mTLS-capable CI environment just to
test RLS policy correctness (a concern this ADR's certificate work is orthogonal to) was judged not
worth the added CI fragility.

### Secrets prefer OpenBao's KV store, with an unconditional environment-variable fallback

`core.secrets.resolve.resolve_secret` checks OpenBao's KV v2 engine (`secret/data/<path>`) first when
`BULWARK_OPENBAO_ADDR`/`BULWARK_OPENBAO_TOKEN` are both set and the secret actually exists there,
falling back to the named environment variable in every other case: OpenBao unconfigured, OpenBao
unreachable, or the secret simply not migrated yet. `core.config.Settings` and `core.llm.client.
LLMConfig` both route their sensitive fields (the GitHub App private key and webhook secret, the API
bearer token, the LLM API key) through it. This is additive, not a breaking change: every existing
deployment that has never touched OpenBao keeps reading exactly the environment variables it always
has, unconditionally -- the same "off means off" posture as every other optional integration in this
project, verified by confirming an OpenBao-configured-but-secret-not-yet-written case still falls
through to the environment variable, not an error.

### A CLI command moves existing plaintext secrets into OpenBao; nothing does this automatically

`bulwark secrets migrate-env` reads each of the four secrets `resolve_secret` knows about from the
current environment and writes them into OpenBao's KV store, reporting which it migrated and which
it skipped (not set). It is a one-time, explicitly operator-triggered action -- nothing in this
change silently moves a secret on its own, and a deployment that never runs this command behaves
identically to one from before this task existed.

## What is NOT done

- **True least-privilege database grants per service.** The three new roles inherit the exact same
  privileges `bulwark_app` always had; narrowing what each one can actually do requires auditing
  `core.persistence.repo`'s call sites function by function, which this pass explicitly did not
  attempt (see the decision above).
- **No automated certificate rotation or a real CA.** `scripts/gen-mtls-certs.sh` is a dev/self-signed
  generator; a real deployment needs its own CA and issuance process (cert-manager or equivalent),
  not this script.
- **Database connection strings (passwords, URLs) are not migrated into OpenBao.** Only the four
  secrets named above route through `resolve_secret`; `APP_DB_PASSWORD` and the Postgres/Redis/S3
  connection strings still come from plain environment variables, now additionally protected by mTLS
  at the connection layer (this ADR) rather than by being moved into a secrets store.
- **Temporal's own Postgres credential remains password-only,** an explicitly disclosed gap in an
  otherwise unconditional certificate requirement, not an oversight.
