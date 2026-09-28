# ADR-0019: Tamper-evident audit log (hash chain + Rekor checkpoints)

Status: Implemented (2026-09-28, Week 30 backfill), except a real, published Rekor checkpoint —
that step is a real, permanent, public write to a third-party transparency log, done only with
explicit confirmation each time, not automatically as part of this backfill. See
docs/v2-week29-backfill-verification.md for exactly what was and wasn't verified live.

## Context

Nothing in Bulwark records *that* a security-relevant action happened in a way that survives
someone with database access editing or deleting the record afterward. The plan's §19.3 (and its
own ADR-008 slot) asks for a hash-chained log with periodic checkpoints signed and published to
Sigstore's Rekor transparency log — "the original blockchain idea done properly": tamper-evidence
without a distributed ledger, using infrastructure the software supply-chain world already
depends on (this project already uses cosign/Sigstore for SBOM attestation, ADR-009).

## Decision

`core/audit.py` (pure logic, no DB access — mirrors `core/issues.py`'s split):

```
entry_hash = SHA256(seq || prev_hash || timestamp || actor || action || target || payload_digest)
```

- `payload_digest`, never the payload itself: deleting the underlying record later (a revoked
  token, a removed installation) must never break the chain, since the chain never depended on
  that data still existing.
- `seq` is application-assigned, not a database autoincrement — the chain needs to know the exact
  sequence number *before* the row exists, to hash it. `core/persistence/repo.py`'s
  `append_audit_entry` handles the read-latest-then-insert race with a bounded optimistic-retry
  loop, not a database lock: an accepted, documented simplification at this project's current
  scale (one API process, one worker), not a claim that a concurrent-write race is impossible.
- `verify_chain` checks each entry's `prev_hash` against the *actual* previous entry's
  `entry_hash` — not against that entry's own `prev_hash` field, which an attacker could edit to
  agree with a forged `entry_hash` on the same row. Editing any stored field is caught at that
  entry; deleting an entry is caught at the *next* one, whose `prev_hash` now points at a hash
  that doesn't exist.

A single, global, operator-facing ledger — not per-organization. There's no per-org sign-in yet for
a per-org audit screen to gate access to (that's the deferred identity work, §19.2/ADR-0018's own
deferred item); building per-org filtering ahead of the UI that would need it is speculative scope.

**Checkpointing (`core/audit_rekor.py`) is key-based signing with real Rekor upload, not keyless.**
The plan's own architecture diagram mentions "keyless signing through Sigstore's Fulcio CA," but
keyless signing needs an OIDC identity provider this project doesn't integrate with for a
long-running self-hosted server (GitHub Actions gets this for free via its own ambient OIDC token;
a Docker Compose deployment does not). Rekor's transparency-log guarantee doesn't require keyless
signing — a key-based `cosign sign-blob` still uploads to the public log unless told not to, which
is exactly this module's job. This reuses the same `cosign generate-key-pair` / `COSIGN_PASSWORD`
setup `core/attest` already documents, in a **new, separate module** rather than extending
`core/attest/cosign.py`: that module signs scan artifacts completely offline (`--network=none`,
`--tlog-upload=false`) by design, and a checkpoint's entire purpose is the opposite of offline.

`bulwark audit verify` walks the whole chain and recomputes every hash; `bulwark audit checkpoint`
signs the current head and publishes it. Neither runs automatically yet (see below).

## Alternatives considered

- **Keyless (Fulcio-issued, OIDC-bound) signing**, as the plan's diagram suggests. Rejected for
  now: no OIDC identity provider integration exists for a long-running server outside GitHub
  Actions' own workflow context. Revisit if/when Bulwark runs *as* a GitHub Actions-triggered job
  for this specific purpose, or integrates a real OIDC provider for other reasons first.
- **A DB-level lock (advisory lock or `SELECT ... FOR UPDATE`) around `append_audit_entry`**,
  instead of an optimistic retry loop. Rejected for this week: more moving parts (and a dialect
  difference between SQLite tests and Postgres) for a race that's currently unlikely at this
  project's scale. Documented as an accepted simplification, not hidden.

## What was actually built, and where it differs from the design above

- **A real, live-tested, genuine bug was caught building this**: SQLite (and possibly a
  differently-configured Postgres session) can hand back a *naive* datetime even for a
  `DateTime(timezone=True)` column. `compute_hash`'s original `.astimezone(timezone.utc)` on a
  naive value assumes the *local* zone, silently shifting it — meaning `verify_chain` would
  recompute a different hash than the one written, and report a perfectly untampered chain as
  broken. Fixed by treating a naive timestamp as already UTC (every timestamp this codebase writes
  is UTC, `core.persistence.models._now`) before hashing. Caught by a real, live test failure
  against actual data, not by inspection — and confirmed fixed against both SQLite and real
  Postgres afterward.
- **Automatic checkpointing (every hour or every N entries, per the plan) is not wired up.**
  `bulwark audit checkpoint` exists and works, run by hand or from external cron/CI, but nothing in
  `core/tasks.py`'s Celery beat schedule calls it yet. A deliberate Week 30 scope cut: wiring a
  scheduled task is small, but this ADR's job was proving the checkpoint mechanism itself works
  (including a real, deliberately-confirmed publish to the public Rekor instance) before automating
  when it fires.
- **No audit log screen in the web app.** Backend + CLI only, consistent with how this project's
  API has repeatedly shipped ahead of its UI.
- **Only two real integration points log anything today**: `installation.created` /
  `installation.deleted` (the GitHub App webhook, ADR-0017) and `token.created` / `token.revoked`
  (ADR-0018's CLI). Most of the plan's own example actions to log — role changes, triage decisions,
  accepted risk, policy changes, fix approvals, DAST authorizations — don't exist as features yet.
  The log is real and ready for them; there is nothing to log for a feature that isn't built.

## Consequences

- Every future feature the plan lists as auditable (risk acceptance, policy changes, fix approvals,
  DAST authorization) should call `repo.append_audit_entry` when it ships, not retrofit it later —
  this ADR is the checklist a reviewer should hold new security-relevant actions to.
- A real Rekor checkpoint, once published, is permanent and public. `bulwark audit checkpoint`
  should not be run against production data without deliberately intending that — there's no
  `--undo`.
- `audit_entries`/`audit_checkpoints` carry no `org_id` and no RLS; if this ever needs to become
  per-organization (a customer-facing audit screen, not just an operator one), that's a schema
  migration and a scoping decision this ADR does not make for it.
