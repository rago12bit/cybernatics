# ADR-0032: Envelope encryption and crypto-shredding

Status: Implemented (2026-10-01), Week 47 tasks 1-2 (plan §22.2), the first half of "Data
protection" -- mTLS and secrets management (tasks 3-4) are ADR-0033.

## Context

Raw scanner output stored in object storage (`core.pipeline._store_raw`) has been plaintext since
v1: readable by anyone with S3 credentials, and unrecoverably deletable only by finding and erasing
every copy, including in backups. The plan asks for envelope encryption -- each organization holds a
key-encryption key (KEK), each scan gets its own data key (DEK) wrapping the actual bytes -- and
"deletion by crypto-shredding": destroying a scan's DEK makes its data permanently unreadable without
needing to reach the ciphertext itself, backups included.

## Decisions

### OpenBao's Transit engine mints and unwraps data keys; this project never re-implements envelope encryption's key math

`core/secrets/openbao.py`'s `generate_data_key`/`unwrap_data_key` call Transit's own
`/datakey/plaintext` and `/decrypt` endpoints -- Vault/OpenBao's built-in primitive for exactly this
pattern, not something assembled from a lower-level encrypt call. The plaintext DEK exists only for
the duration of one `core.secrets.envelope.encrypt`/`decrypt` call; OpenBao itself never sees a
scan's actual data, only ever wraps and unwraps a 32-byte key. Every method's exact request/response
shape, and two things that would have been wrong guesses (Transit key creation is idempotent, but
mounting the engine itself is not; a bad ciphertext comes back as a clean HTTP 400, not a
connection-level failure), were confirmed against a real `openbao/openbao:2.1` dev-mode container
before being written, not assumed from documentation alone.

### The storage key itself is authenticated, not just the payload

`core.persistence.storage.EncryptingObjectStore` passes the object's own storage key (e.g.
`scans/<id>/raw/bandit.json`) as AES-GCM associated data. This means a ciphertext can never be
copied onto a different object's key and still decrypt -- verified with a real test that swaps one
scan's stored ciphertext onto another scan's key and confirms decryption fails closed
(`DecryptionError`), not a wrong-but-plausible plaintext.

### Encryption is wired into the real production path, off by default

`core.tasks.run_scan_task` builds its `ObjectStore` through `core.persistence.storage.
build_object_store`, which returns a plain `S3Store` unless `BULWARK_OPENBAO_ADDR`/
`BULWARK_OPENBAO_TOKEN` are both set -- the same "off means off, not a silent partial feature"
posture the GitHub App integration and LLM gateway already use. A scan's data key is minted once
(first `put`) and reused for every object that scan writes, looked up and unwrapped again on every
subsequent read; this needed its own care about Postgres RLS (see `core.persistence.storage.
_resolve_scan_data_key`'s docstring) since `scan_data_keys` carries the same tenant-isolation policy
every other RLS table does.

### Crypto-shredding destroys the key, never touches the ciphertext or the scan/issue rows

`core.retention.shred_expired_scans` deletes a scan's `scan_data_keys` row once its organization's
retention window has passed (`core.persistence.repo.get_retention_days`, default 7 days, plan
§22.2). This is the entire mechanism: the encrypted object itself is never located or deleted, and
neither is the `Scan` row or any `IssueRow`/`FindingRow` -- the plan is explicit that issues are kept
regardless ("keep issues"). A scan whose data key is gone is functionally indistinguishable from one
that never had encryption enabled in the first place, from the object-storage side; only
`get_scan_data_key` returning `None` reveals which case applies, and callers are not meant to
distinguish them.

### The sweep iterates one organization at a time, not one query across all of them

`scans` and `scan_data_keys` both carry `FORCE ROW LEVEL SECURITY` policies keyed on
`app.current_org` (migrations 0005/0018), and the worker's `bulwark_app`-family connection is
`NOBYPASSRLS` by design (ADR-0013). A single unscoped query across every organization's rows would
see *zero* rows under RLS, not every organization's -- an unset session variable satisfies no
policy, not all of them. `shred_expired_scans` discovers the full list of organizations from the
`organizations` table (the one table with no RLS, ADR-0013/0017), then opens a session scoped to
each org in turn via `core.tenancy.set_session_org` before querying that org's own rows. This exact
gap was caught and fixed here before shipping; the same gap in the older, pre-existing
`core.maintenance.reap_stale_scans` was found along the way and flagged separately rather than fixed
inline, since it's outside this week's scope.

### Time comparisons happen in Python, not in the SQL WHERE clause

SQLite (every unit test) stores timestamps as naive text; comparing a stored naive value against an
aware `cutoff` inside a database-level `WHERE` clause silently matches nothing under SQLite, even
though the same comparison is correct under real Postgres. `core.maintenance.reap_stale_scans`
already worked around this by filtering in Python against `_aware()`-normalized values;
`shred_expired_scans` follows the same pattern rather than reintroducing the bug in new code.

## What is NOT done

- **No object-storage cleanup.** Crypto-shredding leaves the ciphertext bytes in place forever
  (permanently unreadable, but still occupying storage). Deleting the underlying S3 objects too
  would be a reasonable follow-up but was not in this week's scope.
- **A concurrent first-use race for one scan's data key is unhandled.** Two parallel calls to
  `_resolve_scan_data_key` for the same never-before-seen `scan_id` could both attempt to insert a
  `scan_data_keys` row; the current call pattern (`_store_raw` writes sequentially within one scan)
  never triggers this, but it is not defended against structurally.
- **No manual, user-triggered "delete my data now" endpoint.** Only the automatic per-organization
  retention sweep exists; an explicit right-to-erasure-style API was not built this pass.
