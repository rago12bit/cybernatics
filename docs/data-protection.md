# Data protection

How scan data is encrypted at rest and deleted, how internal services authenticate to Postgres, and
where secrets live. Design reasoning is in [ADR-0032](adr/0032-envelope-encryption-and-crypto-shredding.md)
(envelope encryption, crypto-shredding) and [ADR-0033](adr/0033-mtls-and-secrets-management.md) (mTLS,
secrets); the honest verification record is in [v2-week47-verification.md](v2-week47-verification.md).

## Envelope encryption

Each organization has a key-encryption key (KEK) held in OpenBao's Transit engine. Each scan gets its
own data key, wrapped by its organization's KEK, encrypting that scan's raw tool output before it's
written to object storage. Turning it on:

```bash
export BULWARK_OPENBAO_ADDR=http://openbao:8200
export BULWARK_OPENBAO_TOKEN=...
```

Without both set, scans store raw tool output exactly as they always have -- unencrypted, the
original behavior, not a degraded mode.

## Crypto-shredding and retention

An hourly sweep (`core.tasks.crypto_shred_task`) destroys a scan's data key once its organization's
retention window has passed -- default 7 days, configurable per organization at **Settings →
Retention** (`GET`/`PUT /settings/retention`). Destroying the key, not deleting the encrypted object
itself, is the entire mechanism: it makes that scan's raw tool output permanently unreadable,
including in any backup, without needing to locate and erase every copy of the ciphertext. Issues and
findings are never affected by this -- only the raw artifact.

## mTLS between services and Postgres

Every network connection to Postgres requires a client certificate whose CN matches the role
connecting: `api` connects as `bulwark_api`, `worker` as `bulwark_worker`, `fixagent-worker` as
`bulwark_fixagent`, and `migrate` as `bulwark` itself -- four distinct, individually revocable
identities instead of one shared credential. Generate a local dev CA and per-service certificates
once:

```bash
./scripts/gen-mtls-certs.sh
```

This writes a `certs/` directory (gitignored, never committed) that `docker-compose.yml` mounts into
Postgres and every service that talks to it. **A real deployment needs its own CA and certificate
issuance process** (cert-manager or equivalent) -- this script is dev/self-signed only.

## Secrets

`BULWARK_GITHUB_APP_PRIVATE_KEY`, `BULWARK_GITHUB_WEBHOOK_SECRET`, `BULWARK_API_TOKEN`, and
`BULWARK_LLM_API_KEY` all prefer a value stored in OpenBao's KV store when one exists there, falling
back to the plain environment variable otherwise -- unconditionally, so a deployment that has never
touched OpenBao for secrets keeps working exactly as before. Move existing plaintext secrets into
OpenBao once `BULWARK_OPENBAO_ADDR`/`BULWARK_OPENBAO_TOKEN` are set:

```bash
bulwark secrets migrate-env
```

This reports which secrets it moved and which were left alone (not set in the environment). It is
the only thing that writes to OpenBao's secret store; nothing does this automatically.

## Attachments and their origin

Evidence on manual findings, proof on risk acceptances and files on notes share one store: the
bytes are sniffed (the uploader's claimed type is kept only for display), encrypted with a fresh
data key wrapped by the organization's OpenBao key, and never rendered in the app. They download
only through a link signed for one file and one organization, valid for five minutes, served as
`application/octet-stream` with `Content-Disposition: attachment`, `nosniff` and a sandboxing CSP.

Set `BULWARK_ATTACHMENTS_ORIGIN` to a separate host routed to the API (Helm:
`api.attachmentsOrigin`) so that a captured HTML or SVG file, if someone opens it anyway, lands on
a host with no cookies, no token and no API behind it (threat T24, [ADR-0048](adr/0048-engagements-retests-collaboration.md)):

- that host serves signed downloads and nothing else (every other path answers 404), and never sets
  a cookie;
- the API's own host then refuses those downloads.

For local use, `http://attachments.localhost:8000` works without DNS: browsers resolve any
`*.localhost` name to this machine. Without the setting, files download from the API's own host,
which sets no cookies either.

## Advisories and project owners

Since Week 68 (ADR-0052) a project may name an owner: a reference to one of the organization's
people (`assets.owner`, the same `token:<prefix>` an Issue's assignee is), shown on advisory impact
views and audit-logged when it changes. The advisory data itself (OSV, CISA KEV, NVD) is public and
shared by every organization; what it means for one organization (`advisory_impacts`,
`advisory_states`) is under forced RLS. Fetching advisories sends nothing about an organization's
packages anywhere: matching happens inside Bulwark.

## Email addresses and notifications

Since Week 66 (ADR-0050) Bulwark stores one piece of personal contact data: the email address a
person gives in their notification settings, in `notification_prefs` under the same forced RLS as
every per-organization table. Only that person sets or clears it; the audit log records that it
changed, never the address. Notifications themselves (`notifications`) hold the one-line title and
a short excerpt of what happened -- a note's first 600 characters, for example -- and are kept with
the organization's other data.

Mail goes only to the operator's own SMTP server (`BULWARK_SMTP_*`), as plain text. Nothing is
emailed when no server is configured, and items waiting for a digest are then marked skipped rather
than kept.
