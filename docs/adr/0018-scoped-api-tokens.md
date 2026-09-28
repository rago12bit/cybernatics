# ADR-0018: Scoped, hashed, prefixed API tokens

Status: Implemented (2026-09-28, Week 29 backfill). Verified live against real Postgres; see
docs/v2-week29-backfill-verification.md.

## Context

v1.0/Week 29 authenticated every request with one shared `BULWARK_API_TOKEN` — "the whole
deployment," full access, org selected only by a client-suppliable `X-Bulwark-Org` header
(ADR-0013). ADR-0013 documented this as a known limitation, not a finished access-control story: a
caller who knows the token can claim any org id that exists.

The plan's §19.2 asks for real per-token identity: a recognizable prefix plus a checksum (GitHub's
own token format), shown once, stored only as a hash, carrying scopes, and expiring.

## Decision

`core/tokens.py` (pure logic) generates `bulwark_<40 hex chars>_<6-char base62 checksum>`:

- The checksum (CRC32-derived) is a typo/truncation check, not a security property — it lets a
  clearly-malformed token be rejected before it ever reaches a database lookup.
- Only `sha256(raw)` is ever persisted (`ApiToken.token_hash`); the raw value is returned exactly
  once, by `core.persistence.repo.create_api_token`, and the CLI that calls it never logs it.
- `display_prefix` (the first 14 characters) is safe to show afterwards in a token listing, so an
  operator can tell tokens apart without the secret ever being reconstructable from it.

**Scopes are real and enforced, not decorative.** `SCOPES = {"scans:read", "scans:write"}` today —
deliberately smaller than the plan's own example (`issues:read`), because there is no dedicated
issues endpoint yet (ADR-0012's own deferred item) to gate with it. A scope that nothing checks
would be a scope that lies about what it does; new scopes get added alongside the endpoint they
actually restrict, not ahead of it.

**A scoped token's org is authoritative, not client-suppliable.** `api/deps.py`'s `AuthContext`
carries `org_id` and `scopes` from whichever credential authenticated the request:

- The legacy shared token: `org_id=None, scopes=None` — "the whole deployment," exactly ADR-0013's
  existing behavior, `X-Bulwark-Org` still selects scope as before.
- A real scoped token: `org_id` fixed to the token's own org, `X-Bulwark-Org` **ignored entirely**
  for it. Trusting a client-suppliable header over what the token actually authenticated as would
  defeat the entire point of scoping the token — this is the concrete fix for the exact limitation
  ADR-0013 named.

**`api_tokens` carries no Row-Level Security policy**, for the same structural reason
`github_installations` doesn't (ADR-0017): authenticating a request with a token is what *resolves*
org context in the first place, so the lookup that does it can't itself require org context to
already exist. It's a directory/credential table, not tenant-owned content.

**Token management is CLI-only** (`bulwark token create/list/revoke`), not a self-service API
endpoint. There is no per-user identity yet for a "your tokens" page to belong to (that's the
deferred piece below) — an operator with direct database/container access mints tokens for now, the
same trust boundary `bulwark kb load` already operates at.

## Alternatives considered

- **A separate lookup table keyed by a short public id**, instead of hashing the whole token and
  looking up by hash directly. Rejected: unnecessary complexity — `token_hash` is already a
  fixed-length, indexed, exact-match value; there's no scan-the-table cost to avoid.
- **Letting the org header override a scoped token's org when explicitly requested.** Rejected:
  no legitimate use case needs it, and it reintroduces exactly the trust-the-header problem this
  ADR exists to close.

## What was actually built, and where it differs from the design above

- **No custom Gitleaks rule for the platform's own token format**, despite the plan explicitly
  asking for one ("the scanner protects its own credentials"). This needs mounting a custom
  `.gitleaks.toml` into the gitleaks scanner container, but the sandboxed runner
  (`core/runner.py`) launches sibling containers via the *host's* Docker daemon (Docker-outside-
  of-Docker, the same reason `BULWARK_WORKDIR` must be host-visible) — a bind mount path has to
  exist on the host, not just inside the api/worker container, and no such mechanism exists yet
  for a one-off config file. A real, small follow-up (extend `ToolSpec` with a read-only mount,
  materialize the config into `scratch_dir()`), deliberately not rushed into the sandboxing code
  in the middle of an already-large backfill.
- **No self-service token API**, no web UI for tokens — CLI-only, as decided above; not a
  deviation so much as the plan's own identity work (§19.2's sign-in) not existing yet to hang a
  self-service page off of.

## Consequences

- `AuthContext.actor` (e.g. `"token:bulwark_5c83e8"`) is available for audit-log attribution
  (ADR-0019) wherever an authenticated API request should be logged — not wired into every
  endpoint yet, since most of the plan's own example audit actions (role changes, triage, fix
  approvals) don't exist as features yet either.
- A future org-management/self-service API, when it exists, should reuse `require_scope` and
  `AuthContext` rather than inventing a second auth layer alongside them.
