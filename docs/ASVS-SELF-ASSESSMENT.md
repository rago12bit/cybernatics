# OWASP ASVS 4.0.3 self-assessment (Level 1 + 2)

Bulwark scanning other projects for security issues without holding itself to the same bar would be
a strange place to stop, so this is a real self-audit against [OWASP ASVS
4.0.3](https://owasp.org/www-project-application-security-verification-standard/), Level 2. Every
row cites real code or docs, verified by reading the file, not assumed from a description. Where
something is genuinely absent, it says so plainly rather than being left off the table.

Status key: **Met** (verified in the code), **Partial** (some real mitigation, a real gap remains),
**Not met** (no mitigation found), **N/A** (the feature this control applies to doesn't exist in
Bulwark's architecture, explained inline). Where a control area applies to something Bulwark doesn't
have (native mobile apps, biometric auth, server-rendered HTML forms with CSRF tokens for a
stateless API), whole sub-areas are marked N/A once rather than enumerated line by line.

Last reviewed: 2026-10-01 (Week 48 task 3, plan §22.3). Three real gaps found during this review were
fixed as part of it, not just written down: see the "Fixed during this review" note under V8/V9/V10/V12.

## V1 — Architecture, Design and Threat Modeling

| Control | Status | Evidence |
|---|---|---|
| A documented, current threat model exists | Met | [docs/THREAT-MODEL.md](THREAT-MODEL.md) — STRIDE-based, per-threat status, last reviewed 2026-09-25 |
| Security decisions are recorded with rationale, not just implemented silently | Met | 33 ADRs in [docs/adr/](https://github.com/Rag2102/cyberimp/tree/main/docs/adr), each with a Status line; e.g. ADR-002 (Docker isolation), ADR-0013 (tenancy/RLS), ADR-0019 (audit log), ADR-0032/0033 (encryption, mTLS) |
| High-value components (auth, tenancy, sandboxing) are componentized, not scattered | Met | `core/tokens.py` (auth), `core/tenancy.py` (isolation), `core/sandbox/` (sandboxing) are each single-purpose modules other code depends on, not reimplemented per call site |
| Known limitations are disclosed, not silently assumed away | Met | [SECURITY.md](https://github.com/Rag2102/cyberimp/blob/main/SECURITY.md)'s "Known limits" section; `core/tenancy.py:29-35`'s own docstring on the shared-token org-claiming limitation |

## V2 — Authentication

Bulwark has no password-based authentication anywhere in the codebase (confirmed: no password
hashing, no login form, no "forgot password" flow exist). Authentication is bearer-token only.
Controls about password policy, account lockout, biometrics, and OTP hardware tokens are **N/A** —
there is no password to have a policy about.

| Control | Status | Evidence |
|---|---|---|
| Credentials are compared in constant time, not with `==` | Met | `api/deps.py:49-50` — `hmac.compare_digest` for the shared token |
| Tokens are not stored or logged in recoverable form | Met | `core/tokens.py:58-59` — SHA-256 hash stored, never the raw token; raw token is shown to the operator exactly once at creation (`cli/main.py`'s `token create` command) |
| Tokens can be scoped to least privilege | Met | `core/tokens.py:23` — `SCOPES` (`scans:read`/`scans:write`, `fixes:read`/`fixes:write`, `ingest:read`/`ingest:write`); `api/deps.py:116-125`'s `require_scope` |
| Tokens can expire and be revoked | Met | `api/deps.py:83-93` (expiry check on every request); `cli/main.py`'s `token revoke` command |
| Rate limiting on authentication attempts (brute-force resistance) | **Not met** | No rate limiting found on the auth path itself in `api/deps.py`. The only rate limiting in the codebase (`core/llm/limits.py`'s `UsageLimiter`) gates LLM-feature cost, not authentication attempts. A high-entropy 40-hex-char token (`core/tokens.py:14-23`) makes brute-forcing impractical regardless, but there is no explicit lockout/backoff mechanism |
| Multi-factor authentication | N/A | No user-identity concept exists yet (real per-user auth is plan §19.2, not built — this is a known, disclosed future item, not an oversight) |

## V3 — Session Management

Bulwark's API is fully stateless: no server-side session store, no session cookies. Every request
re-authenticates via its bearer token. Session-fixation, session-timeout, and CSRF-token controls
are **N/A** in the traditional sense — there is no session to fix, time out, or forge a request
against via a stolen cookie.

| Control | Status | Evidence |
|---|---|---|
| No session identifier is transmitted that could be fixed or hijacked | Met (N/A by design) | `api/deps.py:100-113` — auth is per-request from the `Authorization` header, nothing session-based exists to attack |
| A revoked credential takes effect immediately, not at next login | Met | Scoped-token revocation is checked on every request (`api/deps.py:83-93`), not cached |

## V4 — Access Control

| Control | Status | Evidence |
|---|---|---|
| Tenant data is isolated by a mechanism the database itself enforces, not application code alone | Met | `migrations/versions/0005_tenancy_rls.py:132-154` — Postgres `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + `CREATE POLICY tenant_isolation` on `assets/scans/tool_runs/findings/issues`, extended to every later table (`llm_usage`, `verified_fix_runs`, `hypotheses`, `code_chunks`, `data_retention_policies`, `scan_data_keys`, ...) |
| The application connects as a role RLS actually restricts, not a superuser | Met | `migrations/versions/0005_tenancy_rls.py:80-97` creates the non-superuser `bulwark_app` role — the docstring is explicit that `FORCE ROW LEVEL SECURITY` is a no-op against a superuser regardless of policies |
| Least-privilege database identity per service, not one shared credential | Met | `migrations/versions/0020_per_service_db_roles.py` — `bulwark_api`/`bulwark_worker`/`bulwark_fixagent`, each a distinct mTLS-authenticated identity; `bulwark_app` itself set `NOLOGIN` |
| API scopes are enforced server-side on every relevant endpoint | Met | `require_scope(...)` dependency (`api/deps.py:116-125`), applied per-endpoint in `api/main.py` |
| Cross-tenant access is proven impossible, not just assumed from code review | Met | `tests/integration/test_tenancy_rls_docker.py`, `test_data_protection_rls_docker.py` — live tests against real Postgres RLS, run in CI on every push (`.github/workflows/ci.yml`'s `tenancy-rls` job) |
| A caller cannot claim access to organizations it doesn't belong to | **Partial** | Disclosed, known limitation: `core/tenancy.py:29-35` — the legacy shared bearer token can specify any `X-Bulwark-Org` header value and RLS will isolate that org's *data* correctly, but nothing yet verifies the *caller* is entitled to act as that org (real per-organization identity is plan §19.2, not yet built). Scoped tokens (`core/tokens.py`) close this for themselves — an org is fixed on the token row and the header is ignored (`api/deps.py:128-139`) |

## V5 — Validation, Sanitization and Encoding

| Control | Status | Evidence |
|---|---|---|
| Output is escaped by default, not manually per call site | Met | React's default JSX escaping; no `dangerouslySetInnerHTML` found rendering scan-derived content |
| Attacker-controlled content (a scanned repo's own code) cannot execute as script in the browser | Met | `web/tests/xss.test.tsx` — a `Finding` with `<script>`, `onerror=`, `javascript:`/`data:` URLs injected into every field; asserts no live script/event-handler survives and only `https://` reference links pass an explicit allowlist |
| A per-request CSP with no `unsafe-inline` for scripts backs the escaping | Met | `web/proxy.ts:11-25` — nonce-based CSP, `strict-dynamic`, no `unsafe-inline`/`unsafe-eval` in production |
| API request bodies are structurally validated before use | Met | `api/schemas.py` — Pydantic models throughout (464 lines), e.g. `Literal` type discriminators, `max_length` constraints |
| SQL queries are parameterized, never string-concatenated | Met | No f-string/`%`/`.format()`-built SQL passed to `execute()` found in `core/persistence/repo.py`; the ORM (SQLAlchemy) is used throughout. The two places raw SQL text appears (`migrations/versions/0005_tenancy_rls.py`, `0020_per_service_db_roles.py`) bind org id as a parameter (`core/tenancy.py:51-54`, explicit comment: "always a bound parameter, never concatenated into SQL text") and embed a password literal only inside a `DO $$ $$` block (which can't take driver placeholders), sourced only from `scripts/init-env.sh`'s random hex generator, never user input — documented and justified in the code, not an unexamined oversight |
| Archive extraction rejects path traversal, symlinks, and decompression bombs | Met | `core/ingest.py:28-46` — `_safe_dest` rejects absolute paths and traversal; symlinks/special files rejected for both zip and tar; size/count/ratio limits checked against both metadata and actual bytes written |

## V6 — Stored Cryptography

| Control | Status | Evidence |
|---|---|---|
| Data at rest is encrypted with a modern, authenticated cipher | Met | `core/secrets/envelope.py:17-39` — AES-256-GCM via `cryptography.hazmat`, random 12-byte nonce per call, `nonce \|\| ciphertext+tag` format |
| Encryption keys are managed by a dedicated system, not embedded in application config | Met | `core/secrets/openbao.py` — OpenBao Transit engine mints/unwraps per-organization data keys; plaintext keys are never persisted, only OpenBao's own wrapped ciphertext |
| A ciphertext cannot be swapped onto a different record and still decrypt | Met | `core/secrets/envelope.py:33-34` — the storage key is bound as AEAD associated data; `core/persistence/storage.py:79,85` passes it through; a live test proves a swapped ciphertext fails closed (`DecryptionError`), not a wrong-but-plausible plaintext |
| Cryptographic failures fail closed, not open | Met | `core/secrets/envelope.py:42-55` — `InvalidTag` is mapped to a hard `DecryptionError`, never a silently-accepted fallback |
| Password hashing (bcrypt/argon2/scrypt) | N/A | No password authentication exists anywhere in the codebase (see V2) |
| High-entropy token identifiers are hashed before storage | Met | `core/tokens.py:58-59` — SHA-256 (a reasonable, standard choice for a 40-hex-char random token, which is not a low-entropy secret bcrypt-class slow hashing exists to protect) |

## V7 — Error Handling and Logging

| Control | Status | Evidence |
|---|---|---|
| Logs are structured and machine-parseable, not free-text string concatenation | Met | `core/observability/logs.py:24-27` — JSON-line logs carrying `scan_id`/`trace_id`/`span_id` via `contextvars` |
| Log injection (newline forgery) is structurally prevented | Met | JSON-line format means a value containing a newline is encoded, not interpreted as a new log line (`core/observability/logs.py`'s own docstring) |
| Secrets are scrubbed from logs, not just from user-facing output | Met | `core/observability/logs.py:20` imports the same `core.llm.scrub.scrub_secrets` detector the LLM layer uses |
| Security-relevant events are recorded in a tamper-evident audit trail | Met | `core/audit.py` — hash-chained entries (`entry_hash = SHA256(seq \|\| prev_hash \|\| timestamp \|\| actor \|\| action \|\| target \|\| payload_digest)`), genesis hash fixed, payload stored as a digest so deleting the underlying record (a revoked token, a removed installation) never breaks the chain |
| The audit chain's integrity can be independently verified | Met | `bulwark audit verify` (`cli/main.py`) walks the whole chain and recomputes every hash; `core/audit_rekor.py` can publish checkpoints to Sigstore Rekor's public transparency log (opt-in per publish, not automatic — a real, permanent public write is deliberately not silent) |
| Error responses do not leak stack traces or internal details to the client | Met | No `debug=True` passed to `FastAPI(...)` (`api/main.py:248`), so FastAPI's safe default (no traceback in the response body) applies; `HTTPException` call sites raise clean, specific messages, not interpolated exception internals |

## V8 — Data Protection

**Fixed during this review**: none needed — this area was already solid going in (see below).

| Control | Status | Evidence |
|---|---|---|
| Sensitive data is encrypted at rest with per-tenant, per-record keys | Met | See V6 — `core/secrets/envelope.py` + `core/secrets/openbao.py`, wired into `core/persistence/storage.py`'s `EncryptingObjectStore` |
| Data can be made permanently unrecoverable on request/expiry, including against backups | Met | `core/retention.py:38-73` — crypto-shredding: destroying a scan's wrapped data key (not the ciphertext object itself, and never the Scan/Issue/Finding rows) makes it permanently unreadable, backups included, without needing to locate and erase every copy |
| Retention is configurable per tenant, not a single global policy | Met | `core/persistence/repo.get_retention_days` — per-org, default 7 days, configurable via `GET`/`PUT /settings/retention` |
| Secrets are redacted from data that reaches a person or a model, not just from the primary output | Met | `core/redact.py:21,36-37` (findings), `core/llm/scrub.py`/`core/llm/pii.py` (LLM prompts), Gitleaks output redacted at the source tool (`core/pipeline.py:348`) |
| Sensitive data does not appear in URLs or query strings | Met | Scoped tokens are sent as `Authorization: Bearer`, never a query parameter; no grep hits for tokens/secrets in URL construction in `web/lib/api.ts` |

## V9 — Communications

| Control | Status | Evidence |
|---|---|---|
| Internal service-to-service connections are mutually authenticated | Met | `docker/postgres/pg_hba.conf` — `cert clientcert=verify-full` required for every network connection to Postgres; `migrations/versions/0020_per_service_db_roles.py` ties each service's certificate CN to its own database role |
| A third-party dependency that can't meet the internal standard is an explicit, scoped exception, not a silent gap | Met | `docker/postgres/pg_hba.conf`'s own comment: Temporal's auto-setup image (`temporal_svc`) is carved out by role name for password auth, since it cannot present a client certificate — every role Bulwark's own code uses keeps the certificate requirement unconditionally |
| HTTP Strict Transport Security is sent wherever the deployment is actually served over HTTPS | **Fixed during this review** | Previously: `web/proxy.ts` set HSTS *only* when `NEXT_PUBLIC_DEMO_ONLY=1`, meaning any other production deployment — including one that does terminate real TLS — never got it. Fixed: HSTS now also fires when an operator explicitly sets `BULWARK_FORCE_HTTPS=1` (`web/proxy.ts`, this review). Forcing it on by default for *every* `NODE_ENV=production` build was deliberately rejected: Bulwark's documented self-hosted path may run over plain HTTP with no TLS termination at all, and HSTS would make browsers refuse to reconnect entirely in that case — opt-in is the honest fix, not a default that could break a real, documented deployment path |
| Cross-origin isolation headers are set on real pages | Met | `web/proxy.ts` — `Cross-Origin-Embedder-Policy: require-corp`, `-Opener-Policy: same-origin`, `-Resource-Policy: same-origin`, all added and live-verified (real browser load, zero console errors, ZAP re-scan) as part of Week 48 task 2's own ZAP baseline findings |
| CORS is an explicit allowlist, never a wildcard | Met | `core/config.py:25` (default origin list), `api/main.py:255-260` — explicit `CORSMiddleware` origins, comment "never '*'", methods and headers both restricted |

## V10 — Malicious Code

| Control | Status | Evidence |
|---|---|---|
| Untrusted code (a scanned repository) never executes on the host outside a sandbox | Met | `core/sandbox/docker_runtime.py:27-62` — one ephemeral container per tool: `--network=none`, `--read-only` rootfs, `--cap-drop=ALL`, non-root uid, `--security-opt=no-new-privileges`, memory/CPU/pids limits, target mounted read-only; ADR-002 |
| A deeper isolation layer exists for the case a container escape isn't enough | Partial | ADR-0031's own status line: `SandboxRuntime`/gVisor backend is written and argv-tested, but has never actually executed (no Linux dev host, no macOS `runsc` build) — a real, disclosed gap, not a claim of completion |
| Bulwark's own dependencies are scanned for known vulnerabilities, not just the dependencies it scans for others | **Fixed during this review** | Previously: no evidence of this at all — Bulwark ships OSV-Scanner/Grype as *products* for other people's code (ADR-0024) but had no equivalent check on its own `pyproject.toml`/`package.json`. Fixed: `.github/workflows/ci.yml`'s new `dependency-audit` job runs `pip-audit` and `npm audit` on every push and pull request; `.github/dependabot.yml` (new) proposes weekly update PRs for pip, both npm projects, and GitHub Actions versions |
| Third-party licenses are checked, not just vulnerabilities | Met | `scripts/gen-licenses.py` — a real policy (deny AGPL/SSPL/BUSL-class licenses, flag weak-copyleft for review), enforced in CI's `licenses` job |

## V11 — Business Logic

| Control | Status | Evidence |
|---|---|---|
| Expensive, cost-bearing operations (LLM calls) are rate-limited per tenant | Met | `core/llm/limits.py`'s `UsageLimiter`, wired at `api/deps.py:36`; 429 responses on every LLM-backed endpoint |
| Concurrent long-running workflows are capped | Met | `api/main.py`'s verified-fix/scan endpoints return 429 on a per-organization concurrency cap |
| General-purpose API rate limiting / abuse prevention on ordinary read/write endpoints | **Not met** | No general request-rate-limiting middleware found in `api/main.py`/`api/deps.py`. The only rate limiting that exists is cost-driven (LLM usage), not abuse-prevention-driven. A single-operator, bearer-token-gated deployment (this project's current documented trust model, SECURITY.md's "Known limits") makes this lower-severity than it would be for a multi-tenant public service, but it is a real, disclosed gap for anyone exposing the API more broadly |

## V12 — Files and Resources

**Fixed during this review**: see below.

| Control | Status | Evidence |
|---|---|---|
| Uploaded archives are protected against zip-slip / path traversal | Met | `core/ingest.py:28-35` — `_safe_dest` rejects absolute paths, null bytes, and traversal via `.resolve()` + parent-containment check |
| Uploaded archives are protected against decompression bombs | Met | `core/ingest.py:38-46` — compressed size, uncompressed size, file count, and compression-ratio limits, checked against both metadata *and* actual streamed bytes |
| Symlinks and special files inside an archive are rejected | Met | `core/ingest.py:73-74` (zip), `93-94` (tar) |
| Pathologically deep directory structures inside an archive are rejected | **Fixed during this review** | Previously: [SECURITY.md](https://github.com/Rag2102/cyberimp/blob/main/SECURITY.md) claimed "depth limits" but no such check existed in `core/ingest.py` — an inaccurate claim, found and corrected by actually checking the code rather than trusting the doc. Fixed: `Limits.max_depth` (default 64 path components), enforced in `_safe_dest`, tested (`tests/unit/test_ingest.py`'s new depth-limit tests). SECURITY.md's claim is now accurate rather than aspirational |

## V13 — API and Web Service

| Control | Status | Evidence |
|---|---|---|
| The API is documented from its actual implementation, not a hand-maintained spec that can drift | Met | `scripts/gen-api-docs.py` generates `docs/openapi.json`/`docs/api.md` from the live FastAPI app |
| CORS is scoped, not permissive | Met | See V9 |
| Every endpoint but the health check requires authentication | Met | SECURITY.md's own stated control, `api/deps.py`'s `require_auth`/`require_scope` dependencies applied per-route in `api/main.py` |
| Interactive API documentation exposure is a considered choice, not a default left unexamined | Partial | FastAPI's `/docs`/`/openapi.json` are live by default (`FastAPI(...)` at `api/main.py:248` passes no `docs_url=None`). This exposes the API's schema to anyone who can reach it — not a vulnerability on its own (every real call still requires a bearer token), but worth an explicit decision for any deployment that shouldn't advertise its API surface publicly; not disabled or made configurable in this review |

## V14 — Configuration

| Control | Status | Evidence |
|---|---|---|
| The application refuses to start with an insecure configuration, rather than starting insecurely | Met | `api/main.py:244-247` — refuses to start if `BULWARK_API_TOKEN` is unset or below the minimum length |
| Debug/verbose error modes cannot be accidentally enabled in production | Met | No `debug` flag exists in `core/config.py` at all; no `debug=True` passed to `FastAPI(...)` — there is no configuration knob to leak, rather than one that defaults safely |
| Secrets prefer a dedicated secrets store over plain environment variables | Met | `core/secrets/resolve.py` — GitHub App credentials, the API token, and the LLM API key all prefer OpenBao's KV store when configured, with an unconditional environment-variable fallback (`bulwark secrets migrate-env` moves existing values over) |
| Security-relevant HTTP response headers are set comprehensively | Met | `web/proxy.ts` — CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Embedder/Opener/Resource-Policy`, conditional HSTS (see V9) |
| Default credentials are never shipped | Met | Every secret (`scripts/init-env.sh`) is generated fresh via `openssl rand -hex 24`; nothing ships with a fixed default password or token |

## Summary of gaps found and their disposition

| Gap | Severity | Disposition |
|---|---|---|
| No rate limiting / brute-force protection on authentication attempts (V2) | Low (high-entropy tokens mitigate) | Disclosed, not fixed this pass |
| A caller can claim any org via the legacy shared token's header (V4) | Already disclosed pre-existing limitation | Unchanged; real per-org identity is plan §19.2 |
| No general API rate limiting / abuse prevention (V11) | Medium for a multi-tenant deployment, low for the current single-operator model | Disclosed, not fixed this pass |
| HSTS not set for most production deployments (V9) | Medium | **Fixed**: opt-in via `BULWARK_FORCE_HTTPS=1` |
| No CVE scanning of Bulwark's own dependencies (V10) | Medium | **Fixed**: `dependency-audit` CI job + Dependabot |
| No archive path-depth limit despite SECURITY.md claiming one (V12) | Low, and a documentation-accuracy issue | **Fixed**: `Limits.max_depth`, tested |
| gVisor/Firecracker isolation layer never actually executed (V10) | Already disclosed (ADR-0031) | Firecracker built for the fix agent's test runs (2026-10-12) and its guest side booted under QEMU; neither runtime has run on a KVM/`runsc` host yet |
| Interactive API docs live by default (V13) | Low | Disclosed, left as a deployment-time decision |
