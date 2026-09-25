# Threat model

Bulwark downloads or accepts untrusted code and runs third-party tools over it, then renders what those
tools say. That is an attack surface. This document lists what we defend against, what actually exists in
the code today, and what does not. Status is stated per threat so it can be checked, not assumed.

Status key: **Done** (implemented and tested), **Partial** (some of the mitigation exists), **Open** (not
implemented), **N/A yet** (the feature that creates the threat is not built).

Last reviewed: 2026-09-25 (v0.1.0). Review again before any deployment that accepts scans from people you
do not trust.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| The host running the worker and Docker | The worst outcome is code from a scanned repo running on it |
| Source code and secrets inside scanned repos | Users upload private code; findings can echo secrets |
| The API token | The only credential; grants full access |
| Report consumers (browsers, GitHub, PDF readers) | They render text that came from an attacker-controlled repo |

Boundaries: (1) the scanned repository is **untrusted** input to everything; (2) scanner containers are
**untrusted** processes; (3) the worker, API and database are trusted; (4) the browser is trusted only to
render text, never to run scan-derived markup.

## STRIDE summary

| # | Threat | Category | Status |
|---|---|---|---|
| T1 | Container escape / RCE via a scanner parser bug | Elevation of privilege | Partial |
| T2 | Code execution during dependency install | Elevation of privilege | Done |
| T3 | Decompression bomb | Denial of service | Done |
| T4 | Zip-slip / path traversal | Tampering | Done |
| T5 | SSRF via Git URL | Information disclosure | Done |
| T6 | Resource exhaustion | Denial of service | Partial |
| T7 | Secret leakage via findings | Information disclosure | Partial |
| T8 | Prompt injection into remediation LLM | Tampering | Partial |
| T9 | Stored XSS in the report UI and exports | Tampering / Elevation | Done |
| T10 | Malicious or compromised scanner image | Tampering | Open |
| T11 | Unauthorized API access | Spoofing | Partial |
| T12 | Worker's Docker access abused | Elevation of privilege | Partial |
| T13 | Poisoned or unavailable exploit-data feeds | Tampering | Partial |

## Detail

### T1 Container escape / RCE (Partial)
A crafted repo exploits a bug in Bandit, Semgrep, Trivy, OSV-Scanner or Gitleaks.
- **Done:** every scanner runs with `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`,
  non-root UID 10001, `--memory=2g --cpus=1.0 --pids-limit=256`, a `noexec` 64 MB tmpfs, and the target mounted
  read-only (`core/runner.py`, [ADR-002](adr/0002-docker-isolation-strategy.md)). Docker's default seccomp
  profile applies. Integration tests run the real containers.
- **Open:** rootless Docker or gVisor. The default runtime shares the host kernel, so a kernel or runtime
  exploit is not contained. Required before hosting for strangers.

### T2 Code execution during dependency install (Done)
Dependencies are never installed. Trivy and OSV-Scanner read lockfiles offline; vulnerability databases are
baked into the images at build time.

### T3 Decompression bomb (Done)
Before extraction: maximum compressed size (100 MB), uncompressed size (500 MB), file count (20,000) and
compression ratio (100:1) (`core/ingest.py`). Git clones are size-watched and killed past the limit.

### T4 Zip-slip / path traversal (Done)
Every archive entry is resolved against the extraction root; escaping entries, absolute paths, dot-segments
and symlinks are rejected. Covered by unit tests.

### T5 SSRF via Git URL (Done)
Strict URL grammar, https only, host allowlist (github.com, gitlab.com, bitbucket.org), DNS resolved and every
address required to be public, the resolved IP pinned for the clone, no redirects, no submodules, hooks
disabled (`core/gitfetch.py`). The API never scans server-side paths: only Git URLs and uploads.

### T6 Resource exhaustion (Partial)
- **Done:** per-container memory, CPU, PID and wall-clock limits; upload size cap; scans stuck past 30 minutes
  are reaped; orphaned containers and scratch directories are cleaned every 5 minutes.
- **Open:** no disk quota on the scan workspace beyond the ingestion size limits, and **no limit on how many
  scans one caller may queue**. With a single shared token this is an availability risk to whoever holds it.

### T7 Secret leakage (Partial)
- **Done:** Gitleaks runs with `--redact`; snippets become `[secret redacted]` and the finding id is a hash of
  rule, path and line, never of the secret. Bandit's hard-coded-password messages are scrubbed. A cross-tool
  pass redacts snippets and quoted literals near a detected secret (correlation runs first so distinct
  defects are not merged). Raw scanner output is **not stored** when secrets were found. Exports (SARIF, HTML,
  PDF, JSON) are built from the already-redacted findings.
- **Open:** findings are **not encrypted at rest** (Postgres and the object store hold plaintext, minus the
  redactions above). Rely on disk or volume encryption for now.
- **Note:** redaction before any LLM call applies when the LLM features exist (see T8).

### T8 Prompt injection (Partial)
The remediation layer (Week 12, [docs/llm-remediation.md](llm-remediation.md), [ADR-010](adr/0010-llm-remediation-design.md))
is built but **off by default and not yet wired into scans or the UI**.
- **Done and tested:** instructions only in the system message; repository text in random-nonce fenced data
  blocks with the task reminder after them; strict schema validation of the reply (extra keys, dismissal
  language, control/bidi characters and patches outside the finding's file are rejected whole); the model has
  no way to change severity, triage or taxonomy and the `Finding` object is never modified; any failure degrades
  to static CWE/cheat-sheet text; secrets findings send no code, other code is scrubbed first; the retrieval
  query never uses the code snippet; injection-like text in a repository is reported to the user. Tested with 20
  hostile payloads across four placements and with simulated hijacked models (135 tests).
- **Open:** no real model has been run against these defences, so real-world resistance is **unmeasured** (Week
  14). A well-formed reply can still be a wrong or misleading fix; patches are labelled and never applied. The
  secret scrubber is pattern-based and can miss unusual formats. The dismissal filter is phrase-based.
- **Privacy:** enabling the feature sends finding text and about 40 lines of code to the configured provider.

### T9 Stored XSS (Done)
Scanner-derived text is rendered as React text nodes, never HTML; the UI runs under a per-request-nonce
Content-Security-Policy with no inline styles or scripts; links are only built from validated ids and https
URLs. The HTML export escapes every value and carries its own CSP that forbids scripts and network access;
the API serves downloads with `nosniff` and a sandbox CSP; PDF text is escaped before layout. Regression tests
inject hostile titles, paths, snippets and descriptions into each of them (`web/tests/xss.test.tsx`,
`tests/unit/test_export.py`).

### T10 Malicious scanner image (Open)
Images are pinned by **tag**, not SHA-256 digest (`bulwark/*:1.7.10` etc., `zricethezav/gitleaks:v8.21.0`), and
the compose file uses `:latest` for the object store and the Docker socket proxy. Signatures are not verified.
A compromised upstream tag would be pulled and run (still inside the sandbox flags). Fix: pin digests in
production, verify signatures where publishers provide them.

### T11 Unauthorized API access (Partial)
- **Done:** every endpoint except `/healthz` needs a bearer token; comparison is constant-time; the API refuses
  to start with a weak token (under 16 characters); CORS is an explicit allowlist; the WebSocket authenticates
  in its first message so the token is never in a URL.
- **Open:** one shared token, no users, roles, expiry, rotation or rate limiting, so it can be brute-forced
  online and cannot be revoked per person. Do not expose the API to the internet.

### T12 Worker's Docker access (Partial)
The worker starts scanner containers through `docker-socket-proxy`, which allows only container
create/start/kill, image inspect and volumes, not the raw socket. Residual risk (also in ADR-002): a
compromised worker can still ask for containers with arbitrary host bind mounts. Production should use a
dedicated runner on an isolated host, or rootless Docker or gVisor, with the worker holding no Docker access.

### T13 Poisoned or unavailable exploit-data feeds (Partial)
EPSS and CISA KEV are fetched from two fixed https URLs by the API/worker side only (scanners still have no
network). Downloads are size-capped, structurally validated with minimum-size sanity floors, and replace the
cache atomically; a bad file leaves the previous one in place; a missing feed degrades scores to "unknown"
rather than failing scans. **Open:** the files are trusted on TLS alone; there is no signature to verify. A
compromised feed could distort ranking, not execute code.

## Out of scope
DAST ([ADR-003](adr/0003-no-dast-in-v1.md)); the security of the upstream scanners themselves; multi-tenant
isolation between users (there are no users yet); physical and cloud-account security of wherever it runs.

## Before a public deployment
1. Resolve the Semgrep rules licence ([ADR-006](adr/0006-semgrep-rules-licensing.md)).
2. Run scanners under gVisor or rootless Docker on a host that holds nothing else (T1, T12).
3. Per-user authentication, rate limiting and a scan queue cap (T6, T11).
4. Pin image digests (T10); encrypt storage at rest (T7).
