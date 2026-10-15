# Threat model

Bulwark downloads or accepts untrusted code and runs third-party tools over it, then renders what those
tools say. That is an attack surface. This document lists what we defend against, what actually exists in
the code today, and what does not. Status is stated per threat so it can be checked, not assumed.

Status key: **Done** (implemented and tested), **Partial** (some of the mitigation exists), **Open** (not
implemented), **N/A yet** (the feature that creates the threat is not built).

Last reviewed: 2026-10-07 (Week 75: sign-in, sessions and access, T11 and T18). Review again before any deployment that accepts scans from people you
do not trust.

## Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| The host running the worker and Docker | The worst outcome is code from a scanned repo running on it |
| Source code and secrets inside scanned repos | Users upload private code; findings can echo secrets |
| The API tokens and sign-in sessions | Tokens act as their organization or person; a session is a signed-in person (T11, T18) |
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
| T10 | Malicious or compromised scanner image | Tampering | Partial |
| T11 | Unauthorized API access | Spoofing | Partial |
| T12 | Worker's Docker access abused | Elevation of privilege | Partial |
| T13 | Poisoned or unavailable exploit-data feeds | Tampering | Partial |
| T15 | Forged or tampered scan results, reports or SBOM in transit | Tampering / Repudiation | Partial |
| T14 | Parser bug or resource exhaustion while analysing scanned source for reachability | Denial of service / Elevation | Partial |
| T16 | A wrong VEX claim tells customers they are not affected | Repudiation / Information integrity | Partial |
| T17 | An evidence pack discloses another organization's activity, or is forged | Information disclosure / Tampering | Partial |
| T18 | Sign-in, sessions and access | Spoofing / Elevation of privilege | Partial |
| T19 | Untrusted text steering an agent through MCP; `/fix` run by the wrong person or on a fork | Tampering / Elevation of privilege | Partial |

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
is **off by default** and, once enabled, runs only when a user clicks "Generate AI suggestion" on a finding
(`POST /scans/{id}/suggestion`); reading guidance never contacts a model. Model calls are capped per minute and
per day, and results are cached by rule and snippet.
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
- **Privacy:** enabling the feature sends finding text and the scanner's code snippet to the configured provider
  (the CLI can add +/-20 lines). Cache entries are shared across scans on a server.
- **Cost abuse:** the per-process spend limit bounds a shared-token holder's spend but resets on restart and is
  not per user (there are no users yet).

### T9 Stored XSS (Done)
Scanner-derived text is rendered as React text nodes, never HTML; the UI runs under a per-request-nonce
Content-Security-Policy with no inline styles or scripts; links are only built from validated ids and https
URLs. One exception, contained: the threat-model diagram is drawn by Mermaid, whose SVG needs inline styles,
in a same-origin frame (`/diagram-frame`) whose policy allows inline styles but scripts only from this origin
(Mermaid's build and the frame's own script), with no network access, framable only by the app. It takes
the diagram source by `postMessage` from its parent only, and Mermaid sanitizes its own output
(`securityLevel: "strict"`). The HTML export escapes every value and carries its own CSP that forbids scripts and network access;
the API serves downloads with `nosniff` and a sandbox CSP; PDF text is escaped before layout. Regression tests
inject hostile titles, paths, snippets and descriptions into each of them (`web/tests/xss.test.tsx`,
`tests/unit/test_export.py`).

### T10 Malicious scanner image (Partial)
- **Done (2026-10-14):** the images Bulwark builds itself (`bulwark/*`: every scanner but gitleaks, the
  import parser, Nuclei, the egress sidecar) are run with `--pull=never` (`core.sandbox.docker_runtime.
  pull_policy`) and built, never pulled, by compose (`pull_policy: build`). Before, an image not built
  locally was fetched as `docker.io/bulwark/<tool>`, a Docker Hub namespace Bulwark does not own (no public
  repository there on 2026-10-14): whoever registered it would have had their image run as a scanner, and
  `docker compose pull` would have fetched it over a local build. A missing image is now "No such image",
  reported as that tool's error. Gitleaks, the one scanner run from its author's image, is pinned by digest,
  as cosign and the PDF renderer already were; a test requires every built-in image to be built here or
  pinned by digest. A plugin's image runs by the digest its publisher's signature covers (the signed
  payload's `docker-manifest-digest`, `core.plugins.signing.pinned_reference`), so a tag moved between the
  signature check and the run cannot swap it.
- **Done (2026-10-14):** every other image is pinned by digest too: the 22 `FROM` lines the `bulwark/*`
  and web images are built from, the 9 images compose pulls (the two `:latest` ones as the versions they
  pointed to, `rustfs/rustfs:1.0.1` and `tecnativa/docker-socket-proxy:v0.5.0`), ZAP (`2.17.0`, which
  `stable` pointed to) and CI's Postgres. A rebuild or a pull gets exactly the image pinned; tests fail
  on any image added by tag. Dependabot moves the digests weekly as pull requests (a rebuilt base image's
  security fixes included), majors and Redis 7.4+ (ADR-0011) excluded, so a pin does not quietly go stale.
- **Open:** signatures of upstream images are not verified: a digest proves the image is the one
  pinned, not who built it or that it is safe. Docker Official Images and cosign-signed upstreams could be checked with
  `cosign verify` at build time, as plugin images are at run time.

### T11 Unauthorized API access (Partial)
- **Done:** every endpoint except `/healthz` needs a bearer token; comparison is constant-time; the API refuses
  to start with a weak token (under 16 characters); CORS is an explicit allowlist; the WebSocket authenticates
  in its first message so the token is never in a URL.
- **Done since (Weeks 29 and 75):** scoped, expiring, revocable tokens per organization (ADR-0018); user
  accounts that sign in through the organization's identity provider, with roles per organization,
  business unit and project, and tokens that act as their person and die with them (T18, ADR-0058).
- **Open:** the shared `BULWARK_API_TOKEN` still exists for the operator and has every scope; there is no
  rate limiting, so a token can be guessed at online (they are 160 random bits). Keep the shared token for
  automation you control, and do not expose the API to the internet without a reverse proxy that limits rates.

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

Since Week 68 (ADR-0052) the advisory engine also fetches OSV's per-ecosystem data, CISA KEV and NVD's
CVE API, on the worker, from three fixed HTTPS hosts only (any other URL is refused), certificates
verified against certifi's bundle. Sizes are capped (1 GiB per dump, 2 MiB per record), records are
parsed as data, a KEV file with fewer than 100 entries never replaces the catalog, and an
advisory's reference links are kept only if they are `http(s)` addresses; its text is shown as
text, never rendered. **Open:** as above, a compromised source could add or hide advisories (false
alarms or missed ones); it cannot run code. Fetching sends nothing about an organization: the
requests are plain GETs of public files, unlike osv-scanner's online mode, which posts package
lists to api.osv.dev.

### T14: reachability analysis parses untrusted source outside the sandbox

Unlike the scanners, `core/reachability` runs in the API/worker process. It never executes scanned code:
Python is parsed with the standard `ast` module and JavaScript/TypeScript with tree-sitter (native code).
Mitigations: symlinks are not followed and dependency/build directories are skipped, at most 20,000 files and
1 MB per file are read, parse errors (including `RecursionError`/`MemoryError`) mark the file unparsed instead of
failing the scan, and any failure of the whole analysis leaves findings without reachability rather than failing the
scan. **Residual:** a memory-safety bug in tree-sitter or CPython's parser triggered by a hostile file would run in
the worker, which is the one component with (proxied) Docker access. Moving the analysis into a sandboxed container
is the fix and is not done. Status: Partial.

### T15: scan results can be altered after the fact

`bulwark attest sign` and `bulwark attest provenance` sign a report, SARIF or SBOM with a cosign key pair and record
which Bulwark and which scanner images (by content hash) produced it, with the result counts. cosign runs in a
container with no network and a read-only root filesystem; the key is mounted read-only and its password is passed
by environment-variable name, never on a command line. **Residual:** signatures are key-based with no transparency
log, so they prove who held the key but not when the signature was made; a stolen key forges results; keyless
(OIDC) signing is not implemented; nothing yet stops an attacker with the key from attesting a scan they did not
run, and the attestation says nothing about whether the findings are correct. Status: Partial.

### T16: a wrong VEX claim (Week 69, ADR-0053)

A `not_affected` statement published to customers that is not true hides a real exposure from them.
**Done:** Bulwark only proposes; a person confirms each statement with a personal token (the shared
token is refused), and the confirmation, the evidence and its limits are in the statement and the
audit log. Evidence errs towards "used" (names matched loosely, an unknown import name means "can't
tell"); nothing is proposed for malicious packages, uncertain versions or unscanned projects. A
confirmed statement a later scan contradicts is exported as `under_investigation`, and reopening its
Issue withdraws it. **Residual:** the evidence does not see calls made inside other dependencies, by
reflection or through function values; a reviewer who confirms without reading can still publish a
wrong claim; the proposals' precision has not been measured. Status: Partial.

### T17: evidence packs (Week 69, ADR-0053)

A pack holds an organization's SLA history, risk acceptances, issue counts and audit-log extract.
**Done:** packs are stored under forced RLS and served only to their organization; the audit extract
shows other organizations' entries as hashes only, which still lets every link be recomputed
(version-2 entries put the organization inside the hash); payloads are never in the log, only their
digests. `verify.py` checks the files and the chain without Bulwark; the manifest is signed with
cosign when a key is configured, and a pack is never produced unsigned after signing failed.
Checkpoints can be verified against Rekor offline. **Residual:** the number and timing of other
organizations' audit entries are visible in an extract; entries from before migration 0041 can be
checked by link only; whoever holds the signing key can sign a fabricated pack (the chain and Rekor
checkpoints still have to agree); a pack is only as current as its last checkpoint. Status: Partial.

### T18: sign-in, sessions and access (Week 75, plan threat T30, ADR-0058)

**Done:** OIDC with PKCE and strict checks of the ID token: asymmetric signatures only (never `none` or
an HMAC "signed" with the public key), exact issuer, our audience (and `azp` when there are several),
expiry, and the nonce of this sign-in; one-time `state`; HTTPS to the provider. SAML only through
pysaml2 with xmlsec1, assertions required to be signed, no unsolicited responses, audience and
destination checked; tests forge an unsigned assertion, another key's signature, a tampered one, three
kinds of signature wrapping, a comment inside the NameID, another service's response, an expired one, a
replayed one and an unsolicited one, and each is refused for its own reason. A person is bound to the
provider's stable subject, so a second account with the same email cannot take theirs. Sessions are
HttpOnly, SameSite=Lax, Secure cookies holding a secret whose SHA-256 alone is stored, at most 12 hours
and 2 idle; every change made with one needs its CSRF token. SCIM deprovisioning (and turning someone
off by hand) ends their sessions and revokes their tokens in the same request. A person limited to some
projects runs as the `bulwark_guest` database role, whose restrictive RLS policies hide every other
project's rows in every table that names one; the two-project test proves it on Postgres. Evidence files
are served with `Content-Security-Policy: sandbox`, so a file that runs script cannot use the session.
**Residual:** Google, Entra ID and Okta are covered by standard OIDC but were exercised only through a
local Keycloak; the shared token and pre-account tokens are nobody in particular and keep their scopes;
a provider administrator can sign in as anyone the provider vouches for. Status: Partial.

### T19: agents and pull request comments (Week 76, plan threat T29, ADR-0059)

**MCP server.** `bulwark mcp` calls the API with the person's own token, so scopes, roles, project
limits and RLS apply unchanged; the shared token is refused; ids are checked before a request;
redirects are not followed and a remote API must be https. Read-only by default (`run_scan` needs
`--allow-scans` and a token that may write scans); no tool changes a status. Every value Bulwark
does not set itself is wrapped as `{"untrusted_text": ...}`, default-deny: a trusted key must also
hold a value that looks like one. Hidden and reordering characters are shown as `<U+XXXX>`; long
text is cut. Tested with a Hypothesis property (no unwrapped string escapes) and live: a planted
injection in a scanned file came back wrapped, with its bidi override shown as a code, to the SDK's
own stdio client. **Residual:** a label informs an agent, it cannot stop one from following the text;
the agent's own permissions are the real limit.

**`/fix`.** Only from a GitHub owner, member or collaborator (`author_association`) whose login an
admin linked to an active person with the Member role or higher on that project; never for a pull
request from a fork (its code must not run with the base repository's credentials, the
`pull_request_target` lesson); only a new comment's first line is a command, never an edit; a bot is
ignored; the organization comes from the App installation, and a comment never creates one. A
preview shows the findings and the token cap and spends nothing; the confirm repeats every check and
is refused when the pull request has new commits since the preview, the code has expired (24 h) or
been used, the monthly budget cannot cover the cap, or the organization is at its concurrency limit.
The agent stops at the cap (checked before each model call) and every token is charged to the
organization's budget. Results are posted as comments; Bulwark never pushes to the branch. Tested on
SQLite, on Postgres (RLS, a project-limited guest), and live with the real worker on Temporal.
**Residual:** not exercised with a real GitHub App or a real model; a scan of the head commit is
matched by the commit the webhook named, so a push in the seconds between the webhook and the clone
could make the scan describe a newer commit. Status: Partial.

### Observability endpoints

The worker's `/metrics` (port 9101) has no authentication and is not published to the host; only the compose network
reaches it. Grafana's default admin password (`admin`) and anonymous viewer access are for localhost use only (the
port is bound to 127.0.0.1); change the password and remove anonymous access before exposing it anywhere. Logs are
scrubbed of credentials by pattern, which is best effort, and traces carry tool names, statuses and counts but never
code or findings.

## Out of scope
DAST ([ADR-003](adr/0003-no-dast-in-v1.md)); the security of the upstream scanners themselves; multi-tenant
isolation is covered by RLS (ADR-0013) and, between projects, by T18; physical and cloud-account security of wherever it runs.

## Before a public deployment
1. Resolve the Semgrep rules licence ([ADR-006](adr/0006-semgrep-rules-licensing.md)).
2. Run scanners under gVisor or rootless Docker on a host that holds nothing else (T1, T12).
3. Per-user authentication, rate limiting and a scan queue cap (T6, T11).
4. Verify upstream image signatures (T10; digests are already pinned); encrypt storage at rest (T7).
