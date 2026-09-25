# Security policy

Bulwark scans code you do not trust, so its own security matters. Thank you for reporting problems.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(*Security* tab, *Report a vulnerability*) once the repository is public. Until then, email
ragh.gupta22@gmail.com. Include what you found, how to reproduce it, and the version or commit.

You can expect an acknowledgement within 5 working days. This is a pre-alpha, single-maintainer project,
so fixes are best effort, but every credible report gets a written answer.

## Supported versions

Only the latest release and `main` (pre-alpha, `0.1.x`). There are no backports yet.

## What Bulwark defends against

The full threat model, with the status of every threat, is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
The main controls that exist today:

| Threat | Control |
|---|---|
| A scanned repo attacks the scanner (code execution, escape) | One container per scanner: no network, read-only filesystem, all capabilities dropped, non-root, memory/CPU/PID limits, target mounted read-only, dependencies never installed ([ADR-002](docs/adr/0002-docker-isolation-strategy.md)) |
| Malicious archives (zip-slip, symlinks, bombs) | Size, file-count and depth limits; symlink and path-traversal rejection |
| Git URL abuse (SSRF, local file access) | https only, host allowlist, public-IP check with IP pinning, no redirects, submodules or hooks |
| Secrets echoed by a scanner into reports | Gitleaks `--redact`, cross-tool redaction, raw output withheld when secrets are found |
| Malicious scanner output rendered in the UI | All scanner data is rendered as text, never HTML; per-request-nonce CSP (`web/tests/xss.test.tsx`) |
| Unauthenticated API use | Bearer token required on every endpoint but `/healthz`; the API refuses to start without a strong token |

## Known limits (please read before deploying)

- **One shared bearer token.** There are no users, roles or rate limiting. Do not expose the API to the
  internet or to people you do not trust.
- **Docker socket proxy.** The worker reaches Docker through `docker-socket-proxy`. That is much narrower
  than the raw socket, but a compromised worker could still start containers with host bind mounts.
  Production needs a dedicated runner host, rootless Docker or gVisor
  ([ADR-002 amendment](docs/adr/0002-docker-isolation-strategy.md)).
- **Semgrep rules licence.** Do not offer a hosted service built on the bundled Semgrep rules
  ([ADR-006](docs/adr/0006-semgrep-rules-licensing.md)).
- **Findings are not verdicts.** Scanners produce false positives and miss things. Bulwark measures
  duplicate reduction, not accuracy.

## Scope

In scope: this repository's code, its Docker images and compose file, and the web UI. Out of scope:
vulnerabilities in the upstream scanners (report those to their projects), and findings about the
deliberately vulnerable repositories used in benchmarks and tests.
