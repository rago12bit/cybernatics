# Platform support (Apple Silicon)

Host: Apple Silicon (arm64). Several scanner images are amd64-only, so every tool is
checked before we commit to it (design doc §11.3).

Check: `docker manifest inspect <image> | grep architecture`

Fallback order: arm64-native alternative -> `--platform linux/amd64` under Rosetta (2-4x slower)
-> small amd64 cloud VM for CI/benchmarks.

| Tool | Candidate image | arm64? | Status |
|------|-----------------|--------|--------|
| Semgrep CE | returntocorp/semgrep:1.90.0 | yes | verified 2026-09-24 |
| Trivy | aquasec/trivy | yes | verified 2026-09-24 |
| Gitleaks | zricethezav/gitleaks | yes | verified 2026-09-24 |
| OSV-Scanner | ghcr.io/google/osv-scanner | yes | verified 2026-09-24 |
| Trivy (custom image, DB baked in) | `docker/trivy/Dockerfile` on aquasec/trivy:0.55.2 | yes | verified 2026-09-24 (built and run) |
| OSV-Scanner (custom image, offline DBs) | `docker/osv-scanner/Dockerfile` on osv-scanner:v1.9.2 | yes | verified 2026-09-24 (built and run) |
| RustFS (object store) | rustfs/rustfs | yes | verified 2026-09-24 (ADR-007) |
| docker-socket-proxy | tecnativa/docker-socket-proxy | yes | verified 2026-09-24 (ran on arm64) |
| Bandit | built locally from `python:3.12-slim` (`docker/bandit/Dockerfile`) | yes | base image is multi-arch |

No Tier-1 tool needs the Rosetta fallback. Tier-2 (Grype, Checkov, KICS, gosec, Hadolint, Dockle)
to be checked before Week 22. Digest pinning happens when images are finalised for production.
