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
| OSV-Scanner (custom image, offline DBs) | `docker/osv-scanner/Dockerfile` on osv-scanner:v2.6.0 | yes | verified 2026-09-24 (built and run) |
| RustFS (object store) | rustfs/rustfs | yes | verified 2026-09-24 (ADR-007) |
| docker-socket-proxy | tecnativa/docker-socket-proxy | yes | verified 2026-09-24 (ran on arm64) |
| Bandit | built locally from `python:3.12-slim` (`docker/bandit/Dockerfile`) | yes | base image is multi-arch |

No Tier-1 tool needs the Rosetta fallback. Tier-2 (Grype, Checkov, gosec, Dockle) shipped in Week 22 and, checked
the same way as above, is also arm64-native: `anchore/grype:v0.119.0`, `bridgecrew/checkov:3.3.19` and
`goodwithtech/dockle:v0.4.15` all publish an arm64 manifest; gosec is built locally from `golang:1.25-alpine`
(`docker/gosec/Dockerfile`), itself multi-arch. Digest pinning happens when images are finalised for production.
