# Platform support (Apple Silicon)

Host: Apple Silicon (arm64). Several scanner images are amd64-only, so every tool is
checked before we commit to it (design doc §11.3).

Check: `docker manifest inspect <image> | grep architecture`

Fallback order: arm64-native alternative -> `--platform linux/amd64` under Rosetta (2-4x slower)
-> small amd64 cloud VM for CI/benchmarks.

| Tool | Candidate image | arm64? | Status |
|------|-----------------|--------|--------|
| Semgrep CE | returntocorp/semgrep:1.90.0 | ? | TODO: Docker daemon was down on 2026-09-24 |
| Trivy | aquasec/trivy | ? | TODO |
| Gitleaks | zricethezav/gitleaks | ? | TODO |
| OSV-Scanner | ghcr.io/google/osv-scanner | ? | TODO |
| Bandit | (build our own python:3.12-slim + pip bandit image) | n/a | TODO |

Tier-2 (Grype, Checkov, KICS, gosec, Hadolint, Dockle) to be checked before Week 22.
