#!/usr/bin/env bash
# Build the scanner images Bulwark runs in sandboxed containers. Tags must match core/adapters/*.py
# (tests/unit/test_action.py checks that they do).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker_dir="$here/../docker"  # action/ sits next to docker/ in the repository

build() { docker build --quiet --tag "$1" "$docker_dir/$2" >/dev/null && echo "built $1"; }

build bulwark/bandit:1.7.10 bandit
build bulwark/semgrep:1.90.0 semgrep
build bulwark/trivy:0.55.2 trivy
build bulwark/osv-scanner:2.6.0 osv-scanner
build bulwark/syft:1.52.0 syft
docker pull --quiet zricethezav/gitleaks:v8.21.0 >/dev/null && echo "pulled gitleaks"
