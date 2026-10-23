#!/usr/bin/env bash
# Regenerate docker/app/requirements.txt, the hash-pinned dependency set the app image installs.
#
# Run it after changing pyproject.toml's dependencies (tests/unit/test_app_lock.py fails until you
# do) and from time to time to take updates; pip-audit checks the pinned set in CI. Needs uv.
set -euo pipefail
cd "$(dirname "$0")/.."
uv pip compile pyproject.toml docker/app/requirements.in \
  --extra llm --extra otel \
  --universal --python-version 3.12 \
  --generate-hashes --quiet \
  --custom-compile-command "scripts/lock-app-deps.sh" \
  -o docker/app/requirements.txt
