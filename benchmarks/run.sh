#!/usr/bin/env bash
# Reproduce the published benchmark numbers. Needs Docker, the scanner images, and network for
# the git clones. Results are written to benchmarks/results/ as versioned JSON.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m benchmarks.dedup
