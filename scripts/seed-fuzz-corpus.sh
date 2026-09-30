#!/usr/bin/env bash
# Seeds each adapter's fuzz corpus directory with its golden raw.json (Week 48 task 1, plan §22.3):
# a real recorded tool output is a far better coverage-guided-fuzzing starting point than an empty
# corpus. Run once before `python tests/fuzz/fuzz_adapter.py <name> tests/fuzz_corpus/<name>`.
#
# "syft" is deliberately not seeded here: tests/golden has no fixture for it (its parse() consumes a
# CycloneDX SBOM document, a different shape than the other nine adapters' vulnerability-finding
# JSON), and this pass didn't build one -- a disclosed gap, not an oversight.
set -euo pipefail
cd "$(dirname "$0")/.."
for name in bandit semgrep gitleaks trivy osv-scanner grype checkov gosec dockle; do
  golden="tests/golden/$name/raw.json"
  if [[ ! -f "$golden" ]]; then
    echo "warning: no golden fixture for $name, skipping" >&2
    continue
  fi
  corpus="tests/fuzz_corpus/$name"
  mkdir -p "$corpus"
  cp "$golden" "$corpus/seed-golden.bin"
done
echo "Seeded tests/fuzz_corpus/<adapter>/ from each adapter's golden raw.json."
