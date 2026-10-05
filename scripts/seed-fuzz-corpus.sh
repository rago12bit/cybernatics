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

# Uploaded-report parsers (Week 54 task 6): seeded from real Syft/Grype/Semgrep/OSV-Scanner files.
seed() { # <parser> <file>...
  corpus="tests/fuzz_corpus/ingest-$1"; mkdir -p "$corpus"; shift
  for f in "$@"; do cp "$f" "$corpus/seed-$(basename "$f")"; done
}
seed sarif tests/golden/semgrep/raw.json tests/golden/opengrep/raw.json
seed cyclonedx tests/golden/ingest/cyclonedx-*.json tests/golden/ingest/cyclonedx-*.xml
seed spdx tests/golden/ingest/spdx.json
seed osv tests/golden/osv-scanner/raw.json
# Ported parsers: one vendored DefectDojo directory per parser, named for it.
for d in tests/golden/ingest/defectdojo/*/; do
  files=(); for f in "$d"*; do [[ "$(basename "$f")" == MANIFEST.json ]] || files+=("$f"); done
  seed "$(basename "$d")" "${files[@]}"
done
# The universal mapper's fixed fuzz mappings and the sample analysis (Week 59, tests/fuzz/mappings.py).
seed universal-json tests/fuzz/seeds/universal.json
seed universal-csv tests/fuzz/seeds/universal.csv
seed universal-xml tests/fuzz/seeds/universal.xml
seed analyze tests/fuzz/seeds/universal.json tests/fuzz/seeds/universal.csv tests/fuzz/seeds/universal.xml
echo "Seeded tests/fuzz_corpus/<adapter>/ and tests/fuzz_corpus/ingest-<parser>/ from real files."
