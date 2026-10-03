#!/usr/bin/env bash
# Runs the uploaded-report parser fuzzers (tests/fuzz/fuzz_ingest_parser.py) in a Linux container,
# because Atheris needs a Clang+libFuzzer build and cannot install on macOS. Builds the fuzzing image
# once (Clang + Atheris from source: there is no prebuilt aarch64 wheel), seeds a throwaway corpus
# from the real files in tests/golden, and fuzzes each parser for SECONDS (default 60).
#
#   scripts/fuzz-ingest-docker.sh                # all four parsers
#   scripts/fuzz-ingest-docker.sh cyclonedx 300  # one parser, five minutes
#
# Corpus and any crash-<hash> file land in $WORK (default /tmp/bulwark-fuzz), never in the repo; copy
# a crash into tests/fuzz_regressions/ingest-<parser>/ once it is fixed.
set -euo pipefail
cd "$(dirname "$0")/.."
PARSERS="${1:-sarif cyclonedx spdx osv}"
SECONDS_PER="${2:-60}"
WORK="${WORK:-/tmp/bulwark-fuzz}"
IMAGE=bulwark-fuzz-local

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -t "$IMAGE" - <<'DOCKERFILE'
FROM python:3.12
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libclang-rt-dev >/dev/null \
    && pip install -q atheris ijson google-re2 defusedxml
DOCKERFILE
fi

rm -rf "$WORK"; mkdir -p "$WORK"
seed() { mkdir -p "$WORK/corpus-$1"; shift_p=$1; shift; for f in "$@"; do cp "$f" "$WORK/corpus-$shift_p/seed-$(basename "$f")"; done; }
seed sarif tests/golden/semgrep/raw.json tests/golden/opengrep/raw.json
seed cyclonedx tests/golden/ingest/cyclonedx-*.json tests/golden/ingest/cyclonedx-*.xml
seed spdx tests/golden/ingest/spdx.json
seed osv tests/golden/osv-scanner/raw.json
chmod -R 777 "$WORK"

status=0
for p in $PARSERS; do
  echo "=== fuzzing $p for ${SECONDS_PER}s"
  docker run --rm -v "$PWD":/repo:ro -v "$WORK":/work -e PYTHONPATH=/repo -e PYTHONDONTWRITEBYTECODE=1 \
    "$IMAGE" python /repo/tests/fuzz/fuzz_ingest_parser.py "$p" "/work/corpus-$p" \
    -max_total_time="$SECONDS_PER" -timeout=10 -rss_limit_mb=2048 2>&1 | tail -6 || status=1
done
ls "$WORK"/corpus-*/crash-* 2>/dev/null && { echo "CRASHES FOUND"; status=1; } || echo "no crash files"
exit $status
