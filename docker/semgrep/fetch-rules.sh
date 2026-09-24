#!/usr/bin/env bash
# Fetch Semgrep community rules into ./rules at build time. NEVER commit or redistribute them:
# Semgrep Rules License v1.0 allows internal business use only (see ADR-006).
set -euo pipefail
cd "$(dirname "$0")"
REV=a84ff9cc2453ca91d581380de4b8b3f272f6f4be
rm -rf rules .rules-src
git clone -q https://github.com/semgrep/semgrep-rules .rules-src
git -C .rules-src checkout -q "$REV"
mkdir rules
for d in python javascript typescript go java; do cp -R ".rules-src/$d" "rules/$d"; done
cp .rules-src/LICENSE rules/LICENSE
rm -rf .rules-src
