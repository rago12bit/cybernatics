"""Atheris fuzz harness for one scanner adapter's parse() (Week 48 task 1, plan §22.3).

Usage:
    python tests/fuzz/fuzz_adapter.py <adapter-name> <corpus-dir> [libFuzzer args...]

`corpus-dir` should be seeded first with `tests/golden/<adapter-name>/raw.json` (a real recorded
tool output is a far better starting corpus than an empty one) -- see
`scripts/seed-fuzz-corpus.sh`. `parse()` is called directly with no target-level try/except: an
adapter's own contract (`core/scan.py`'s `_execute_tool`, line ~178) calls `adapter.parse(run.raw)`
with nothing catching an exception from it, so any input that makes `parse()` raise is a genuine
finding here, not a false positive to filter out -- a malformed or malicious scanner output crashing
the whole scan job for that tool is exactly the robustness gap this harness exists to find.

Requires `atheris`, which needs a real Clang+libFuzzer build and does not install on macOS (Apple's
shipped Clang deliberately omits libFuzzer -- confirmed by trying, not assumed: `pip install
atheris` fails at build time with "Failed to find libFuzzer; you may be building using Apple
Clang"). It runs in CI (.github/workflows/fuzz.yml, Ubuntu, where atheris ships a prebuilt wheel)
or a Linux container, never on macOS -- see docs/v2-week48-verification.md for what has run.

Any crash atheris finds is written by libFuzzer as `crash-<hash>` inside `corpus-dir`. Copying that
file into `tests/fuzz_regressions/<adapter-name>/` makes `test_fuzz_regressions.py` replay it
through `parse()` forever after -- "every crash becomes a regression test" (plan §22.3) is this
manual-but-permanent step; nothing here commits a crash file automatically.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from core.scan import ADAPTERS


def _target(data: bytes) -> None:
    adapter_name = _target.adapter_name  # type: ignore[attr-defined]
    ADAPTERS[adapter_name].parse(data)


def main(argv: list[str]) -> None:
    if len(argv) < 3 or argv[1] not in ADAPTERS:
        print(f"usage: {argv[0]} <adapter-name> <corpus-dir> [libFuzzer args...]", file=sys.stderr)
        print(f"known adapters: {', '.join(sorted(ADAPTERS))}", file=sys.stderr)
        raise SystemExit(2)
    _target.adapter_name = argv[1]  # type: ignore[attr-defined]
    atheris.Setup([argv[0], *argv[2:]], _target)
    atheris.Fuzz()


if __name__ == "__main__":
    main(sys.argv)
