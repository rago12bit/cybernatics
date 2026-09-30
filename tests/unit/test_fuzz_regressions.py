"""Replays every stored fuzz-crash input through its adapter's parse() (Week 48 task 1, plan §22.3):
"every crash becomes a regression test." Files land in tests/fuzz_regressions/<adapter-name>/ by
hand, copied there from whatever libFuzzer/Atheris wrote as `crash-<hash>` during a real run (see
tests/fuzz/fuzz_adapter.py) -- this file's only job is to keep replaying them forever after, so a
fix for one crash can never silently regress.

This directory is currently empty for an honest reason, not an oversight: Atheris cannot run on this
project's macOS dev machine at all (see tests/fuzz/fuzz_adapter.py's module docstring), and a manual
boundary-case probe of all nine adapters during this task (empty input, truncated JSON, non-UTF8
bytes, wrong-shaped JSON, deeply nested arrays, ...) found no crash -- every adapter already handles
malformed input by logging a warning and returning no findings, not by raising. That is a genuinely
good sign, not proof nothing is there: real coverage-guided fuzzing explores inputs no hand-picked
boundary case would think to try, which is the entire reason this task exists. See
docs/v2-week48-verification.md for the honest, full record.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.scan import ADAPTERS

REGRESSIONS_DIR = Path(__file__).parent.parent / "fuzz_regressions"


def _regression_cases() -> list[tuple[str, Path]]:
    if not REGRESSIONS_DIR.is_dir():
        return []
    return [
        (adapter_dir.name, crash_file)
        for adapter_dir in sorted(REGRESSIONS_DIR.iterdir())
        if adapter_dir.is_dir() and adapter_dir.name in ADAPTERS
        for crash_file in sorted(adapter_dir.iterdir())
        if crash_file.is_file()
    ]


@pytest.mark.parametrize(
    "adapter_name,crash_file",
    _regression_cases(),
    ids=lambda v: str(v) if isinstance(v, Path) else v,
)
def test_a_previously_crashing_input_no_longer_crashes(adapter_name: str, crash_file: Path) -> None:
    ADAPTERS[adapter_name].parse(crash_file.read_bytes())  # must not raise
