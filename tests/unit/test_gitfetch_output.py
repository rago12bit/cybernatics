"""git's output cannot stall a clone (core.gitfetch._run_git).

It was read through a pipe that nothing drained while the watchdog loop waited: past a pipe's worth
of output (64 KB) git blocked on its next write, and a clone that had failed with a reason was
reported, a deadline later, as "timed out"."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from core.gitfetch import _run_git
from core.ingest import IngestError, Limits

NOISY = (
    "import sys\n"
    "for i in range(4000):\n"
    "    sys.stderr.write('warning: could not check out path/number/%d\\n' % i)\n"
    "    sys.stdout.write('progress %d\\n' % i)\n"
    "sys.stderr.write('fatal: repository not found\\n')\n"
    "sys.exit(128)\n"
)


def test_a_failure_with_a_lot_of_output_is_reported_at_once_with_its_reason(
    tmp_path: Path,
) -> None:
    started = time.monotonic()
    with pytest.raises(IngestError) as exc:
        _run_git([sys.executable, "-c", NOISY], {}, tmp_path / "dest", started + 20, Limits())
    assert time.monotonic() - started < 10  # not the deadline
    assert "timed out" not in str(exc.value)
    assert "Couldn't find this repository" in str(exc.value)  # the end of what git said


def test_a_quiet_success_and_a_real_timeout_still_behave(tmp_path: Path) -> None:
    dest, limits = tmp_path / "d", Limits()
    _run_git([sys.executable, "-c", "print('ok')"], {}, dest, time.monotonic() + 20, limits)
    with pytest.raises(IngestError, match="timed out"):
        _run_git(
            [sys.executable, "-c", "import time; time.sleep(30)"], {}, dest,
            time.monotonic() + 0.5, limits,
        )  # fmt: skip
