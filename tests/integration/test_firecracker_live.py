"""The fix agent's test run in a real Firecracker microVM (core.sandbox.firecracker), end to end:
image to root filesystem, checkout to a disk, boot, run, result. Skipped unless this host can run
one: Linux with /dev/kvm, `firecracker` on PATH, Docker, mkfs.ext4, and a guest kernel in
`BULWARK_FIRECRACKER_KERNEL` (Firecracker's own CI kernels work; docs/sandbox-runtimes.md says
where to get one). Never run on the macOS dev machine, which has no KVM."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.fixagent import sandbox
from core.sandbox import firecracker as fc


def _host_problem() -> str | None:
    try:
        fc.check_host(fc.FirecrackerConfig.from_env())
    except fc.FirecrackerError as exc:
        return str(exc)
    return None


pytestmark = pytest.mark.skipif(_host_problem() is not None, reason=f"{_host_problem()}")


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n")
    return tmp_path


def test_a_passing_and_a_failing_command_in_a_microvm(
    monkeypatch: pytest.MonkeyPatch, checkout: Path
) -> None:
    monkeypatch.setenv("BULWARK_TEST_SANDBOX", "firecracker")
    ok = sandbox.run_tests(checkout, sandbox.TestRunSpec(
        image="python:3.12-slim", memory="1g", cpus=1, timeout_s=180,
        command="python -c 'import os; assert \"test_ok.py\" in os.listdir(\".\")'",
    ))  # fmt: skip
    assert ok.passed, ok.detail
    bad = sandbox.run_tests(checkout, sandbox.TestRunSpec(
        image="python:3.12-slim", memory="1g", cpus=1, timeout_s=180,
        command="sleep 1000 & echo BULWARK-EXIT 0; exit 7",
    ))  # fmt: skip
    assert not bad.passed and bad.detail.startswith("exit code 7"), bad.detail


def test_the_guest_has_no_network(monkeypatch: pytest.MonkeyPatch, checkout: Path) -> None:
    monkeypatch.setenv("BULWARK_TEST_SANDBOX", "firecracker")
    step = sandbox.run_tests(checkout, sandbox.TestRunSpec(
        image="python:3.12-slim", memory="1g", cpus=1, timeout_s=180,
        command="python -c 'import socket; socket.create_connection((\"1.1.1.1\", 53), 3)'",
    ))  # fmt: skip
    assert not step.passed and "Network is unreachable" in step.detail, step.detail
