"""The test-execution sandbox's argv construction and pass/fail/timeout handling (plan §21.2).

Mocks `subprocess.run`, not Docker itself -- the real container path (a real `python:3.12-slim`
image, real `pip install`, a real passing AND a real failing pytest run) was validated live against
Docker while building this feature; see docs/v2-week42-verification.md. Unit tests here cover the
logic around that call: argv shape, timeout handling, exit-code interpretation.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.fixagent.sandbox import SandboxError, TestRunSpec, _argv, run_tests


def test_argv_mounts_the_checkout_and_runs_the_command_via_sh(tmp_path: Path) -> None:
    spec = TestRunSpec(image="python:3.12-slim", command="pytest -q")
    argv = _argv(spec, tmp_path, "container-1")
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert f"{tmp_path.resolve()}:/work" in argv
    assert argv[-4:] == ["python:3.12-slim", "sh", "-c", "pytest -q"]
    assert "--network=none" not in argv  # deliberately network-enabled, unlike the scanner sandbox
    assert "--read-only" not in argv  # deliberately writable, unlike the scanner sandbox


def test_run_tests_reports_pass_on_exit_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, stdout=b"1 passed", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))
    assert step.passed and step.name == "run_tests"


def test_run_tests_reports_failure_with_the_real_output_tail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, stdout=b"1 failed: AssertionError", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))
    assert not step.passed and "AssertionError" in step.detail


def test_run_tests_reports_a_timeout_and_kills_the_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    killed = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[:2] == ["docker", "kill"]:
            killed.append(argv[2])
            return subprocess.CompletedProcess(argv, 0)
        raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))

    monkeypatch.setattr(subprocess, "run", fake_run)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest", timeout_s=5))
    assert not step.passed and "timed out after 5s" in step.detail
    assert len(killed) == 1


def test_run_tests_raises_sandbox_error_when_docker_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("no docker")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SandboxError):
        run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))
