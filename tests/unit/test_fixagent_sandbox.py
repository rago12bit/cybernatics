"""The test-execution sandbox's argv construction and pass/fail/timeout handling (plan §21.2,
Week 46 task 3 plan §22.1).

Mocks `subprocess.run`, not Docker itself -- the real container path (a real `python:3.12-slim`
image, a real sidecar-applied egress policy, a real passing AND a real failing pytest run, and the
`deny_internal_egress=False` legacy fallback) was validated live against Docker while building this
feature; see docs/v2-week46-verification.md. Unit tests here cover the logic around those calls:
argv shape, the detached+barrier+wait sequence, timeout handling, exit-code interpretation.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.fixagent.egress import EgressPolicyError
from core.fixagent.sandbox import (
    SandboxError,
    TestRunSpec,
    _argv,
    _argv_with_egress_barrier,
    run_tests,
)


def _name_from_start_argv(argv: list[str]) -> str:
    return argv[argv.index("--name") + 1]


def test_argv_mounts_the_checkout_and_runs_the_command_via_sh(tmp_path: Path) -> None:
    spec = TestRunSpec(image="python:3.12-slim", command="pytest -q")
    argv = _argv(spec, tmp_path, "container-1")
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert f"{tmp_path.resolve()}:/work" in argv
    assert argv[-4:] == ["python:3.12-slim", "sh", "-c", "pytest -q"]
    assert "--network=none" not in argv  # deliberately network-enabled, unlike the scanner sandbox
    assert "--read-only" not in argv  # deliberately writable, unlike the scanner sandbox


def test_egress_barrier_argv_is_detached_without_rm_and_waits_before_running_the_command(
    tmp_path: Path,
) -> None:
    spec = TestRunSpec(image="python:3.12-slim", command="pytest -q")
    argv = _argv_with_egress_barrier(spec, tmp_path, "container-1", tmp_path)
    assert argv[0:3] == ["docker", "run", "-d"]  # detached
    assert "--rm" not in argv  # caller reads `docker logs` after exit; --rm would race it
    assert f"{tmp_path.resolve()}:/bulwark-egress:ro" in argv
    command = argv[-1]
    assert "while [ ! -e /bulwark-egress/ready ]" in command
    assert command.endswith("pytest -q")


# ---- deny_internal_egress=True (default): detached + barrier + sidecar + wait ----


def test_run_tests_applies_egress_policy_by_default_then_reports_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        if argv[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"cid\n", stderr=b"")
        if argv[:2] == ["docker", "wait"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"0\n", stderr=b"")
        if argv[:2] == ["docker", "logs"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"1 passed", stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    def fake_apply(container_name: str, **kw: Any) -> None:
        calls.append(["APPLY_EGRESS", container_name])

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("core.fixagent.sandbox.apply_egress_policy", fake_apply)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))
    assert step.passed and step.name == "run_tests"

    kinds = [c[0] if c[0] != "docker" else c[1] for c in calls]
    assert kinds == [
        "run",
        "APPLY_EGRESS",
        "wait",
        "logs",
        "rm",
    ]  # start, apply, wait, logs, cleanup


def test_run_tests_reports_failure_with_the_real_container_log_tail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"cid\n", stderr=b"")
        if argv[:2] == ["docker", "wait"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"1\n", stderr=b"")
        if argv[:2] == ["docker", "logs"]:
            return subprocess.CompletedProcess(
                argv, 0, stdout=b"1 failed: AssertionError", stderr=b""
            )
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("core.fixagent.sandbox.apply_egress_policy", lambda name, **kw: None)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))
    assert not step.passed and "exit code 1" in step.detail and "AssertionError" in step.detail


def test_run_tests_kills_and_reraises_when_the_egress_policy_fails_to_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    killed: list[str] = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"cid\n", stderr=b"")
        if argv[:2] == ["docker", "kill"]:
            killed.append(argv[2])
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    def fake_apply(container_name: str, **kw: Any) -> None:
        raise EgressPolicyError("sidecar exited 1")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("core.fixagent.sandbox.apply_egress_policy", fake_apply)
    with pytest.raises(SandboxError, match="failed to apply egress policy"):
        run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))
    assert (
        len(killed) == 1
    )  # the never-released target must be killed, not left running unprotected


def test_run_tests_reports_a_timeout_and_kills_the_container_after_egress_is_applied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    killed: list[str] = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(argv, 0, stdout=b"cid\n", stderr=b"")
        if argv[:2] == ["docker", "kill"]:
            killed.append(argv[2])
            return subprocess.CompletedProcess(argv, 0)
        if argv[:2] == ["docker", "wait"]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("core.fixagent.sandbox.apply_egress_policy", lambda name, **kw: None)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest", timeout_s=5))
    assert not step.passed and "timed out after 5s" in step.detail
    assert len(killed) == 1


def test_run_tests_raises_sandbox_error_when_docker_is_missing_on_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("no docker")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SandboxError):
        run_tests(tmp_path, TestRunSpec(image="x", command="pytest"))


# ---- deny_internal_egress=False: the original, fully-open-network fallback ----


def test_legacy_fallback_run_tests_reports_pass_on_exit_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, stdout=b"1 passed", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest", deny_internal_egress=False))
    assert step.passed and step.name == "run_tests"


def test_legacy_fallback_run_tests_reports_failure_with_the_real_output_tail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, stdout=b"1 failed: AssertionError", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    step = run_tests(tmp_path, TestRunSpec(image="x", command="pytest", deny_internal_egress=False))
    assert not step.passed and "AssertionError" in step.detail


def test_legacy_fallback_run_tests_reports_a_timeout_and_kills_the_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    killed = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[:2] == ["docker", "kill"]:
            killed.append(argv[2])
            return subprocess.CompletedProcess(argv, 0)
        raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))

    monkeypatch.setattr(subprocess, "run", fake_run)
    step = run_tests(
        tmp_path,
        TestRunSpec(image="x", command="pytest", timeout_s=5, deny_internal_egress=False),
    )
    assert not step.passed and "timed out after 5s" in step.detail
    assert len(killed) == 1


def test_legacy_fallback_run_tests_raises_sandbox_error_when_docker_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("no docker")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SandboxError):
        run_tests(tmp_path, TestRunSpec(image="x", command="pytest", deny_internal_egress=False))
