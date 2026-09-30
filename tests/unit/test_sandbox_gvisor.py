"""GvisorRuntime's argv construction (Week 46 task 2, plan §22.1).

runsc itself can't run on this dev machine (Linux only -- see core.sandbox.gvisor_runtime's module
docstring), so this only covers argv shape, the same style test_runner.py already uses for
DockerRuntime -- it's what's actually testable without a Linux host."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.adapters.bandit import BanditAdapter
from core.sandbox.docker_runtime import build_docker_argv
from core.sandbox.gvisor_runtime import GvisorRuntime


def test_gvisor_runtime_inserts_the_runsc_runtime_flag_right_after_run() -> None:
    argv = GvisorRuntime().build_argv(BanditAdapter(), Path("."), Path("."), "c1")
    assert argv[0] == "docker"
    assert argv[1] == "run"
    assert argv[2] == "--runtime=runsc"


def test_gvisor_runtime_preserves_every_docker_flag_unchanged() -> None:
    """The gvisor backend must never loosen the container contract -- only add a deeper
    enforcement layer underneath it."""
    plain = build_docker_argv(BanditAdapter(), Path("."), Path("."), "c1")
    gvisor = GvisorRuntime().build_argv(BanditAdapter(), Path("."), Path("."), "c1")
    for flag in plain:
        assert flag in gvisor


def test_gvisor_runtime_name_is_gvisor() -> None:
    assert GvisorRuntime().name == "gvisor"


def test_gvisor_runtime_omits_seccomp_flag_when_no_profile_exists() -> None:
    argv = GvisorRuntime().build_argv(BanditAdapter(), Path("."), Path("."), "c1")
    assert not any(a.startswith("--security-opt=seccomp=") for a in argv)


def test_gvisor_runtime_adds_seccomp_flag_when_a_profile_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.sandbox.gvisor_runtime.seccomp_profile_path", lambda name: Path("/profiles/x.json")
    )
    argv = GvisorRuntime().build_argv(BanditAdapter(), Path("."), Path("."), "c1")
    assert "--security-opt=seccomp=/profiles/x.json" in argv
