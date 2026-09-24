from pathlib import Path

from core.adapters.bandit import BanditAdapter
from core.runner import build_docker_argv


def test_sandbox_flags_present() -> None:
    argv = build_docker_argv(BanditAdapter(), Path("."), Path("."), "c1")
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--user=10001:10001",
        "--security-opt=no-new-privileges",
        "--memory=2g",
        "--cpus=1.0",
        "--pids-limit=256",
    ):
        assert flag in argv
    assert any(a.endswith(":/target:ro") for a in argv)
    assert "--privileged" not in argv


def test_writable_volume_only_where_a_tool_declares_it() -> None:
    from core.adapters.trivy import TrivyAdapter

    trivy = build_docker_argv(TrivyAdapter(), Path("."), Path("."), "c1")
    assert trivy[trivy.index("/db") - 1] == "-v"
    bandit = build_docker_argv(BanditAdapter(), Path("."), Path("."), "c1")
    assert "/db" not in bandit
    assert "--read-only" in trivy  # rootfs stays read-only even for Trivy
