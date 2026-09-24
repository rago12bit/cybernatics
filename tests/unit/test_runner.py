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
