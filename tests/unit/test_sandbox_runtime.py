"""The SandboxRuntime interface and core.runner.run_tool's runtime injection (Week 46 task 1,
plan §22.1). test_runner.py already covers build_docker_argv's own flags in detail; this file
covers the new seam: that DockerRuntime produces the identical argv, and that run_tool defaults to
it but can be swapped."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.adapters.bandit import BanditAdapter
from core.runner import RunnerError, run_tool
from core.sandbox.docker_runtime import DockerRuntime, build_docker_argv


def test_docker_runtime_build_argv_matches_the_free_function() -> None:
    adapter = BanditAdapter()
    direct = build_docker_argv(adapter, Path("."), Path("."), "c1")
    via_runtime = DockerRuntime().build_argv(adapter, Path("."), Path("."), "c1")
    assert direct == via_runtime


def test_run_tool_defaults_to_docker_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_tool(BanditAdapter(), tmp_path)
    assert seen["argv"][:2] == ["docker", "run"]


def test_run_tool_accepts_an_injected_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeRuntime:
        name = "fake"

        def build_argv(
            self, adapter: Any, target: Path, out_dir: Path, name: str, ctx: Any = None
        ) -> list[str]:
            return ["echo", "fake-runtime-invoked"]

    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_tool(BanditAdapter(), tmp_path, runtime=FakeRuntime())
    assert seen["argv"] == ["echo", "fake-runtime-invoked"]


def test_run_tool_missing_binary_names_the_runtime_in_the_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeRuntime:
        name = "fake-runtime"

        def build_argv(
            self, adapter: Any, target: Path, out_dir: Path, name: str, ctx: Any = None
        ) -> list[str]:
            return ["fake-runtime-binary"]

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("no such binary")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RunnerError, match="fake-runtime"):
        run_tool(BanditAdapter(), tmp_path, runtime=FakeRuntime())
