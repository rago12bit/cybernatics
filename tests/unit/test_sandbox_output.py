"""A file a container wrote is read as that file and nothing else (core.sandbox.output).

The output directory is shared with the scanner's container. `path.read_bytes()` followed a link
planted there to any host file the worker can read, blocked for ever on a FIFO, and read a file of
any size into memory."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from core import runner
from core.adapters.bandit import BanditAdapter
from core.sandbox.output import OutputRefused, read_output


def test_a_regular_file_is_read_and_a_missing_one_is_nothing(tmp_path: Path) -> None:
    (tmp_path / "result.json").write_bytes(b'{"results": []}')
    assert read_output(tmp_path / "result.json") == b'{"results": []}'
    assert read_output(tmp_path / "absent.json") is None


def test_a_link_is_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "host-secret"
    secret.write_text("BULWARK_API_TOKEN=hunter2")
    (tmp_path / "result.json").symlink_to(secret)
    with pytest.raises(OutputRefused, match="symbolic link"):
        read_output(tmp_path / "result.json")
    (tmp_path / "dangling.json").symlink_to(tmp_path / "nowhere")
    with pytest.raises(OutputRefused, match="symbolic link"):
        read_output(tmp_path / "dangling.json")


def test_a_fifo_or_a_directory_is_refused_without_waiting(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "result.json")  # a blocking open would hang here: nobody writes to it
    with pytest.raises(OutputRefused, match="not a regular file"):
        read_output(tmp_path / "result.json")
    (tmp_path / "dir.json").mkdir()
    with pytest.raises(OutputRefused):
        read_output(tmp_path / "dir.json")


def test_a_file_over_the_limit_is_refused(tmp_path: Path) -> None:
    (tmp_path / "result.json").write_bytes(b"x" * 101)
    with pytest.raises(OutputRefused, match="larger than 100 bytes"):
        read_output(tmp_path / "result.json", 100)
    assert read_output(tmp_path / "result.json", 101) == b"x" * 101


def _run_tool_with(monkeypatch: pytest.MonkeyPatch, leave: Any) -> runner.RunResult:
    """`run_tool` with a stand-in for the container, which leaves something in the output dir."""

    def fake_run(argv: list[str], **_kw: Any) -> Any:
        out_dir = next(a.split(":")[0] for a in argv if a.endswith(f":{runner.CONTAINER_OUT}"))
        leave(Path(out_dir))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    return runner.run_tool(BanditAdapter(), Path("."))


def test_a_scanner_that_plants_a_link_as_its_output_has_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "worker.env"
    secret.write_text('{"BULWARK_SECRETS_KEY": "hunter2"}')
    result = _run_tool_with(monkeypatch, lambda out: (out / "result.json").symlink_to(secret))
    assert result.status == "error" and result.raw == b""
    assert "symbolic link" in result.stderr and "hunter2" not in result.stderr


def test_a_scanner_that_writes_its_report_is_read_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run_tool_with(monkeypatch, lambda out: (out / "result.json").write_bytes(b"{}"))
    assert result.status == "ok" and result.raw == b"{}"
