"""Uploaded reports parsed inside the real scanner sandbox (Week 54 task 5, plan §42.2): the same
file gives the same findings in a container as in-process, hostile files are refused rather than
trusted, and a container that fails never reads as "the report was empty"."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.adapters.base import RepoContext
from core.imports.parsers import ParseLimits, get_parser, run_parser_on_bytes
from core.imports.parsers.sandbox import IngestParseAdapter, parse_in_sandbox
from core.sandbox.docker_runtime import build_docker_argv

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "golden" / "semgrep" / "raw.json"
IMAGE = IngestParseAdapter.spec.image


def _docker_ready() -> bool:
    return bool(shutil.which("docker")) and (
        subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    )


pytestmark = pytest.mark.skipif(not _docker_ready(), reason="docker not available")


@pytest.fixture(scope="module", autouse=True)
def image() -> None:
    """The parser image, built from the repo root if this machine does not have it (CI builds it
    in an explicit step; this makes the test self-sufficient anywhere else)."""
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        subprocess.run(
            ["docker", "build", "-q", "-f", "docker/ingest-parser/Dockerfile", "-t", IMAGE, "."],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )


def test_a_report_gives_the_same_findings_in_the_sandbox_as_in_process(tmp_path: Path) -> None:
    report = tmp_path / "semgrep.sarif"
    report.write_bytes(GOLDEN.read_bytes())
    in_process = run_parser_on_bytes(get_parser("sarif"), GOLDEN.read_bytes())
    sandboxed = parse_in_sandbox(report, "sarif")

    assert sandboxed.complete and sandboxed.error is None
    assert [f.to_dict() for f in sandboxed.findings] == [f.to_dict() for f in in_process.findings]
    assert len(sandboxed.findings) == 4


def test_the_container_runs_with_the_scanner_hardening_flags() -> None:
    """Asserted on the argv the shared runner builds, so loosening the sandbox for parsers would
    have to loosen it for every scanner too (there is only one place that builds it)."""
    argv = build_docker_argv(
        IngestParseAdapter("sarif", ParseLimits()),
        Path("/tmp/x"),
        Path("/tmp/y"),
        "c",
        RepoContext(Path(".")),
    )
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in argv
    assert "--user=10001:10001" in argv
    assert any(a.startswith("--memory=") for a in argv)
    assert any(a.endswith(":/target:ro") for a in argv)  # the upload is mounted read-only


def test_a_hostile_file_is_refused_inside_the_container(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.json"
    bomb.write_bytes(b'{"runs": ' + b"[" * 500 + b"]" * 500 + b"}")
    result = parse_in_sandbox(bomb, "sarif")
    assert not result.complete and "deeper than" in (result.error or "")
    assert result.findings == []


def test_the_size_limit_reaches_the_container(tmp_path: Path) -> None:
    report = tmp_path / "r.sarif"
    report.write_bytes(GOLDEN.read_bytes())
    result = parse_in_sandbox(report, "sarif", ParseLimits(max_bytes=500))
    assert not result.complete and "byte limit" in (result.error or "")


def test_a_truncated_report_is_an_error_not_an_empty_one(tmp_path: Path) -> None:
    raw = GOLDEN.read_bytes()
    report = tmp_path / "cut.sarif"
    report.write_bytes(raw[: len(raw) // 2])
    result = parse_in_sandbox(report, "sarif")
    assert not result.complete and "valid JSON" in (result.error or "")


def test_an_unknown_parser_is_an_error(tmp_path: Path) -> None:
    report = tmp_path / "r"
    report.write_bytes(b"{}")
    result = parse_in_sandbox(report, "no-such-parser")
    assert not result.complete and "unknown parser" in (result.error or "")


def test_a_container_that_cannot_start_is_an_error_not_an_empty_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the sandbox itself fails, the answer must be "could not parse" -- an empty successful
    parse would close every Issue the file used to list."""
    from dataclasses import replace

    report = tmp_path / "r.sarif"
    report.write_bytes(GOLDEN.read_bytes())
    monkeypatch.setattr(
        IngestParseAdapter,
        "spec",
        replace(IngestParseAdapter.spec, image="bulwark/does-not-exist:0"),
    )
    result = parse_in_sandbox(report, "sarif")
    assert not result.complete and "did not finish" in (result.error or "")
    assert result.findings == []
