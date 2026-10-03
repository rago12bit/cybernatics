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
    """The parser image, rebuilt from the repo root (cached layers make an unchanged build instant),
    so a stale local image can neither fake a pass nor hide a missing COPY line in the Dockerfile.
    """
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


GOLDEN_INGEST = ROOT / "tests" / "golden" / "ingest"


@pytest.mark.parametrize(
    "name,filename,parser",
    [
        ("cyclonedx json", "cyclonedx-vulnerabilities.json", "cyclonedx"),
        ("cyclonedx xml", "cyclonedx-vulnerabilities.xml", "cyclonedx"),
    ],
)
def test_real_cyclonedx_files_give_the_same_findings_in_the_sandbox(
    tmp_path: Path, name: str, filename: str, parser: str
) -> None:
    raw = (GOLDEN_INGEST / filename).read_bytes()
    report = tmp_path / filename
    report.write_bytes(raw)
    sandboxed = parse_in_sandbox(report, parser)
    in_process = run_parser_on_bytes(get_parser(parser), raw)
    assert sandboxed.complete, (name, sandboxed.error)
    assert len(sandboxed.findings) == 19
    assert [f.to_dict() for f in sandboxed.findings] == [f.to_dict() for f in in_process.findings]
    assert sandboxed.can_close_missing is True


def test_an_inventory_file_still_cannot_close_anything_after_crossing_the_container(
    tmp_path: Path,
) -> None:
    """The flag that stops an SBOM from closing Issues is set inside the container; it must survive
    the trip back, and a container that does not say must not be trusted to allow closing."""
    for filename, parser in (("spdx.json", "spdx"), ("cyclonedx-sbom.json", "cyclonedx")):
        report = tmp_path / filename
        report.write_bytes((GOLDEN_INGEST / filename).read_bytes())
        result = parse_in_sandbox(report, parser)
        assert result.complete and result.findings == []
        assert result.can_close_missing is False, filename


def test_xml_entity_attacks_are_refused_inside_the_container(tmp_path: Path) -> None:
    evil = tmp_path / "evil.xml"
    evil.write_text(
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component type="library">'
        "<name>&xxe;</name><version>1</version></component></components></bom>"
    )
    result = parse_in_sandbox(evil, "cyclonedx")
    assert not result.complete and (
        "DTD" in (result.error or "") or "entity" in (result.error or "")
    )
    assert result.findings == []
    assert "root:" not in str([result.error, result.warnings])


def test_osv_scanner_output_is_parsed_in_the_sandbox_like_in_process(tmp_path: Path) -> None:
    raw = (ROOT / "tests" / "golden" / "osv-scanner" / "raw.json").read_bytes()
    report = tmp_path / "osv.json"
    report.write_bytes(raw)
    sandboxed = parse_in_sandbox(report, "osv")
    in_process = run_parser_on_bytes(get_parser("osv"), raw)
    assert sandboxed.complete and len(sandboxed.findings) == 17
    assert [f.to_dict() for f in sandboxed.findings] == [f.to_dict() for f in in_process.findings]


def _ported_samples() -> list[tuple[str, Path]]:
    """For each ported parser, its smallest and its largest vendored real sample (two containers
    per parser keeps this fast; tests/unit/test_ingest_defectdojo.py runs every file in-process)."""
    out: list[tuple[str, Path]] = []
    base = ROOT / "tests" / "golden" / "ingest" / "defectdojo"
    for d in sorted(p for p in base.iterdir() if p.is_dir()):
        files = sorted(
            (f for f in d.iterdir() if f.name != "MANIFEST.json" and f.stat().st_size > 0),
            key=lambda f: f.stat().st_size,
        )
        out += [(d.name, f) for f in {files[0], files[-1]}]
    return sorted(out, key=lambda t: (t[0], t[1].name))


@pytest.mark.parametrize("parser,sample", _ported_samples(), ids=lambda v: getattr(v, "name", v))
def test_a_ported_parser_gives_the_same_findings_in_the_sandbox_as_in_process(
    parser: str, sample: Path, tmp_path: Path
) -> None:
    report = tmp_path / sample.name
    report.write_bytes(sample.read_bytes())
    in_process = run_parser_on_bytes(get_parser(parser), sample.read_bytes())
    sandboxed = parse_in_sandbox(report, parser)
    assert sandboxed.error == in_process.error
    assert [f.to_dict() for f in sandboxed.findings] == [f.to_dict() for f in in_process.findings]
    if sample.stat().st_size > 5_000:  # the smallest sample may legitimately be a clean report
        assert sandboxed.findings, f"{sample.name} should have findings"


def test_zap_xml_with_an_external_entity_is_refused_inside_the_container(tmp_path: Path) -> None:
    report = tmp_path / "xxe.xml"
    report.write_bytes(
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<OWASPZAPReport><site name='http://t'><alerts><alertitem><pluginid>1</pluginid>"
        b"<alert>&x;</alert><riskcode>1</riskcode></alertitem></alerts></site></OWASPZAPReport>"
    )
    result = parse_in_sandbox(report, "zap")
    assert not result.complete and result.findings == []
    assert "root:" not in (result.error or "")
