"""Saved mappings and sample analysis inside the real parser sandbox (Week 59, plan §42.4, ADR-0043):
a mapped report gives the same findings in the container as in-process, describing a sample does
too, and the XML protections hold for a mapped file exactly as for a built-in parser."""

from __future__ import annotations

import io
import json
from pathlib import Path

from core.imports.parsers.analyze import analyze
from core.imports.parsers.base import ParseLimits, run_parser
from core.imports.parsers.sandbox import analyze_in_sandbox, parse_in_sandbox
from core.imports.parsers.universal import MappingSpec, UniversalParser
from tests.integration.test_ingest_sandbox_docker import image, pytestmark  # noqa: F401

SPEC = {
    "format": "json",
    "source": "acme",
    "records": "$.issues[*]",
    "fields": {"title": "$.name", "severity": "$.risk", "path": "$.at.file", "line": "$.at.line",
               "rule": "$.id", "cwe": "$.cwe"},  # fmt: skip
    "severity_map": {"p1": "CRITICAL"},
}
DOC = {
    "issues": [
        {"name": f"Issue {i}", "risk": "P1" if i % 3 == 0 else "low", "id": f"AC-{i % 7}",
         "at": {"file": f"src/m{i}.py", "line": i + 1}, "cwe": "CWE-89"}
        for i in range(200)
    ]
}  # fmt: skip


def test_a_mapped_report_parses_the_same_in_the_sandbox(tmp_path: Path) -> None:
    data = json.dumps(DOC).encode()
    report = tmp_path / "acme.json"
    report.write_bytes(data)
    sandboxed = parse_in_sandbox(report, "universal:test", mapping=SPEC)
    direct = run_parser(UniversalParser(MappingSpec.from_dict(SPEC), "universal:test"),
                        io.BytesIO(data))  # fmt: skip
    assert sandboxed.complete, sandboxed.error
    assert len(sandboxed.findings) == 200
    assert [f.to_dict() for f in sandboxed.findings] == [f.to_dict() for f in direct.findings]


def test_a_sample_is_described_the_same_in_the_sandbox(tmp_path: Path) -> None:
    data = json.dumps(DOC).encode()
    sample = tmp_path / "sample.json"
    sample.write_bytes(data)
    limits = ParseLimits(max_bytes=2 * 1024 * 1024, max_seconds=20.0)
    assert analyze_in_sandbox(sample, limits) == analyze(io.BytesIO(data), limits)


def test_a_mapped_xml_report_with_an_entity_is_refused_in_the_sandbox(tmp_path: Path) -> None:
    report = tmp_path / "r.xml"
    report.write_bytes(
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
        b"<r><issue><name>&b;</name></issue></r>"
    )
    spec = {
        "format": "xml",
        "source": "acme-xml",
        "records": "r/issue",
        "fields": {"title": "name"},
    }
    result = parse_in_sandbox(report, "universal:x", mapping=spec)
    assert not result.complete and result.findings == []
