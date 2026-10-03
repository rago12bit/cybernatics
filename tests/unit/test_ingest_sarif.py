"""The SARIF import parser (Week 54 task 5, plan §42.2): real tool output against the native path,
Bulwark's own export as input, a CodeQL-shaped file with the awkward cases, and hostile input."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pytest

from core.adapters.semgrep import SemgrepAdapter
from core.export import ReportData
from core.export.sarif import to_sarif
from core.imports.parsers import (
    ParseLimits,
    detect,
    get_parser,
    run_parser,
    run_parser_on_bytes,
)
from core.imports.parsers.sarif import SarifParser
from tests.unit.test_reimport import file_of

GOLDEN = Path("tests/golden")
PARSER = SarifParser()


def parse(doc: bytes | dict[str, Any], **limits: Any):
    data = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    return run_parser_on_bytes(PARSER, data, ParseLimits(**limits) if limits else None)


# --- real third-party SARIF -----------------------------------------------------------------


def test_a_real_semgrep_sarif_imports_the_same_findings_the_native_path_reads() -> None:
    """The golden file is SARIF captured from a real Semgrep run. Imported as an upload it must
    mean exactly what it means when Bulwark ran Semgrep itself: both go through one mapper."""
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    native = SemgrepAdapter().parse(raw)
    imported = parse(raw)

    assert imported.complete and imported.error is None
    assert len(imported.findings) == len(native) == 4
    for n, i in zip(native, imported.findings, strict=True):
        assert (i.location.path, i.location.start_line) == (n.location.path, n.location.start_line)
        assert i.taxonomy.cwe == n.taxonomy.cwe
        assert i.scoring.normalized_severity == n.scoring.normalized_severity
        assert i.evidence.reported_by == ["semgrep-oss"]  # named for the driver in the file


def test_a_real_semgrep_sarif_is_recognised_with_high_confidence() -> None:
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    detected = detect(raw[:4096])
    assert detected and detected[0][0].name == "sarif" and detected[0][1] >= 0.9


# --- Bulwark's own export as input ----------------------------------------------------------


def test_bulwark_can_import_its_own_sarif_export() -> None:
    findings = [f.to_dict() for f in file_of(1, 2, 3)]
    report = ReportData(
        scan_id="s1", source_label="a/b", status="completed", finished_at=None, tool_status={},
        raw_findings=3, unique_findings=3, dedup_rate=0.0, severity_counts={"HIGH": 3},
        findings=findings,
    )  # fmt: skip
    result = parse(to_sarif(report))
    assert result.complete
    assert sorted(f.location.path for f in result.findings) == [f"app/mod{n}.py" for n in (1, 2, 3)]


# --- a CodeQL-shaped file: every awkward case in one ------------------------------------------

CODEQL_STYLE: dict[str, Any] = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            # results BEFORE the tool block that holds their rules: SARIF does not fix the order
            "results": [
                {
                    "ruleId": "py/sql-injection",
                    "level": "error",
                    "message": {"text": "This query depends on a user-provided value."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/db.py"},
                                "region": {"startLine": 42, "endLine": 43},
                            }
                        }
                    ],
                },
                {
                    "ruleIndex": 1,  # names its rule only by position
                    "message": {"text": "Use of a weak cryptographic hash."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/crypto.py"},
                                "region": {"startLine": 7},
                            }
                        }
                    ],
                },
                {  # a finding about a whole file: SARIF allows a missing region
                    "ruleId": "py/sql-injection",
                    "message": {"text": "Whole-file note."},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/x.py"}}}],
                },
                {"message": {"text": "no rule and no location at all"}},  # unusable: skipped
            ],
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [
                        {
                            "id": "py/sql-injection",
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-089"],  # lower case, padded
                                "security-severity": "9.8",
                            },
                            "helpUri": "https://codeql.github.com/",
                        },
                        {
                            "id": "py/weak-hash",
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {"tags": ["external/cwe/cwe-327"]},
                        },
                    ],
                }
            },
        }
    ],
}


def test_a_codeql_shaped_file_exercises_the_awkward_cases() -> None:
    result = parse(CODEQL_STYLE)
    assert result.complete
    by_path = {f.location.path: f for f in result.findings}
    assert set(by_path) == {"app/db.py", "app/crypto.py", "app/x.py"}

    sqli = by_path["app/db.py"]
    assert sqli.taxonomy.cwe == ("CWE-89",)  # "cwe-089" normalised
    assert (
        sqli.scoring.normalized_severity.value == "CRITICAL"
    )  # security-severity 9.8 beats "error"
    assert (sqli.location.start_line, sqli.location.end_line) == (42, 43)
    assert sqli.evidence.reported_by == ["codeql"]

    crypto = by_path["app/crypto.py"]  # found by ruleIndex, default level from the rule
    assert crypto.taxonomy.cwe == ("CWE-327",)
    assert crypto.scoring.normalized_severity.value == "MEDIUM"

    assert by_path["app/x.py"].location.start_line == 1  # region-less -> line 1, not dropped
    assert any("1 of 4 results" in w for w in result.warnings)  # the unusable one, said aloud


def test_two_runs_keep_their_own_rules_and_tool_names() -> None:
    def run(tool: str, rule: str, level: str) -> dict[str, Any]:
        return {
            "tool": {"driver": {"name": tool, "rules": [{"id": rule}]}},
            "results": [
                {
                    "ruleId": rule,
                    "level": level,
                    "message": {"text": "m"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": f"{tool}.py"}}}
                    ],
                }
            ],
        }

    result = parse(
        {"version": "2.1.0", "runs": [run("ToolA", "r1", "error"), run("ToolB", "r1", "note")]}
    )
    assert [f.evidence.reported_by for f in result.findings] == [["toola"], ["toolb"]]
    assert [f.scoring.normalized_severity.value for f in result.findings] == ["HIGH", "LOW"]


def test_an_empty_report_is_complete_and_has_no_findings() -> None:
    """A clean scan is a legitimate report (and, with close_missing on, a meaningful one)."""
    result = parse(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]}
    )
    assert result.complete and result.findings == []


# --- hostile and broken input: never raises, never passes a half-read file for a whole one ----


def test_a_truncated_file_is_an_error_not_a_smaller_report() -> None:
    """The dangerous case: reimport closes what a file no longer lists, so a file cut off halfway
    must be refused, not read as "most findings are fixed"."""
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    result = run_parser_on_bytes(PARSER, raw[: len(raw) // 2])
    assert not result.complete
    assert result.error and "valid JSON" in result.error


@pytest.mark.parametrize(
    "garbage",
    [b"", b"not json at all", b"\x00\xff\xfe", b"[]", b'{"runs": "nope"}', b'{"version": "2.1.0"}',
     b'{"runs": [{"results": 5}]}', b"{" * 10],
)  # fmt: skip
def test_garbage_never_raises_and_is_always_reported_as_incomplete_or_empty(garbage: bytes) -> None:
    result = run_parser_on_bytes(PARSER, garbage)  # must not raise
    assert result.findings == [] or result.complete
    if not result.complete:
        assert result.error


def test_json_nested_beyond_the_depth_limit_is_refused() -> None:
    bomb = b'{"runs": ' + b"[" * 200 + b"]" * 200 + b"}"
    result = run_parser_on_bytes(PARSER, bomb)
    assert not result.complete and "deeper than" in (result.error or "")


def test_a_file_over_the_size_limit_is_refused_while_reading() -> None:
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    result = run_parser(PARSER, io.BytesIO(raw), ParseLimits(max_bytes=500))
    assert not result.complete and "byte limit" in (result.error or "")


def test_too_many_findings_is_refused() -> None:
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    result = parse(raw, max_findings=2)
    assert not result.complete and "more than 2 findings" in (result.error or "")


def test_a_parse_that_runs_too_long_is_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    real = time.monotonic
    ticks = iter(range(10_000))
    monkeypatch.setattr(time, "monotonic", lambda: real() + next(ticks) * 1000.0)
    # The time check runs every few thousand events, so give it enough to reach one.
    big = json.loads(raw)
    big["runs"][0]["results"] = big["runs"][0]["results"] * 3000
    result = parse(json.dumps(big).encode(), max_seconds=5.0)
    assert not result.complete and "longer than" in (result.error or "")


def test_a_stream_that_cannot_seek_still_parses() -> None:
    class ReadOnly:
        def __init__(self, data: bytes) -> None:
            self._b = io.BytesIO(data)

        def read(self, n: int = -1) -> bytes:
            return self._b.read(n)

        def seekable(self) -> bool:
            return False

    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    result = run_parser(PARSER, ReadOnly(raw))  # type: ignore[arg-type]
    assert result.complete and len(result.findings) == 4


# --- detection --------------------------------------------------------------------------------


def test_sniff_recognises_sarif_and_nothing_else() -> None:
    assert PARSER.sniff(json.dumps(CODEQL_STYLE).encode()) >= 0.9
    assert PARSER.sniff(b'{"results": [{"source": {}, "packages": []}]}') == 0.0
    assert PARSER.sniff(b"<?xml version='1.0'?><bom/>") == 0.0
    assert PARSER.sniff(b"") == 0.0
    assert PARSER.sniff(b"\xef\xbb\xbf" + json.dumps(CODEQL_STYLE).encode()) >= 0.9  # BOM


def test_the_registry_finds_the_parser_by_name_and_refuses_unknown_names() -> None:
    assert get_parser("sarif") is PARSER or get_parser("sarif").name == "sarif"
    with pytest.raises(ValueError, match="unknown parser"):
        get_parser("nessus-but-not-yet")
