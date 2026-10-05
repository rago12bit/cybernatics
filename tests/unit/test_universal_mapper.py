"""The universal mapper's parser (Week 59, plan §42.4, ADR-0043): a saved mapping is a deterministic
parser. The expected values here come from the test's own data (the records it wrote), never from
the code under test."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from core.imports.parsers import sandbox, worker
from core.imports.parsers.analyze import analyze
from core.imports.parsers.base import ParseLimits, run_parser
from core.imports.parsers.universal import (
    MappingError,
    MappingSpec,
    UniversalParser,
    parse_json_path,
    parse_xml_path,
)
from core.models import Category, Severity

JSON_SPEC = {
    "format": "json",
    "source": "acme",
    "records": "$.scan.results[*]",
    "fields": {
        "title": "$.name",
        "severity": "$.risk",
        "path": "$.where.file",
        "line": "$.where.line",
        "rule": '$["check id"]',
        "cwe": "$.cwe",
        "references": "$.links[*]",
        "recommendation": "$.fix",
    },
    "severity_map": {"p1": "CRITICAL"},
}


def records() -> list[dict[str, Any]]:
    return [
        {"name": "SQL injection", "risk": "P1", "where": {"file": "app/db.py", "line": 42},
         "check id": "ACME-1", "cwe": "CWE-89: Improper Neutralization", "fix": "Bind parameters.",
         "links": ["https://acme.test/1", "javascript:alert(1)"]},
        {"name": "Weak hash", "risk": "Low", "where": {"file": "a.py", "line": "7"},
         "check id": "ACME-2", "cwe": "327"},
        {"name": "", "risk": "High"},
        {"name": "Odd severity", "risk": "purple", "where": {"file": "b.py"}},
    ]  # fmt: skip


def parse(spec: dict[str, Any], data: bytes) -> Any:
    return run_parser(UniversalParser(MappingSpec.from_dict(spec), "universal:t"), io.BytesIO(data))


def test_a_json_mapping_reads_every_mapped_field() -> None:
    doc = {"scan": {"tool": "acme", "results": records()}}
    r = parse(JSON_SPEC, json.dumps(doc).encode())
    assert r.complete
    by_title = {f.title: f for f in r.findings}
    assert sorted(by_title) == ["Odd severity", "SQL injection", "Weak hash"]
    sqli = by_title["SQL injection"]
    assert sqli.scoring.normalized_severity is Severity.CRITICAL  # from the mapping's own word
    assert sqli.scoring.native_severity == {"acme": "P1"}
    assert (sqli.location.path, sqli.location.start_line) == ("app/db.py", 42)
    assert sqli.taxonomy.cwe == ("CWE-89",) and sqli.taxonomy.category is Category.SAST
    assert sqli.evidence.reported_by == ["acme"] and sqli.evidence.rule_ids == {"acme": ["ACME-1"]}
    assert sqli.remediation.summary == "Bind parameters."
    assert sqli.remediation.references == ["https://acme.test/1"]  # never a javascript: link
    weak = by_title["Weak hash"]
    assert weak.scoring.normalized_severity is Severity.LOW and weak.location.start_line == 7
    assert weak.taxonomy.cwe == ("CWE-327",)
    odd = by_title["Odd severity"]
    assert odd.scoring.normalized_severity is Severity.INFO  # unknown: Info, never a guess
    assert any("no title" in w for w in r.warnings)
    assert any("'purple'" in w and "Info" in w for w in r.warnings)


def test_the_same_mapping_and_file_always_give_the_same_findings() -> None:
    data = json.dumps({"scan": {"results": records()}}).encode()
    first = [f.to_dict() for f in parse(JSON_SPEC, data).findings]
    second = [f.to_dict() for f in parse(JSON_SPEC, data).findings]
    assert first == second and len(first) == 3


def test_a_csv_mapping_matches_columns_ignoring_case_and_spaces() -> None:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Finding Title", "Severity", "File", "Line", "CWE"])
    w.writerow(["XSS", "Medium", "web/a.js", "12", "CWE-79, CWE-80"])
    w.writerow(["", "", "", "", ""])
    w.writerow(["Open redirect", "9.1", "web/b.js", "", ""])
    spec = {"format": "csv", "source": "acme-csv",
            "fields": {"title": " finding title", "severity": "SEVERITY", "path": "file",
                       "line": "line", "cwe": "cwe"}}  # fmt: skip
    r = parse(spec, buf.getvalue().encode())
    assert r.complete
    assert [(f.title, f.scoring.normalized_severity, f.taxonomy.cwe) for f in r.findings] == [
        ("XSS", Severity.MEDIUM, ("CWE-79", "CWE-80")),
        ("Open redirect", Severity.CRITICAL, ()),  # a CVSS-like number is banded, 9.1 -> Critical
    ]


def test_a_csv_missing_a_mapped_column_is_refused_not_read_as_empty() -> None:
    spec = {"format": "csv", "source": "acme-csv", "fields": {"title": "Title", "path": "File"}}
    r = parse(spec, b"Title,Severity\nXSS,High\n")
    assert not r.complete and "File".lower() in (r.error or "")


def test_an_xml_mapping_reads_elements_and_attributes_ignoring_namespaces() -> None:
    xml = (
        b'<?xml version="1.0"?><r:report xmlns:r="urn:acme"><r:issues>'
        b'<r:issue sev="high"><r:name>Open redirect</r:name><r:at url="https://Example.com:443/go?x=1"/>'
        b"<r:refs><r:ref>https://a.test/1</r:ref><r:ref>https://a.test/2</r:ref></r:refs></r:issue>"
        b'<r:issue sev="low"><r:name>Banner</r:name><r:at url="https://example.com/"/></r:issue>'
        b"</r:issues></r:report>"
    )
    spec = {"format": "xml", "source": "acme-xml", "category": "dast", "records": "issues/issue",
            "fields": {"title": "name", "severity": "@sev", "url": "at/@url",
                       "references": "refs/ref"}}  # fmt: skip
    r = parse(spec, xml)
    assert r.complete
    first, second = r.findings
    assert (first.title, first.location.host, first.location.route) == (
        "Open redirect", "https://example.com", "/go")  # fmt: skip
    assert first.taxonomy.category is Category.DAST
    assert first.remediation.references == ["https://a.test/1", "https://a.test/2"]
    assert second.scoring.normalized_severity is Severity.LOW


def test_xml_entities_are_refused_in_a_mapped_report_too() -> None:
    xml = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "boom">]>'
           b"<r><issue><name>&x;</name></issue></r>")  # fmt: skip
    spec = {
        "format": "xml",
        "source": "acme-xml",
        "records": "r/issue",
        "fields": {"title": "name"},
    }
    r = parse(spec, xml)
    assert not r.complete and r.findings == []


def test_a_dependency_mapping_gives_package_identity() -> None:
    doc = [{"pkg": "lodash", "ver": "4.17.20", "eco": "npm", "id": "CVE-2021-23337",
            "sev": "high", "title": "Command injection"}]  # fmt: skip
    spec = {"format": "json", "source": "acme-sca", "category": "sca", "records": "$[*]",
            "fields": {"title": "$.title", "severity": "$.sev", "package": "$.pkg",
                       "version": "$.ver", "ecosystem": "$.eco", "cve": "$.id"}}  # fmt: skip
    (f,) = parse(spec, json.dumps(doc).encode()).findings
    assert f.package is not None
    assert (f.package.name, f.package.version, f.package.ecosystem) == ("lodash", "4.17.20", "npm")
    assert f.taxonomy.cve == ("CVE-2021-23337",) and f.title.startswith("CVE-2021-23337")


def test_a_truncated_file_is_an_error_so_it_can_never_close_anything() -> None:
    data = json.dumps({"scan": {"results": records()}}).encode()
    r = parse(JSON_SPEC, data[: len(data) // 2])
    assert not r.complete and "cut off" in (r.error or "")


def test_no_records_at_the_records_path_is_said_out_loud() -> None:
    r = parse(JSON_SPEC, b'{"scan": {"other": []}}')
    assert r.complete and r.findings == [] and any("no records" in w for w in r.warnings)


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({**JSON_SPEC, "format": "yaml"}, "format"),
        ({**JSON_SPEC, "source": "A B"}, "source name"),
        ({**JSON_SPEC, "records": "$.scan.results"}, "end in `[*]`"),
        ({**JSON_SPEC, "records": "$.scan.results[0][*]"}, "index"),
        ({**JSON_SPEC, "fields": {"severity": "$.risk"}}, "title"),
        ({**JSON_SPEC, "fields": {"title": "$..name"}}, "cannot read"),
        ({**JSON_SPEC, "fields": {"title": "$.a[?(@.x)]"}}, "cannot read"),
        ({**JSON_SPEC, "fields": {"title": "$.name", "nope": "$.x"}}, "unknown field"),
        ({**JSON_SPEC, "category": "sca"}, "package"),
        ({**JSON_SPEC, "category": "dast"}, "url"),
        ({**JSON_SPEC, "severity_map": {"x": "SEVERE"}}, "severity_map"),
        ({"format": "csv", "source": "acme", "records": "$[*]", "fields": {"title": "t"}}, "CSV"),
        (
            {"format": "xml", "source": "acme", "records": "a/@b", "fields": {"title": "t"}},
            "records",
        ),
        (
            {"format": "xml", "source": "acme", "records": "a", "fields": {"title": "a b"}},
            "element",
        ),
    ],
)
def test_a_mapping_that_cannot_run_is_refused_with_a_reason(spec: Any, message: str) -> None:
    with pytest.raises(MappingError, match=re.escape(message)):
        MappingSpec.from_dict(spec)


def test_the_json_path_language_is_small_and_exact() -> None:
    rec = {"a": {"b c": [{"d": 1}, {"d": 2}, {"e": 3}]}, "x": [[1, 2], [3]], "n": None}
    assert parse_json_path('$.a["b c"][*].d').values(rec) == [1, 2]
    assert parse_json_path('$.a["b c"][1].d').values(rec) == [2]
    assert parse_json_path("$.x[*][*]").values(rec) == [1, 2, 3]
    assert parse_json_path("$.a").values(rec) == []  # an object is not a value
    assert parse_json_path("$.n").values(rec) == [] and parse_json_path("$.zz").values(rec) == []
    assert parse_xml_path("a/b/@c").attribute == "c" and parse_xml_path(".").elements == ()


def test_sniff_recognises_the_files_a_mapping_was_written_for() -> None:
    p = UniversalParser(MappingSpec.from_dict(JSON_SPEC))
    assert p.sniff(json.dumps({"scan": {"results": records()}}).encode()) >= 0.9
    assert p.sniff(b'{"something": "else"}') < 0.5
    assert p.sniff(b"name,risk\n") == 0.0


# --- in the sandbox's entrypoint ----------------------------------------------------------------


def test_the_worker_parses_with_a_mapping_file_and_decodes_like_in_process(tmp_path: Path) -> None:
    data = json.dumps({"scan": {"results": records()}}).encode()
    (tmp_path / "in").write_bytes(data)
    (tmp_path / "mapping.json").write_text(json.dumps(JSON_SPEC))
    out = tmp_path / "out.json"
    code = worker.main(["--parser", "universal:abc", "--input", str(tmp_path / "in"),
                        "--output", str(out), "--mapping", str(tmp_path / "mapping.json")])  # fmt: skip
    assert code == 0
    decoded = sandbox._decode(out.read_bytes(), "universal:abc")
    direct = parse(JSON_SPEC, data)
    assert decoded.complete and decoded.parser == "universal:abc"
    assert [f.to_dict() for f in decoded.findings] == [f.to_dict() for f in direct.findings]


def test_the_worker_refuses_a_mapped_parse_without_its_mapping(tmp_path: Path) -> None:
    (tmp_path / "in").write_bytes(b"[]")
    out = tmp_path / "out.json"
    worker.main(
        ["--parser", "universal:abc", "--input", str(tmp_path / "in"), "--output", str(out)]
    )
    doc = json.loads(out.read_text())
    assert doc["findings"] == [] and "--mapping" in doc["error"]


def test_the_worker_analyzes_a_sample(tmp_path: Path) -> None:
    (tmp_path / "in").write_bytes(json.dumps({"scan": {"results": records()}}).encode())
    out = tmp_path / "out.json"
    worker.main(["--parser", "analyze", "--input", str(tmp_path / "in"), "--output", str(out),
                 "--analyze"])  # fmt: skip
    doc = json.loads(out.read_text())
    (top,) = [c for c in doc["candidates"] if c["records"] == "$.scan.results[*]"]
    paths = {f["path"] for f in top["fields"]}
    assert {"$.name", "$.risk", "$.where.file", '$["check id"]', "$.links[*]"} <= paths
    assert top["count"] == 4


def test_the_sandbox_adapter_ships_the_mapping_beside_the_report(tmp_path: Path) -> None:
    adapter = sandbox.IngestParseAdapter("universal:x", ParseLimits(), with_mapping=True)
    cmd = adapter.build_command(Path("/target"), Path("/out/r.json"))
    assert cmd[cmd.index("--mapping") + 1] == "/target/mapping.json"
    assert "--analyze" in sandbox.IngestParseAdapter(
        "a", ParseLimits(), analyze=True
    ).build_command(Path("/t"), Path("/o"))


# --- properties ---------------------------------------------------------------------------------

_text = st.text(st.characters(blacklist_categories=("Cs",)), max_size=40)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.fixed_dictionaries({"name": _text, "risk": _text, "file": _text}), max_size=25))
def test_every_record_with_a_title_becomes_exactly_one_finding(rows: list[dict[str, str]]) -> None:
    spec = {"format": "json", "source": "acme", "records": "$.items[*]",
            "fields": {"title": "$.name", "severity": "$.risk", "path": "$.file"}}  # fmt: skip
    r = parse(spec, json.dumps({"items": rows}).encode())
    assert r.complete
    expected = [" ".join(row["name"].split())[:300] for row in rows if row["name"].split()]
    assert [f.title for f in r.findings] == expected


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=2000))
def test_arbitrary_bytes_never_raise(data: bytes) -> None:
    for spec in (
        JSON_SPEC,
        {"format": "csv", "source": "acme", "fields": {"title": "t"}},
        {"format": "xml", "source": "acme", "records": "a/b", "fields": {"title": "c"}},
    ):
        r = parse(spec, data)
        assert r.error is not None or isinstance(r.findings, list)
    assert isinstance(analyze(io.BytesIO(data)), dict)
