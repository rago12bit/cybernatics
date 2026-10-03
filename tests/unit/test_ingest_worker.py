"""The sandbox's container entrypoint and how its output is read (Week 57 hardening).

Found by pushing 95 MB reports through the real sandbox: the worker built a list of findings, then
a list of dicts, then one string, and a 1 GiB container ran out of memory at about 250,000 findings
-- after which the importer said "try again", which cannot help. The output is now written as it is
produced, and a container killed part-way is reported as what it is.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.imports.parsers import sandbox, worker
from core.imports.parsers.base import ParseLimits
from core.runner import RunResult

DD = Path("tests/golden/ingest/defectdojo")


def run_worker(tmp_path: Path, parser: str, data: bytes, *extra: str) -> tuple[str, dict]:
    src, out = tmp_path / "in", tmp_path / "out.json"
    src.write_bytes(data)
    assert worker.main(["--parser", parser, "--input", str(src), "--output", str(out), *extra]) == 0
    text = out.read_text()
    return text, json.loads(text)


def test_findings_are_written_first_and_the_verdict_last(tmp_path: Path) -> None:
    text, doc = run_worker(tmp_path, "zap", (DD / "zap/0_zap_sample.xml").read_bytes())
    assert text.startswith('{"findings":[') and len(doc["findings"]) == 12
    assert text.rindex('"error"') > text.rindex('"title"')  # the verdict follows every finding
    assert doc["error"] is None and doc["can_close_missing"] is True and doc["parser"] == "zap"


def test_the_container_output_decodes_to_the_same_findings_as_in_process(tmp_path: Path) -> None:
    from core.imports.parsers import get_parser, run_parser_on_bytes

    raw = (DD / "nessus/nessus_many_vuln.xml").read_bytes()
    text, _ = run_worker(tmp_path, "nessus", raw)
    decoded = sandbox._decode(text.encode(), "nessus")
    direct = run_parser_on_bytes(get_parser("nessus"), raw)
    assert [f.to_dict() for f in decoded.findings] == [f.to_dict() for f in direct.findings]
    assert decoded.warnings == direct.warnings and decoded.complete


def test_a_file_that_was_not_read_in_full_returns_no_findings(tmp_path: Path) -> None:
    raw = (DD / "zap/0_zap_sample.xml").read_bytes()
    text, doc = run_worker(tmp_path, "zap", raw[: len(raw) // 2])
    assert doc["error"] and "valid XML" in doc["error"]
    decoded = sandbox._decode(text.encode(), "zap")
    assert not decoded.complete and decoded.findings == []  # partial findings are never built


def test_a_limit_hit_part_way_is_an_error(tmp_path: Path) -> None:
    raw = (DD / "zap/0_zap_sample.xml").read_bytes()
    _, doc = run_worker(tmp_path, "zap", raw, "--max-bytes", "2000")
    assert doc["error"] and "byte limit" in doc["error"]


def test_an_unknown_parser_is_an_error_not_an_empty_report(tmp_path: Path) -> None:
    _, doc = run_worker(tmp_path, "no-such-parser", b"{}")
    assert doc["findings"] == [] and "unknown parser" in doc["error"]


def test_a_container_that_does_not_say_it_may_close_is_not_trusted() -> None:
    decoded = sandbox._decode(b'{"findings":[],"parser":"zap","error":null,"warnings":[]}', "zap")
    assert decoded.complete and decoded.can_close_missing is False


@pytest.mark.parametrize(
    "status,code,expected",
    [
        ("timeout", None, "did not finish within 300s"),
        ("ok", 137, "memory limit"),  # killed while writing: output exists, exit is SIGKILL
        ("error", 1, "try again"),
    ],
)
def test_a_failed_container_is_reported_as_what_happened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, code: int | None, expected: str
) -> None:
    f = tmp_path / "r"
    f.write_bytes(b"{}")
    monkeypatch.setattr(
        sandbox, "run_tool", lambda *a, **k: RunResult("ingest-parser", status, code, b'{"fin', "")
    )
    r = sandbox.parse_in_sandbox(f, "sarif", ParseLimits())
    assert not r.complete and r.findings == [] and expected in (r.error or "")
