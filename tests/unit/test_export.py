from __future__ import annotations

import copy
import json
import re
from collections import Counter
from html import unescape
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

import cli.main as cli_main
from core.correlation import CorrelationStats
from core.export import FORMATS, ReportData, render, to_html, to_pdf, to_sarif
from core.export.pdf import MAX_FINDINGS
from core.models import finding_from_dict
from core.scan import ScanResult

ROOT = Path(__file__).resolve().parents[2]
DEMO = json.loads((ROOT / "web/lib/demo-data.json").read_text())
SCHEMA = json.loads((ROOT / "tests/fixtures/sarif-schema-2.1.0.json").read_text())
HOSTILE = "<img src=x onerror=alert(1)></para><b>&amp;</b>‮中文\x00\x07 \"'"


def report(findings: list[dict[str, Any]] | None = None) -> ReportData:
    fs = copy.deepcopy(findings if findings is not None else DEMO["findings"])
    counts = Counter(f["scoring"]["normalized_severity"] for f in fs)
    return ReportData(
        scan_id="11111111-2222-3333-4444-555555555555", source_label="demo", status="completed",
        finished_at="2026-09-25T00:00:35Z",
        tool_status={"bandit": {"status": "ok", "findings": 3}, "trivy": {"status": "error", "findings": 0, "error": "boom"}},
        raw_findings=len(fs) + 5, unique_findings=len(fs), dedup_rate=0.1, severity_counts=dict(counts), findings=fs,
    )  # fmt: skip


def hostile_findings() -> list[dict[str, Any]]:
    fs = copy.deepcopy(DEMO["findings"][:3])
    f = fs[0]
    f["title"] = f["description"] = f["remediation"]["summary"] = f["location"]["snippet"] = HOSTILE
    f["location"]["path"] = f"a/{HOSTILE}.py"
    f["scoring"]["risk_factors"] = [HOSTILE]
    f["taxonomy"]["cwe"] = [HOSTILE]
    return fs


# ---- SARIF -------------------------------------------------------------------------------------


def test_sarif_validates_against_the_official_2_1_0_schema() -> None:
    doc = to_sarif(report())
    jsonschema.validate(doc, SCHEMA)  # raises with the exact path if anything is off
    assert doc["version"] == "2.1.0" and len(doc["runs"][0]["results"]) == len(DEMO["findings"])


def test_sarif_is_shaped_for_github_code_scanning() -> None:
    run = to_sarif(report())["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids and res["level"] in {"error", "warning", "note"}
        assert res["partialFingerprints"]["bulwarkFingerprint/v1"]
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1 and region["endLine"] >= region["startLine"]
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/") and ".." not in uri.split("/")
    for r in run["tool"]["driver"]["rules"]:
        assert 0 <= float(r["properties"]["security-severity"]) <= 10
    scores = [x["properties"]["risk_score"] for x in run["results"]]
    assert scores == sorted(
        scores, key=lambda v: -(v if v is not None else -1)
    )  # ranked like the UI


def test_sarif_never_contains_a_secret_and_survives_hostile_text() -> None:
    doc = to_sarif(report(hostile_findings()))
    jsonschema.validate(doc, SCHEMA)
    text = json.dumps(doc)
    assert "secret redacted" in text or "gitleaks" not in text  # snippets arrive already redacted
    assert json.loads(text)  # round-trips


def test_sarif_empty_scan_is_valid() -> None:
    jsonschema.validate(to_sarif(report([])), SCHEMA)


# ---- HTML --------------------------------------------------------------------------------------


def test_html_escapes_everything_and_forbids_scripts() -> None:
    html = to_html(report(hostile_findings()))
    assert "<img src=x" not in html and "onerror=alert(1)>" not in html.replace(
        "&lt;img src=x onerror=alert(1)&gt;", ""
    )
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert not re.search(r"<script|javascript:|<iframe|<link|<object", html, re.I)
    meta = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html)
    assert (
        meta
        and "default-src 'none'" in unescape(meta.group(1))
        and "script-src" not in meta.group(1)
    )
    assert (
        html.count("<style>") == 1 and "http://" not in html and "https://" not in html
    )  # no external requests


def test_html_contains_the_useful_parts() -> None:
    html = to_html(report())
    assert "Fix these first" in html and "All findings (38)" in html
    assert "boom" in html  # tool errors are visible
    assert html.count("<details>") == len(DEMO["findings"])


def test_html_empty_scan() -> None:
    html = to_html(report([]))
    assert "Nothing to review" in html and "Fix these first" not in html


# ---- PDF ---------------------------------------------------------------------------------------


def test_pdf_is_a_pdf_and_survives_hostile_markup() -> None:
    pdf = to_pdf(report(hostile_findings()))
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF") and len(pdf) > 2000


def test_pdf_caps_huge_reports_and_says_so() -> None:
    base = DEMO["findings"][0]
    many = [{**copy.deepcopy(base), "id": f"f{i}"} for i in range(MAX_FINDINGS + 25)]
    pdf = to_pdf(report(many))
    assert pdf.startswith(b"%PDF-")


def test_pdf_empty_scan() -> None:
    assert to_pdf(report([])).startswith(b"%PDF-")


# ---- dispatcher and CLI -----------------------------------------------------------------------


def test_render_dispatch_and_unknown_format() -> None:
    r = report()
    for fmt in FORMATS:
        assert render(fmt, r)
    assert json.loads(render("json", r))["unique_findings"] == len(DEMO["findings"])
    with pytest.raises(ValueError):
        render("docx", r)


def _stub(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import contextmanager

    @contextmanager
    def fake_materialize(source: str):  # type: ignore[no-untyped-def]
        yield Path(".")

    fs = [finding_from_dict(x) for x in DEMO["findings"]]
    result = ScanResult(
        fs, CorrelationStats(len(fs) + 4, len(fs)), {"bandit": {"status": "ok", "findings": 1}}
    )
    monkeypatch.setattr(cli_main, "materialize", fake_materialize)
    monkeypatch.setattr(cli_main, "scan", lambda *a, **k: result)


def test_cli_writes_sarif_html_and_pdf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch)
    runner = CliRunner()
    out = tmp_path / "r.sarif"
    res = runner.invoke(cli_main.app, ["scan", "./x", "--format", "sarif", "-o", str(out)])
    assert res.exit_code == 0, res.output
    jsonschema.validate(json.loads(out.read_text()), SCHEMA)
    html = tmp_path / "r.html"
    assert (
        runner.invoke(cli_main.app, ["scan", "./x", "--format", "html", "-o", str(html)]).exit_code
        == 0
    )
    assert "<title>Bulwark report" in html.read_text()
    pdf = tmp_path / "r.pdf"
    assert (
        runner.invoke(cli_main.app, ["scan", "./x", "--format", "pdf", "-o", str(pdf)]).exit_code
        == 0
    )
    assert pdf.read_bytes().startswith(b"%PDF-")


def test_cli_pdf_needs_an_output_file_and_bad_format_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub(monkeypatch)
    runner = CliRunner()
    assert runner.invoke(cli_main.app, ["scan", "./x", "--format", "pdf"]).exit_code != 0
    assert runner.invoke(cli_main.app, ["scan", "./x", "--format", "docx"]).exit_code != 0
    res = runner.invoke(cli_main.app, ["scan", "./x"])  # default json still prints to stdout
    assert res.exit_code == 0 and json.loads(res.output)["stats"]["unique_findings"] == 38
