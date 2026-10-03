"""The ZAP and Nuclei import parsers (Week 57, plan §42.2): behaviour on real DefectDojo samples,
detection, hostile input, truncation, and one end-to-end reimport whose expected counts come from an
independent reading of the XML (stdlib ElementTree, set arithmetic), not from our own parser."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET  # noqa: S405 - test-only, on vendored files
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy.orm import Session, sessionmaker

from core.dast.mapping import target_of
from core.imports.parsers import CONFIDENT, ParseResult, detect, get_parser, run_parser_on_bytes
from core.imports.prepare import prepare
from core.imports.service import apply_import
from core.models import Category, Severity
from tests.unit.test_import_service import ORG, digest, setup

DD = Path("tests/golden/ingest/defectdojo")
ZAP_FIRST = (DD / "zap/zap-results-first-scan.xml").read_bytes()
ZAP_SECOND = (DD / "zap/zap-results-second-scan.xml").read_bytes()
ZAP_SMALL = (DD / "zap/0_zap_sample.xml").read_bytes()
NUCLEI_LINES = (DD / "nuclei/many_findings.json").read_bytes()
NUCLEI_ARRAY = (DD / "nuclei/multiple_v3.json").read_bytes()


def run(name: str, data: bytes) -> ParseResult:
    return run_parser_on_bytes(get_parser(name), data)


# --- ZAP ------------------------------------------------------------------------------------------


def _zap_json_from_xml(xml: bytes) -> bytes:
    """The JSON report ZAP writes, built from a real XML one: same alerts, the JSON spelling
    (`@name`, `alerts` list). Synthetic -- no real ZAP JSON sample ships with DefectDojo -- so this
    proves the two readers agree, not that the JSON shape is what a given ZAP version writes."""
    root = ET.fromstring(xml)  # noqa: S314
    sites = []
    for site in root.iter("site"):
        alerts = []
        for item in site.iter("alertitem"):
            alert: dict[str, object] = {}
            for child in item:
                if child.tag == "instances":
                    alert["instances"] = [
                        {c.tag: c.text or "" for c in inst} for inst in child.iter("instance")
                    ]
                else:
                    alert[child.tag] = child.text or ""
            alerts.append(alert)
        sites.append({"@name": site.get("name"), "alerts": alerts})
    return json.dumps({"@programName": "ZAP", "@version": "2.16.1", "site": sites}).encode()


@pytest.mark.parametrize("name", ["zap-results-first-scan.xml", "0_zap_sample.xml", "juicy2.xml"])
def test_zap_xml_and_json_reports_give_identical_findings(name: str) -> None:
    xml = (DD / "zap" / name).read_bytes()
    from_xml, from_json = run("zap", xml), run("zap", _zap_json_from_xml(xml))
    assert from_xml.complete and from_json.complete and from_xml.findings
    assert [f.to_dict() for f in from_xml.findings] == [f.to_dict() for f in from_json.findings]


def test_zap_findings_are_dast_findings_with_a_host_and_a_route() -> None:
    r = run("zap", ZAP_SMALL)
    assert r.complete and r.can_close_missing
    assert {f.taxonomy.category for f in r.findings} == {Category.DAST}
    assert {f.location.host for f in r.findings} == {"https://mainsite.com"}
    assert {f.location.route for f in r.findings} >= {"/dashboard", "/"}
    assert all(f.location.path == "" and f.evidence.reported_by == ["zap"] for f in r.findings)


def test_zap_severity_and_confidence_come_from_the_alert() -> None:
    sev = {f.title: f.scoring.normalized_severity for f in run("zap", ZAP_FIRST).findings}
    assert sev["PII Disclosure"] is Severity.HIGH  # riskcode 3
    assert sev["User Controllable HTML Element Attribute (Potential XSS)"] is Severity.INFO


def test_an_unknown_riskcode_is_info_and_the_report_says_so() -> None:
    bad = ZAP_SMALL.replace(b"<riskcode>1</riskcode>", b"<riskcode>7</riskcode>", 1)
    r = run("zap", bad)
    assert r.complete
    assert any("riskcode 7" in w and "Info" in w for w in r.warnings)


def test_requests_and_responses_are_summarised_not_stored() -> None:
    r = run("zap", (DD / "zap/zap_2.16.1_with_req_resp.xml").read_bytes())
    assert r.complete and r.findings
    assert any("Response: HTTP/" in f.description for f in r.findings)
    assert all(len(f.description) < 5_000 for f in r.findings)  # no 50 KB bodies in a finding


def test_an_empty_zap_report_is_a_valid_clean_scan_that_may_close() -> None:
    r = run("zap", (DD / "zap/empty_2.9.0.xml").read_bytes())
    assert r.complete and r.findings == [] and r.can_close_missing


# --- Nuclei ---------------------------------------------------------------------------------------


def test_nuclei_lines_and_array_forms_are_both_read() -> None:
    lines, array = run("nuclei", NUCLEI_LINES), run("nuclei", NUCLEI_ARRAY)
    assert lines.complete and array.complete
    assert len(lines.findings) == 18 and len(array.findings) == 6
    as_array = b"[" + b",".join(ln for ln in NUCLEI_LINES.splitlines() if ln.strip()) + b"]"
    assert [f.title for f in run("nuclei", as_array).findings] == [f.title for f in lines.findings]


def test_nuclei_network_matches_are_host_and_port() -> None:
    hosts = {f.location.host for f in run("nuclei", NUCLEI_LINES).findings}
    assert "nuclei-example.com:22" in hosts and "nuclei-example.com:3306" in hosts


def test_an_empty_nuclei_file_imports_nothing_and_closes_nothing() -> None:
    """Empty output is what Nuclei writes for a clean run -- and what a failed export looks like."""
    r = run("nuclei", b"")
    assert r.complete and r.findings == [] and not r.can_close_missing
    assert any("empty" in w for w in r.warnings)
    assert run("nuclei", b"  \n\n").can_close_missing is False


def test_an_explicit_empty_array_is_a_clean_run_that_may_close() -> None:
    r = run("nuclei", b"[]")
    assert r.complete and r.findings == [] and r.can_close_missing


def test_a_cut_off_nuclei_file_is_an_error_not_a_shorter_report() -> None:
    cut = NUCLEI_LINES.rstrip()[:-40]  # the last record is cut mid-way
    r = run("nuclei", cut)
    assert not r.complete and "valid JSON" in (r.error or "")


def test_a_non_json_line_in_the_middle_is_an_error() -> None:
    lines = NUCLEI_LINES.splitlines()
    broken = b"\n".join([*lines[:3], b"[INF] Using Nuclei Engine 3.0", *lines[3:]])
    r = run("nuclei", broken)
    assert not r.complete


def test_records_that_are_not_nuclei_results_are_skipped_with_a_warning() -> None:
    r = run("nuclei", NUCLEI_LINES + b'\n{"hello": "world"}\n')
    assert r.complete and len(r.findings) == 18
    assert any("not a Nuclei result" in w for w in r.warnings)


def test_a_deeply_nested_nuclei_record_is_refused() -> None:
    r = run("nuclei", b'{"info":' + b"[" * 5_000 + b"]" * 5_000 + b"}")
    assert not r.complete and "deeper" in (r.error or "")


# --- detection ------------------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["zap", "nuclei", "burp", "nessus", "openvas"])
def test_every_vendored_sample_is_detected_as_its_own_tool_and_nothing_else(tool: str) -> None:
    for path in sorted((DD / tool).iterdir()):
        if path.name == "MANIFEST.json" or path.stat().st_size == 0:
            continue
        ranked = detect(path.read_bytes()[:65536])
        assert ranked and ranked[0][0].name == tool, path.name
        assert ranked[0][1] >= CONFIDENT, path.name
        assert len(ranked) == 1, f"{path.name} also looks like {[p.name for p, _ in ranked[1:]]}"


def test_other_formats_are_not_mistaken_for_zap_or_nuclei() -> None:
    for path in [Path("tests/golden/semgrep/raw.json"), Path("tests/golden/osv-scanner/raw.json"),
                 *Path("tests/golden/ingest").glob("cyclonedx-*"), Path("tests/golden/ingest/spdx.json")]:  # fmt: skip
        names = {p.name for p, _ in detect(path.read_bytes()[:65536])}
        assert not names & {"zap", "nuclei", "burp", "nessus", "openvas"}, path


# --- hostile input --------------------------------------------------------------------------------

XXE = (
    b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    b'<OWASPZAPReport><site name="http://t" host="t" port="80"><alerts><alertitem>'
    b"<pluginid>1</pluginid><alert>&x;</alert><riskcode>1</riskcode><instances/>"
    b"</alertitem></alerts></site></OWASPZAPReport>"
)


def test_zap_xml_with_an_entity_is_refused_and_nothing_leaks() -> None:
    r = run("zap", XXE)
    assert not r.complete and r.findings == []
    assert "root:" not in json.dumps([r.error, r.warnings])


def test_zap_billion_laughs_is_refused_quickly() -> None:
    laugh = (
        '<?xml version="1.0"?><!DOCTYPE z [<!ENTITY a "aaaaaaaaaa">'
        + "".join(
            f'<!ENTITY {chr(98 + i)} "{"&" + chr(97 + i) + ";" * 1}{"&" + chr(97 + i) + ";"}">'
            for i in range(8)
        )
        + "]><OWASPZAPReport><site><alerts/></site></OWASPZAPReport>"
    )
    r = run("zap", laugh.encode())
    assert not r.complete


def test_a_json_file_that_is_not_a_zap_report_is_an_error() -> None:
    assert not run("zap", b'{"hello": 1}').complete
    assert not run("zap", b"<html><body>not a report</body></html>").complete


@settings(max_examples=120, deadline=None)
@given(st.sampled_from(["zap-xml", "zap-json", "nuclei-lines", "nuclei-array"]),
       st.floats(min_value=0.0, max_value=0.999))  # fmt: skip
def test_no_strict_prefix_of_a_report_reads_as_a_complete_one(which: str, fraction: float) -> None:
    """A file cut off anywhere is an error -- never a smaller valid report that would close every
    Issue past the cut."""
    files = {
        "zap-xml": ("zap", ZAP_SMALL),
        "zap-json": ("zap", _zap_json_from_xml(ZAP_SMALL)),
        "nuclei-lines": ("nuclei", NUCLEI_LINES),
        "nuclei-array": ("nuclei", NUCLEI_ARRAY),
    }
    parser, raw = files[which]
    raw = raw.rstrip()
    cut = int(len(raw) * fraction)
    r = run(parser, raw[:cut])
    # A JSONL file cut exactly at a record boundary is a valid shorter JSONL file; nothing in the
    # format says otherwise. Every other cut must fail.
    at_boundary = which == "nuclei-lines" and (
        cut == 0 or raw[cut - 1 : cut] == b"\n" or raw[cut : cut + 1] in (b"\n", b"\r")
    )
    assert not r.complete or at_boundary or (cut == 0 and r.findings == []), (which, cut)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=2048))
def test_arbitrary_bytes_never_raise_in_the_new_parsers(blob: bytes) -> None:
    for name in ("zap", "nuclei"):
        r = run(name, blob)
        assert r.complete or r.error


# --- reimport, end to end -------------------------------------------------------------------------


def _places(xml: bytes) -> set[tuple[str, str, str]]:
    """(alert, host, route) for every instance, read straight from the XML with the standard
    library -- the oracle the import's counts are checked against."""
    out = set()
    for item in ET.fromstring(xml).iter("alertitem"):  # noqa: S314
        plugin = (item.findtext("pluginid") or "").strip()
        for inst in item.iter("instance"):
            host, route = target_of((inst.findtext("uri") or "").strip())
            out.add((plugin, host, route))
    return out


def test_importing_a_second_zap_scan_counts_new_unchanged_and_closed_by_place(
    sessions: sessionmaker[Session],
) -> None:
    first, second = _places(ZAP_FIRST), _places(ZAP_SECOND)
    assert first - second and second - first and first & second  # the sample really differs

    with sessions() as s:
        _, t = setup(s, "ZAP baseline")

        def do(raw: bytes, n: int):
            result = run("zap", raw)
            assert result.complete
            return apply_import(
                s, org_id=ORG, test_id=t["ZAP baseline"], findings=prepare(result.findings),
                parser="zap", file_digest=digest(n), file_name=f"zap-{n}.xml",
            )  # fmt: skip

        one, two = do(ZAP_FIRST, 1).record, do(ZAP_SECOND, 2).record
    assert one.new_count == len(first)
    assert (two.new_count, two.unchanged_count, two.closed_count) == (
        len(second - first),
        len(second & first),
        len(first - second),
    )
