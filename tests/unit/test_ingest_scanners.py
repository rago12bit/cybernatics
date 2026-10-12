"""The Burp, Nessus and OpenVAS import parsers (Week 57, plan §42.2): what each reads from real
DefectDojo samples, what each refuses, and when a report may close Issues and when it may not.

Counts that are checked against an expectation come from the XML itself, read with the standard
library (set arithmetic), not from the parser under test.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET  # noqa: S405 - test-only, on vendored files
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy.orm import Session, sessionmaker

from core.imports.parsers import ParseResult, get_parser, run_parser_on_bytes
from core.imports.parsers.base import ParseContext
from core.imports.parsers.safe import iter_csv
from core.imports.prepare import prepare
from core.imports.service import apply_import
from core.models import Category, Severity
from tests.unit.test_import_service import ORG, digest, setup

DD = Path("tests/golden/ingest/defectdojo")
BURP = (DD / "burp/seven_findings.xml").read_bytes()
BURP_ONE = (DD / "burp/one_finding_with_blank_response.xml").read_bytes()
NESSUS_XML = (DD / "nessus/nessus_many_vuln.xml").read_bytes()
NESSUS_CSV = (DD / "nessus/nessus_many_vuln2-default.csv").read_bytes()
OPENVAS_XML = (DD / "openvas/many_vuln.xml").read_bytes()
OPENVAS_CSV = (DD / "openvas/report_detail_v2.csv").read_bytes()


def run(name: str, data: bytes) -> ParseResult:
    return run_parser_on_bytes(get_parser(name), data)


# --- Burp -----------------------------------------------------------------------------------------


def test_burp_issues_are_dast_findings_one_per_issue() -> None:
    r = run("burp", BURP)
    assert r.complete and r.can_close_missing
    root = ET.fromstring(BURP)  # noqa: S314
    # DefectDojo folds these 16 issues into 7 findings; each <issue> is its own place here.
    assert len(r.findings) == len(root.findall("issue")) == 16
    assert {f.taxonomy.category for f in r.findings} == {Category.DAST}
    assert all(
        f.location.host.startswith("http") and f.location.route.startswith("/") for f in r.findings
    )


def test_burp_information_is_info_and_confidence_is_read() -> None:
    f = run("burp", BURP).findings[0]
    assert f.title == "Frameable response (potential Clickjacking)"
    assert f.scoring.normalized_severity is Severity.INFO
    assert f.evidence.rule_ids == {"burp": ["5245344"]}


def test_burp_cwe_comes_from_the_classifications() -> None:
    r = run("burp", (DD / "burp/one_finding_with_cwe.xml").read_bytes())
    assert r.findings[0].taxonomy.cwe, "expected a CWE from <vulnerabilityClassifications>"
    assert all(c.startswith("CWE-") for c in r.findings[0].taxonomy.cwe)


def test_burp_request_and_response_are_summarised_to_one_line_each() -> None:
    f = run("burp", BURP).findings[0]
    assert "Request: " in f.description and "Response: HTTP/" in f.description
    assert len(f.description) < 20_000


def test_burp_extension_issues_with_the_shared_type_are_kept_apart() -> None:
    """Every extension-raised issue has type 0x08000000 (134217728); on their own they would be
    one rule, and two different issues at one place would be one Issue."""
    xml = b"""<?xml version="1.0"?><issues burpVersion="2024">
    <issue><serialNumber>1</serialNumber><type>134217728</type><name>Ext one</name>
      <host ip="1.1.1.1">http://t</host><path>/a</path><location>/a</location>
      <severity>High</severity><confidence>Firm</confidence></issue>
    <issue><serialNumber>2</serialNumber><type>134217728</type><name>Ext two</name>
      <host ip="1.1.1.1">http://t</host><path>/a</path><location>/a</location>
      <severity>High</severity><confidence>Firm</confidence></issue></issues>"""
    from core.correlation import correlate

    r = run("burp", xml)
    assert r.complete
    merged, _ = correlate(r.findings)
    assert len({f.fingerprint for f in merged}) == 2


def test_burp_garbage_base64_and_missing_fields_do_not_raise() -> None:
    xml = b"""<?xml version="1.0"?><issues burpVersion="1"><issue><type>1</type><name>x</name>
    <host>http://t</host><path>/p?q=1</path><severity>Weird</severity>
    <requestresponse><request base64="true">!!!notbase64!!!</request></requestresponse>
    </issue></issues>"""
    r = run("burp", xml)
    assert r.complete and len(r.findings) == 1
    assert r.findings[0].location.route == "/p"  # the query is not part of the place
    assert any("weird" in w for w in r.warnings)  # unknown severity: Info, and said so


def test_burp_accepts_its_internal_doctype_but_not_an_entity_or_an_external_dtd() -> None:
    assert BURP.lstrip().startswith(b"<?xml") and b"<!DOCTYPE issues [" in BURP  # a real export
    assert run("burp", BURP).complete

    entity = BURP.replace(b"]>", b'<!ENTITY x SYSTEM "file:///etc/passwd">]>', 1)
    r = run("burp", entity)
    assert not r.complete and "refused" in (r.error or "")
    external = b'<?xml version="1.0"?><!DOCTYPE issues SYSTEM "http://127.0.0.1:9/e.dtd"><issues/>'
    r = run("burp", external)
    assert not r.complete and "external DTD" in (r.error or "")


def test_other_xml_is_not_burp() -> None:
    assert not run("burp", b"<html></html>").complete
    assert not run("burp", b"<OWASPZAPReport/>").complete


# --- Nessus ---------------------------------------------------------------------------------------


def _nessus_places(xml: bytes) -> set[tuple[str, str, str, str]]:
    out = set()
    for host in ET.fromstring(xml).iter("ReportHost"):  # noqa: S314
        for item in host.iter("ReportItem"):
            out.add(
                (item.get("pluginID") or "", host.get("name") or "", item.get("port") or "",
                 item.get("protocol") or "")
            )  # fmt: skip
    return out


def test_nessus_xml_gives_one_finding_per_plugin_per_host_and_port() -> None:
    r = run("nessus", NESSUS_XML)
    assert r.complete and r.can_close_missing
    assert len(r.findings) == sum(
        len(list(h.iter("ReportItem")))
        for h in ET.fromstring(NESSUS_XML).iter("ReportHost")  # noqa: S314
    )
    f = next(f for f in r.findings if f.location.route.endswith("/tcp"))
    assert f.taxonomy.category is Category.DAST
    assert f.location.host and not f.location.host.startswith("http")


def test_nessus_host_level_findings_have_the_host_route() -> None:
    xml = b"""<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.5">
    <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506"
      pluginName="Nessus Scan Information"><synopsis>s</synopsis></ReportItem>
    </ReportHost></Report></NessusClientData_v2>"""
    (f,) = run("nessus", xml).findings
    assert (f.location.host, f.location.route) == ("10.0.0.5", "host")


@pytest.mark.parametrize(
    "native,cvss3,expected",
    [
        ("3", "9.8", Severity.CRITICAL),  # the v3 base score overrides Nessus's own 0-4 ...
        ("1", "7.5", Severity.HIGH),
        ("1", "4.0", Severity.MEDIUM),  # ... on the FIRST bands (DefectDojo's start Medium at 5.0)
        ("3", "0.0", Severity.INFO),
        ("3", "", Severity.HIGH),  # no score: Nessus's own word stands
        ("4", "", Severity.CRITICAL),
        ("0", "", Severity.INFO),
    ],
)
def test_nessus_xml_severity(native: str, cvss3: str, expected: Severity) -> None:
    score = f"<cvss3_base_score>{cvss3}</cvss3_base_score>" if cvss3 else ""
    xml = f"""<NessusClientData_v2><Report name="r"><ReportHost name="h"><ReportItem port="22"
      protocol="tcp" severity="{native}" pluginID="1" pluginName="p">{score}</ReportItem>
      </ReportHost></Report></NessusClientData_v2>""".encode()
    (f,) = run("nessus", xml).findings
    assert f.scoring.normalized_severity is expected


def test_nessus_a_report_with_no_hosts_scanned_nothing_and_closes_nothing() -> None:
    r = run("nessus", b"<NessusClientData_v2><Report name='r'></Report></NessusClientData_v2>")
    assert r.complete and r.findings == [] and not r.can_close_missing
    assert any("scanned nothing" in w for w in r.warnings)


def test_nessus_csv_reads_both_delimiters_and_both_header_styles() -> None:
    pro = run("nessus", NESSUS_CSV)
    tenable_io = run("nessus", (DD / "nessus/nessus_new.csv").read_bytes())  # ';' delimited
    assert pro.complete and tenable_io.complete
    # 30 rows (DefectDojo folds one duplicate into 29); 99 rows, none of which fold.
    assert len(pro.findings) == 30 and len(tenable_io.findings) == 99
    assert all(f.evidence.rule_ids["nessus"][0].isdigit() for f in pro.findings)


def test_nessus_csv_ignores_an_impossible_cvss_score_and_says_so() -> None:
    """A real sample (nessus-template.csv) has `75` where 7.5 was meant; as a CVSS score that is
    nonsense, and it must not turn a High into a Critical."""
    r = run("nessus", (DD / "nessus/nessus-template.csv").read_bytes())
    assert r.complete and r.findings[0].scoring.normalized_severity is Severity.HIGH
    assert r.findings[0].scoring.cvss_v3_1 is None
    assert any("not between 0 and 10" in w for w in r.warnings)


def test_nessus_csv_cut_off_mid_row_is_an_error() -> None:
    cut = NESSUS_CSV[: NESSUS_CSV.rindex(b"\n", 0, len(NESSUS_CSV) - 40) + 30]
    r = run("nessus", cut)
    assert not r.complete and ("cut off" in (r.error or ""))


def test_nessus_csv_cut_just_before_the_last_field_is_an_error() -> None:
    """Found by the prefix property test: cut after `...deprecate-00",`, the row's last field
    (Plugin Output) reads as empty, so the row is as wide as the header and used to pass as whole,
    complete and able to close Issues."""
    raw = NESSUS_CSV.rstrip()
    assert raw[:29061].endswith(b'oldversions-deprecate-00",')
    r = run("nessus", raw[:29061])
    assert not r.complete and "cut off" in (r.error or "")


def test_nessus_csv_cut_inside_an_escaped_quote_is_an_error() -> None:
    """Cut between the two quotes of `""Strict-Transport-Security""`, the first reads as the field's
    closing quote: a well-formed, full-width row whose last field is short."""
    raw = NESSUS_CSV.rstrip()
    cut = raw.index(b'""Strict-Transport-Security""') + 1
    r = run("nessus", raw[:cut])
    assert not r.complete and "cut off" in (r.error or "")


def test_nessus_csv_with_only_a_header_closes_nothing() -> None:
    header = NESSUS_CSV.split(b"\n", 1)[0] + b"\n"
    r = run("nessus", header)
    assert r.complete and r.findings == [] and not r.can_close_missing


def test_nessus_csv_epss_in_either_spelling() -> None:
    r = run("nessus", (DD / "nessus/nessus-template.csv").read_bytes())
    assert r.findings[0].scoring.epss_score == 0.3833  # the file writes "3833"


def test_csv_reader_limits_and_quotes() -> None:
    ctx = ParseContext()
    rows = list(iter_csv(io.BytesIO('﻿a,b\n"x\ny",2\n'.encode()), ctx))
    assert rows == [["a", "b"], ["x\ny", "2"]]  # BOM stripped, newline kept inside quotes
    with pytest.raises(Exception, match="cut off"):
        list(iter_csv(io.BytesIO(b'a,b\n"never closed'), ParseContext()))


@pytest.mark.parametrize(
    "data",
    # The last is `1,"x ""quoted"""` cut inside its escaped quote.
    [b'"a","b","c"\n"1","2",', b'"a";"b"\n"1";', b'a,b\n"1","2"', b'a,b\n1,"x "'],
)
def test_csv_ending_on_a_quoted_field_with_no_line_break_reads_as_cut(data: bytes) -> None:
    with pytest.raises(Exception, match="cut off"):
        list(iter_csv(io.BytesIO(data), ParseContext()))


@pytest.mark.parametrize(
    ("data", "can_close"),
    [(b"a,b,c\n1,2,", False), (b"a,b\n1,2", False), (b'a,b\n"1",2', False),
     (b'a,b\n"1","2"\n', True), (b"a,b\r\n1,2\r\n", True)],
)  # fmt: skip
def test_csv_that_ends_unquoted_still_reads_but_closes_only_with_a_line_break(
    data: bytes, can_close: bool
) -> None:
    """Real Tenable exports (nessus-template.csv, nessus_new.csv) end with no line break, on an
    unquoted field; a cut there cannot be told from a whole file, so it is read, but closes nothing
    unless its last row ends with a line break."""
    ctx = ParseContext()
    assert len(list(iter_csv(io.BytesIO(data), ctx))) == 2
    assert ctx.can_close_missing is can_close
    assert any("line break" in w for w in ctx.warnings) is not can_close


def test_nessus_csv_cut_after_an_empty_field_closes_nothing() -> None:
    """Cut right after the delimiter that follows an empty field, the row stays full width and ends
    on a delimiter, exactly as a whole row with an empty last field does (nessus-template.csv ends
    `...,,,`): only the missing line break says it may be cut off."""
    header = NESSUS_CSV.split(b"\n", 1)[0]
    n = header.count(b",") + 1
    whole = header + b"\n" + b",".join([b'"v"'] * (n - 2) + [b"", b'"last"']) + b"\n"
    cut = whole[: whole.rindex(b'"last"')]
    assert cut.endswith(b'"v",,') and run("nessus", whole).can_close_missing
    r = run("nessus", cut)
    assert r.complete and not r.can_close_missing
    assert any("line break" in w for w in r.warnings)


@pytest.mark.parametrize("name", ["nessus-template.csv", "nessus_new.csv"])
def test_real_exports_without_a_final_line_break_still_import_but_close_nothing(name: str) -> None:
    whole = (DD / "nessus" / name).read_bytes()
    assert not whole.endswith(b"\n")
    r = run("nessus", whole)
    assert r.complete and r.findings and not r.can_close_missing
    assert run("nessus", whole + b"\n").can_close_missing


# --- OpenVAS --------------------------------------------------------------------------------------


def test_openvas_xml_gives_one_finding_per_result() -> None:
    r = run("openvas", OPENVAS_XML)
    assert r.complete and r.can_close_missing
    assert (
        len(r.findings) == len(ET.fromstring(OPENVAS_XML).findall(".//result")) == 44
    )  # noqa: S314


def test_openvas_xml_and_csv_agree_on_the_same_result() -> None:
    from_csv = run("openvas", OPENVAS_CSV).findings
    from_xml = run("openvas", (DD / "openvas/report_detail_v2.xml").read_bytes()).findings
    assert len(from_csv) == len(from_xml) == 1
    a, b = from_csv[0], from_xml[0]
    assert (a.title, a.scoring.normalized_severity) == (b.title, b.scoring.normalized_severity)
    assert a.evidence.rule_ids == b.evidence.rule_ids
    assert (a.location.host, a.location.route) == (b.location.host, b.location.route)
    assert set(a.taxonomy.cve) == set(b.taxonomy.cve) and len(a.taxonomy.cve) == 93


def test_openvas_severity_is_the_threat_and_log_is_info_without_a_warning() -> None:
    r = run("openvas", OPENVAS_XML)
    assert {f.scoring.normalized_severity for f in r.findings} >= {Severity.HIGH, Severity.MEDIUM}
    assert not any("severity" in w.lower() and "not a known" in w for w in r.warnings)


def _with_status(status: str) -> bytes:
    return OPENVAS_XML.replace(
        b"<scan_run_status>Done</scan_run_status>",
        f"<scan_run_status>{status}</scan_run_status>".encode(),
        1,
    )


@pytest.mark.parametrize("status", ["Stopped", "Interrupted", "Running", "Requested"])
def test_openvas_a_scan_that_did_not_finish_closes_nothing(status: str) -> None:
    r = run("openvas", _with_status(status))
    assert r.complete and len(r.findings) == 44 and not r.can_close_missing
    assert any(status in w and "partial" in w for w in r.warnings)


def test_openvas_a_finished_scan_may_close() -> None:
    assert run("openvas", _with_status("Done")).can_close_missing


def test_openvas_no_results_and_no_hosts_closes_nothing() -> None:
    r = run("openvas", (DD / "openvas/no_vuln.xml").read_bytes())  # status Done, 0 hosts
    assert r.complete and r.findings == [] and not r.can_close_missing
    assert not run("openvas", (DD / "openvas/no_vuln.csv").read_bytes()).can_close_missing


def test_openvas_a_severity_filtered_export_warns_that_hidden_levels_will_read_as_fixed() -> None:
    filtered = OPENVAS_XML.replace(b"levels=hml", b"levels=hm", 1)
    if filtered == OPENVAS_XML:
        pytest.skip("this sample has no levels= filter to alter")
    r = run("openvas", filtered)
    assert any("levels=hm" in w and "read as fixed" in w for w in r.warnings)


def test_openvas_csv_cut_off_mid_row_is_an_error() -> None:
    raw = (DD / "openvas/many_vuln.csv").read_bytes().rstrip()
    r = run("openvas", raw[:-30])  # inside the last row's quoted text
    assert not r.complete


# --- all five: truncation, hostile bytes, reimport -------------------------------------------------

FILES = {
    "burp": ("burp", BURP_ONE),
    "nessus-xml": ("nessus", NESSUS_XML[:200_000].rsplit(b"</ReportItem>", 1)[0]
              + b"</ReportItem></ReportHost></Report></NessusClientData_v2>"),
    "nessus-csv": ("nessus", NESSUS_CSV),
    "openvas-xml": ("openvas", OPENVAS_XML),
    "openvas-csv": ("openvas", (DD / "openvas/many_vuln.csv").read_bytes()),
}  # fmt: skip


@settings(max_examples=150, deadline=None)
@given(st.sampled_from(sorted(FILES)), st.floats(min_value=0.0, max_value=0.999))
def test_no_strict_prefix_of_a_report_reads_as_a_complete_one(which: str, fraction: float) -> None:
    """A file cut off anywhere is an error, or is read as a report that cannot close anything (a CSV
    cut inside its header line is a header and no rows) -- except a CSV cut exactly between two
    rows, which is a valid shorter CSV and cannot be told apart from one."""
    parser, whole = FILES[which]
    raw = whole.rstrip()
    cut = int(len(raw) * fraction)
    r = run(parser, raw[:cut])
    row_boundary = which.endswith("csv") and (
        raw[cut : cut + 1] in (b"\n", b"\r") or raw[cut - 1 : cut] == b"\n" or cut == 0
    )
    safe = not r.complete or not r.can_close_missing
    assert safe or row_boundary or (cut == 0 and r.findings == []), (which, cut)
    if r.complete and row_boundary and which.endswith("csv"):
        assert len(r.findings) <= len(run(parser, whole).findings)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=2048))
def test_arbitrary_bytes_never_raise_in_the_scanner_parsers(blob: bytes) -> None:
    for name in ("burp", "nessus", "openvas"):
        r = run(name, blob)
        assert r.complete or r.error


def test_reimporting_a_nessus_scan_closes_exactly_what_the_new_file_no_longer_lists(
    sessions: sessionmaker[Session],
) -> None:
    """Expected counts come from the XML (stdlib), not from the parser: drop one plugin on one host
    from a real report and import both."""
    first = _nessus_places(NESSUS_XML)
    root = ET.fromstring(NESSUS_XML)  # noqa: S314
    victim_host = next(h for h in root.iter("ReportHost") if h.find("ReportItem") is not None)
    victim = victim_host.find("ReportItem")
    assert victim is not None
    victim_host.remove(victim)
    second_xml = ET.tostring(root)
    second = _nessus_places(second_xml)
    assert len(first - second) == 1

    with sessions() as s:
        _, t = setup(s, "Nessus")

        def do(raw: bytes, n: int):
            result = run("nessus", raw)
            assert result.complete
            return apply_import(
                s, org_id=ORG, test_id=t["Nessus"], findings=prepare(result.findings),
                parser="nessus", file_digest=digest(n), file_name=f"scan-{n}.nessus",
            )  # fmt: skip

        one, two = do(NESSUS_XML, 1).record, do(second_xml, 2).record
    assert one.new_count == len(first)
    assert (two.new_count, two.unchanged_count, two.closed_count) == (0, len(first) - 1, 1)
