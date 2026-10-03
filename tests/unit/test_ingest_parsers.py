"""CycloneDX, SPDX and OSV import parsers (Week 54 task 6, plan §42.2), against real files generated
by the project's own Syft and Grype images (tests/golden/ingest/README.md), the XXE and entity-
expansion corpus, and property tests that mutate and truncate those real files."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.adapters.osv_scanner import OsvScannerAdapter
from core.imports.parsers import ParseResult, detect, get_parser, run_parser_on_bytes

G = Path("tests/golden/ingest")
CDX_VULN_JSON = (G / "cyclonedx-vulnerabilities.json").read_bytes()
CDX_VULN_XML = (G / "cyclonedx-vulnerabilities.xml").read_bytes()
CDX_SBOM_JSON = (G / "cyclonedx-sbom.json").read_bytes()
CDX_SBOM_XML = (G / "cyclonedx-sbom.xml").read_bytes()
SPDX = (G / "spdx.json").read_bytes()
OSV = Path("tests/golden/osv-scanner/raw.json").read_bytes()
SARIF = Path("tests/golden/semgrep/raw.json").read_bytes()


def run(name: str, data: bytes | dict[str, Any]) -> ParseResult:
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return run_parser_on_bytes(get_parser(name), raw)


# --- CycloneDX, real Grype output -----------------------------------------------------------------


def test_a_real_cyclonedx_with_vulnerabilities_yields_a_finding_per_vulnerability() -> None:
    r = run("cyclonedx", CDX_VULN_JSON)
    assert r.complete and r.can_close_missing
    assert len(r.findings) == 19 and r.warnings == []
    assert {f.package.ecosystem for f in r.findings if f.package} == {"npm", "pypi"}
    assert {f.location.path for f in r.findings} == {"package-lock.json", "requirements.txt"}
    assert {t for f in r.findings for t in f.evidence.reported_by} == {
        "grype"
    }  # the tool named in the file
    lodash = next(f for f in r.findings if f.id.startswith("grype:GHSA-35jh-r3h4-6jhm"))
    assert lodash.package and (lodash.package.name, lodash.package.version) == ("lodash", "4.17.4")
    assert lodash.taxonomy.cve == (
        "CVE-2021-23337",
    )  # pulled out of the advisory URL, so it can correlate
    assert lodash.scoring.cvss_v3_1 == 7.2 and lodash.scoring.normalized_severity.value == "HIGH"


def test_json_and_xml_of_the_same_scan_give_identical_findings() -> None:
    j, x = run("cyclonedx", CDX_VULN_JSON), run("cyclonedx", CDX_VULN_XML)
    assert x.complete
    assert [f.to_dict() for f in j.findings] == [f.to_dict() for f in x.findings]


def test_an_epss_probability_is_not_mistaken_for_a_severity() -> None:
    """Every vulnerability in the real file also has a rating with method "other" and no severity:
    the EPSS exploit probability (0.21...). It must not turn into a severity of any kind."""
    raw = json.loads(CDX_VULN_JSON)
    assert any(
        r.get("method") == "other" and "severity" not in r
        for v in raw["vulnerabilities"]
        for r in v["ratings"]
    )
    by_id = {v["id"]: v for v in raw["vulnerabilities"]}
    for f in run("cyclonedx", CDX_VULN_JSON).findings:
        vid = f.evidence.rule_ids["grype"][0]
        cvss = [
            r["score"] for r in by_id[vid]["ratings"] if str(r.get("method", "")).startswith("CVSS")
        ]
        if cvss:
            assert f.scoring.cvss_v3_1 == max(cvss) or f.scoring.cvss_v3_1 is None


def test_a_real_sbom_with_no_vulnerabilities_is_an_inventory_that_can_close_nothing() -> None:
    for sbom in (CDX_SBOM_JSON, CDX_SBOM_XML):
        r = run("cyclonedx", sbom)
        assert r.complete and r.findings == []
        assert r.can_close_missing is False  # it never said these packages are clean
        assert any("no vulnerabilities section" in w for w in r.warnings)


def test_a_vulnerabilities_section_that_is_empty_is_a_claim_and_can_close() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "vulnerabilities": []}
    r = run("cyclonedx", doc)
    assert r.complete and r.findings == [] and r.can_close_missing is True


def test_vulnerabilities_listed_before_components_still_resolve() -> None:
    """JSON key order is not fixed; the file is read twice for exactly this."""
    doc = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "ratings": [{"score": 9.8, "severity": "critical", "method": "CVSSv31"}],
                "affects": [{"ref": "lib-a"}],
            }
        ],
        "components": [{"bom-ref": "lib-a", "type": "library", "name": "left-pad", "version": "1.0.0",
                        "purl": "pkg:npm/left-pad@1.0.0"}],
    }  # fmt: skip
    (f,) = run("cyclonedx", doc).findings
    assert (
        f.package
        and f.package.name == "left-pad"
        and f.scoring.normalized_severity.value == "CRITICAL"
    )


def test_a_purl_shaped_reference_resolves_without_a_component_entry() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [
            {"id": "CVE-2024-0002", "ratings": [{"severity": "high"}],
             "affects": [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
        ],
    }  # fmt: skip
    (f,) = run("cyclonedx", doc).findings
    assert f.package and f.package.name == "org.apache.logging.log4j:log4j-core"
    assert f.package.ecosystem == "maven" and f.scoring.normalized_severity.value == "HIGH"


def test_things_that_cannot_become_findings_are_counted_and_said_aloud() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "components": [],
        "vulnerabilities": [
            {"id": "CVE-1", "ratings": [{"severity": "high"}], "affects": [{"ref": "not-a-purl"}]},
            {"id": "CVE-2", "ratings": [{"severity": "high"}], "affects": []},
            {"ratings": [{"severity": "high"}], "affects": [{"ref": "pkg:npm/a@1"}]},
        ],
    }  # fmt: skip
    r = run("cyclonedx", doc)
    assert r.complete and r.findings == []
    text = " | ".join(r.warnings)
    assert "not described in the file" in text and "affects nothing" in text and "has no id" in text


def test_an_unknown_severity_is_imported_as_info_and_reported() -> None:
    """The plan's own example: rows saying "Moderate", which is not a known severity."""
    doc = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [
            {"id": f"CVE-{n}", "ratings": [{"severity": "Moderate"}], "affects": [{"ref": "pkg:npm/a@1"}]}
            for n in range(3)
        ],
    }  # fmt: skip
    r = run("cyclonedx", doc)
    assert [f.scoring.normalized_severity.value for f in r.findings] == ["INFO"] * 3
    assert any("3 finding(s) use the severity 'moderate'" in w for w in r.warnings)


def test_a_cyclonedx_1_4_tools_list_is_read() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "metadata": {"tools": [{"vendor": "acme", "name": "Scanner X", "version": "1"}]},
        "vulnerabilities": [{"id": "CVE-9", "ratings": [{"severity": "low"}],
                             "affects": [{"ref": "pkg:pypi/x@1"}]}],
    }  # fmt: skip
    (f,) = run("cyclonedx", doc).findings
    assert f.evidence.reported_by == ["scanner-x"]


def test_a_json_file_that_is_not_cyclonedx_is_refused() -> None:
    r = run("cyclonedx", {"bomFormat": "SomethingElse", "components": []})
    assert not r.complete and "not CycloneDX" in (r.error or "")
    assert not run("cyclonedx", {"hello": "world"}).complete


# --- XML security: XXE, entity expansion, external DTDs ------------------------------------------

BOM_OPEN = '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">'
XML_ATTACKS = {
    "external entity reading a local file": (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        + BOM_OPEN
        + '<components><component type="library"><name>&xxe;</name><version>1</version>'
        + "</component></components></bom>"
    ),
    "external entity reaching the network": (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY xxe SYSTEM "http://127.0.0.1:9/x">]>'
        + BOM_OPEN
        + '<components><component type="library"><name>&xxe;</name></component></components></bom>'
    ),
    "external DTD": (
        '<?xml version="1.0"?><!DOCTYPE bom SYSTEM "http://127.0.0.1:9/evil.dtd">' + BOM_OPEN
        + "</bom>"
    ),
    "parameter entity": (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY % p SYSTEM "file:///etc/passwd">%p;]>'
        + BOM_OPEN
        + "</bom>"
    ),
    "billion laughs": (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY a "aaaaaaaaaa">'
        + "".join(
            f'<!ENTITY {chr(98 + i)} "&{chr(97 + i)};&{chr(97 + i)};&{chr(97 + i)};&{chr(97 + i)};'
            f'&{chr(97 + i)};&{chr(97 + i)};&{chr(97 + i)};&{chr(97 + i)};&{chr(97 + i)};'
            f'&{chr(97 + i)};">'
            for i in range(8)
        )
        + "]>"
        + BOM_OPEN
        + '<components><component type="library"><name>&i;</name></component></components></bom>'
    ),
    "quadratic blowup": (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY a "' + "x" * 5000 + '">]>' + BOM_OPEN
        + '<components><component type="library"><name>' + "&a;" * 5000
        + "</name></component></components></bom>"
    ),
    "a harmless internal entity (refused all the same)": (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY n "lodash">]>' + BOM_OPEN
        + '<components><component type="library"><name>&n;</name></component></components></bom>'
    ),
}  # fmt: skip


@pytest.mark.parametrize("attack", sorted(XML_ATTACKS))
def test_xml_attacks_are_refused_without_leaking_or_connecting(
    attack: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    connections: list[object] = []
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: connections.append(a) or None)
    started = time.monotonic()
    r = run_parser_on_bytes(get_parser("cyclonedx"), XML_ATTACKS[attack].encode())

    assert time.monotonic() - started < 2.0, "expansion must be refused, not performed"
    assert not r.complete and ("DTD" in (r.error or "") or "entity" in (r.error or ""))
    assert r.findings == []
    assert connections == []  # nothing was fetched
    assert "root:" not in json.dumps([r.error, r.warnings])  # /etc/passwd contents never surface


def test_deeply_nested_xml_is_refused() -> None:
    xml = BOM_OPEN + "<a>" * 500 + "</a>" * 500 + "</bom>"
    r = run_parser_on_bytes(get_parser("cyclonedx"), xml.encode())
    assert not r.complete and "deeper than" in (r.error or "")


def test_malformed_xml_is_an_error_not_an_empty_report() -> None:
    r = run_parser_on_bytes(get_parser("cyclonedx"), BOM_OPEN.encode() + b"<components><oops>")
    assert not r.complete and "not valid XML" in (r.error or "")


# --- SPDX ------------------------------------------------------------------------------------------


def test_a_real_spdx_file_is_recognised_validated_and_closes_nothing() -> None:
    r = run("spdx", SPDX)
    assert r.complete and r.findings == [] and r.can_close_missing is False
    assert any("SPDX-2.3" in w and "5 packages" in w for w in r.warnings)


def test_a_json_file_without_an_spdx_version_is_refused() -> None:
    r = run("spdx", {"packages": []})
    assert not r.complete and "spdxVersion" in (r.error or "")


# --- OSV-Scanner results ---------------------------------------------------------------------------


def test_a_real_osv_scanner_report_reads_exactly_as_the_native_path_reads_it() -> None:
    native = OsvScannerAdapter().parse(OSV)
    r = run("osv", OSV)
    assert r.complete and r.can_close_missing
    assert [f.to_dict() for f in r.findings] == [f.to_dict() for f in native]
    assert len(r.findings) == 17


def test_an_empty_osv_results_list_is_a_complete_report_that_can_close() -> None:
    r = run("osv", {"results": []})
    assert r.complete and r.findings == [] and r.can_close_missing is True


def test_osv_output_without_results_is_refused_and_a_bad_result_is_skipped() -> None:
    assert not run("osv", {"vulns": []}).complete
    r = run(
        "osv", {"results": [{"nonsense": True}, {"source": {"path": "/target/x"}, "packages": []}]}
    )
    assert r.complete and r.findings == []


# --- detection: every real file is recognised as itself, with confidence ---------------------------

REAL = {
    "sarif": SARIF,
    "cyclonedx": CDX_VULN_JSON,
    "spdx": SPDX,
    "osv": OSV,
}


@pytest.mark.parametrize(
    "name,data",
    [
        *REAL.items(),
        ("cyclonedx", CDX_VULN_XML),
        ("cyclonedx", CDX_SBOM_JSON),
        ("cyclonedx", CDX_SBOM_XML),
    ],
)
def test_each_real_file_is_detected_as_itself_with_high_confidence(name: str, data: bytes) -> None:
    found = detect(data[:4096])
    assert found and found[0][0].name == name and found[0][1] >= 0.9
    assert all(conf < 0.9 for parser, conf in found if parser.name != name)  # no rival is confident


def test_detection_of_nothing_in_particular_finds_nothing() -> None:
    for junk in (b"", b"hello", b"\x00\x01\x02", b"{}", b"[]", b"<html></html>"):
        assert [c for _, c in detect(junk) if c >= 0.9] == []


# --- properties over mutated and truncated real files ---------------------------------------------

FILES = {
    "sarif": SARIF,
    "cyclonedx-json": CDX_VULN_JSON,
    "cyclonedx-xml": CDX_VULN_XML,
    "spdx": SPDX,
    "osv": OSV,
}
PARSER_FOR = {"sarif": "sarif", "cyclonedx-json": "cyclonedx", "cyclonedx-xml": "cyclonedx",
              "spdx": "spdx", "osv": "osv"}  # fmt: skip


@settings(max_examples=150, deadline=None)
@given(st.sampled_from(sorted(FILES)), st.floats(min_value=0.0, max_value=0.999))
def test_no_strict_prefix_of_a_real_report_ever_reads_as_a_complete_one(
    which: str, fraction: float
) -> None:
    """The property reimport's safety rests on: a file cut off anywhere is an *error*, never a
    smaller-but-valid report that would close everything past the cut."""
    raw = FILES[which].rstrip()
    cut = int(len(raw) * fraction)
    r = run_parser_on_bytes(get_parser(PARSER_FOR[which]), raw[:cut])
    assert not r.complete or (cut == 0 and r.findings == []), (which, cut)


@settings(max_examples=250, deadline=None)
@given(
    st.sampled_from(sorted(FILES)),
    st.lists(
        st.tuples(st.integers(min_value=0, max_value=10**9), st.integers(0, 255)), max_size=12
    ),
    st.integers(min_value=0, max_value=10**9),
)
def test_mutated_real_reports_never_raise(
    which: str, flips: list[tuple[int, int]], insert_at: int
) -> None:
    data = bytearray(FILES[which])
    for pos, value in flips:
        data[pos % len(data)] = value
    data[insert_at % len(data) : insert_at % len(data)] = b'"\x00<![CDATA[{[['
    r = run_parser_on_bytes(get_parser(PARSER_FOR[which]), bytes(data))  # must not raise
    assert r.complete or r.error


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=2048))
def test_arbitrary_bytes_never_raise_in_any_parser_or_in_detection(blob: bytes) -> None:
    detect(blob)
    for name in ("sarif", "cyclonedx", "spdx", "osv"):
        r = run_parser_on_bytes(get_parser(name), blob)
        assert r.complete or r.error
