"""`core.dast.mapping` -- the one reading of a ZAP alert or Nuclei result -- and what it needs from
correlation and fingerprinting to keep DAST findings apart (Week 57, plan §22.4/§42.2).

The correlation tests are regressions for a bug that predates the import work: DAST findings have no
file, line or snippet, so `correlate()` saw every one of them "at the same place" and merged any two
alerts that shared a CWE; and the fingerprint ignored the route, so one alert on fifty URLs was one
Issue. Both were found by feeding a ZAP report to the import path. They fail without the fix.
"""

from __future__ import annotations

import time

import pytest

from core.correlation import correlate, fingerprint
from core.dast.adapters.nuclei import _parse_jsonl
from core.dast.adapters.zap import _parse_report
from core.dast.mapping import (
    cwe_ids,
    network_target,
    nuclei_finding,
    plain_text,
    target_of,
    zap_alert_findings,
)
from core.models import Category, Severity

# --- targets --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Example.com/a/b?x=1#f", ("https://example.com", "/a/b")),
        (
            "https://example.com:443/a",
            ("https://example.com", "/a"),
        ),  # default port is not identity
        ("http://example.com:80", ("http://example.com", "/")),
        ("http://example.com:8080/x", ("http://example.com:8080", "/x")),
        ("https://example.com:8443/x", ("https://example.com:8443", "/x")),
        ("example.com:3306", ("example.com:3306", "/")),  # nuclei network matches: no scheme
        ("10.0.0.5", ("10.0.0.5", "/")),
        ("http://[::1]:8080/x", ("http://[::1]:8080", "/x")),
        ("", ("", "/")),
        ("http://", ("", "/")),
        ("http://host:99999/x", ("", "/")),  # an impossible port is no target, not an exception
        ("http://[bad/x", ("", "/")),
    ],
)
def test_target_of(url: str, expected: tuple[str, str]) -> None:
    assert target_of(url) == expected


def test_network_target_names_the_service_or_the_whole_host() -> None:
    assert network_target("10.0.0.5", "443", "TCP") == ("10.0.0.5", "443/tcp")
    assert network_target("Host.Local", 53, "udp") == ("host.local", "53/udp")
    assert network_target("10.0.0.5", "0") == ("10.0.0.5", "host")  # Nessus: a host-level finding
    assert network_target("10.0.0.5", None) == ("10.0.0.5", "host")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("79", ("CWE-79",)),
        (79, ("CWE-79",)),
        ("cwe-79", ("CWE-79",)),
        ("CWE_79", ("CWE-79",)),
        (["cwe-79", "cwe-89", "CWE-79"], ("CWE-79", "CWE-89")),
        ("-1", ()),  # ZAP's "no CWE" -- once read as CWE-1 by a too-loose pattern
        ("0", ()),
        ("", ()),
        (None, ()),
        (["nvd-cve-other"], ()),  # a real Nuclei template's classification
    ],
)
def test_cwe_ids(raw: object, expected: tuple[str, ...]) -> None:
    assert cwe_ids(raw) == expected


def test_plain_text_strips_markup_and_keeps_paragraphs() -> None:
    assert plain_text("<p>One &amp; two</p><p>Three<br/>four</p>") == "One & two\n\nThree\nfour"
    assert plain_text("already plain") == "already plain"
    assert plain_text(None) == ""


def test_plain_text_is_bounded_on_hostile_markup() -> None:
    """The stdlib HTML parser is not linear on pathological input; the cap is what bounds it."""
    start = time.monotonic()
    out = plain_text("<a " * 5_000_000 + "x")
    assert time.monotonic() - start < 2
    assert len(out) <= 20_000


# --- ZAP ------------------------------------------------------------------------------------------


def _alert(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "pluginid": "10020",
        "alert": "X-Frame-Options Header Not Set",
        "riskcode": "2",
        "confidence": "2",
        "riskdesc": "Medium (Medium)",
        "desc": "<p>No clickjacking protection.</p>",
        "solution": "<p>Send the header.</p>",
        "reference": "<p>https://example.org/a</p><p>https://example.org/b</p>",
        "cweid": "1021",
        "instances": [
            {"uri": "http://t.example/a?q=1", "method": "GET", "param": "x-frame-options"},
            {"uri": "http://t.example/b", "method": "GET"},
        ],
    }
    return {**base, **over}


def test_zap_alert_is_one_finding_per_instance_with_host_and_route() -> None:
    found = zap_alert_findings(_alert(), "http://t.example", "zap")
    assert [(f.location.host, f.location.route) for f in found] == [
        ("http://t.example", "/a"),
        ("http://t.example", "/b"),
    ]
    f = found[0]
    assert f.taxonomy.category is Category.DAST
    assert f.taxonomy.cwe == ("CWE-1021",)
    assert f.scoring.normalized_severity is Severity.MEDIUM
    assert f.scoring.confidence == 0.6
    assert f.remediation.summary == "Send the header."
    assert f.remediation.references == ["https://example.org/a", "https://example.org/b"]
    assert "Parameter: x-frame-options" in f.description and "<p>" not in f.description


def test_zap_unknown_riskcode_is_info_and_reported() -> None:
    seen: list[str] = []
    (f,) = zap_alert_findings(
        _alert(riskcode="9", instances=[{"uri": "http://t/"}]), "http://t", "zap", seen.append
    )
    assert f.scoring.normalized_severity is Severity.INFO
    assert seen == ["riskcode 9"]


def test_zap_instance_without_a_uri_falls_back_to_the_site() -> None:
    (f,) = zap_alert_findings(_alert(instances=[{}]), "https://t.example:8443", "zap")
    assert (f.location.host, f.location.route) == ("https://t.example:8443", "/")


# --- Nuclei ---------------------------------------------------------------------------------------


def _nuclei(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "template-id": "tech-detect",
        "info": {"name": "Tech", "severity": "info", "classification": {"cwe-id": ["cwe-200"]}},
        "matched-at": "https://t.example/",
        "matcher-name": "nginx",
    }
    return {**base, **over}


def test_nuclei_matcher_is_part_of_the_rule_so_two_detections_are_two_findings() -> None:
    a = nuclei_finding(_nuclei(), "a")
    b = nuclei_finding(_nuclei(**{"matcher-name": "php"}), "b")
    assert a and b
    assert a.evidence.rule_ids == {"nuclei": ["tech-detect:nginx"]}
    assert a.fingerprint == b.fingerprint == ""  # identity comes from correlate(), not the parser
    assert fingerprint(a) != fingerprint(b)


def test_nuclei_severity_words() -> None:
    seen: list[str] = []
    ok = nuclei_finding(
        _nuclei(info={"name": "x", "severity": "critical"}), "a", on_unknown=seen.append
    )
    unknown = nuclei_finding(
        _nuclei(info={"name": "x", "severity": "unknown"}), "b", on_unknown=seen.append
    )
    odd = nuclei_finding(
        _nuclei(info={"name": "x", "severity": "banana"}), "c", on_unknown=seen.append
    )
    assert ok and unknown and odd
    assert ok.scoring.normalized_severity is Severity.CRITICAL
    assert unknown.scoring.normalized_severity is Severity.INFO
    assert odd.scoring.normalized_severity is Severity.INFO
    assert seen == ["banana"]  # Nuclei's own "unknown" is a defined severity; "banana" is not


def test_nuclei_cvss_is_taken_only_when_it_is_v3() -> None:
    v3 = nuclei_finding(
        _nuclei(info={"name": "x", "severity": "high",
                      "classification": {"cvss-score": 7.5, "cvss-metrics": "CVSS:3.1/AV:N"}}),
        "a",
    )  # fmt: skip
    v4 = nuclei_finding(
        _nuclei(info={"name": "x", "severity": "high",
                      "classification": {"cvss-score": 8.7, "cvss-metrics": "CVSS:4.0/AV:N"}}),
        "b",
    )  # fmt: skip
    assert v3 and v4 and v3.scoring.cvss_v3_1 == 7.5 and v4.scoring.cvss_v3_1 is None


def test_nuclei_record_that_is_not_a_result_is_none() -> None:
    assert nuclei_finding({"hello": "world"}, "x") is None
    assert nuclei_finding({"info": "not a dict"}, "x") is None


def test_nuclei_null_classification_fields_do_not_break_a_record() -> None:
    """Real Nuclei output writes `"cve-id": null` (tests/golden/ingest/defectdojo/nuclei)."""
    f = nuclei_finding(
        _nuclei(info={"name": "x", "severity": "low",
                      "classification": {"cve-id": None, "cwe-id": None}}),
        "a",
    )  # fmt: skip
    assert f and f.taxonomy.cve == () and f.taxonomy.cwe == ()


# --- the native adapters read through the same functions ------------------------------------------


def test_native_and_imported_zap_alert_are_the_same_issue() -> None:
    """Run natively and uploaded later, one alert must be one Issue: the fingerprint carries rule,
    host and route -- not the tool's name, which differs ("zap-baseline" vs "zap")."""
    report = {"site": [{"@name": "http://t.example", "alerts": [_alert()]}]}
    native, _ = correlate(_parse_report(report))
    imported, _ = correlate(zap_alert_findings(_alert(), "http://t.example", "zap"))
    assert {f.fingerprint for f in native} == {f.fingerprint for f in imported}
    assert native[0].evidence.reported_by == ["zap-baseline"]


def test_native_nuclei_adapter_keeps_working_on_a_jsonl_stream() -> None:
    line = '{"template-id":"x","info":{"name":"X","severity":"low"},"matched-at":"http://t/a"}'
    found = _parse_jsonl(f"progress...\n{line}\n\n{line}\n")
    assert len(found) == 2 and found[0].id == found[1].id  # identical records: identical ids


# --- correlation and fingerprint: the regressions -------------------------------------------------


def _zap(plugin: str, title: str, cwe: str, *uris: str) -> list:
    return zap_alert_findings(
        _alert(pluginid=plugin, alert=title, cweid=cwe, instances=[{"uri": u} for u in uris]),
        "http://t.example",
        "zap",
    )


def test_two_different_alerts_sharing_a_cwe_are_not_merged() -> None:
    """ZAP's X-Frame-Options and CSP rules are both CWE-1021. They were folded into one finding
    (and which rule survived depended on input order)."""
    found = _zap("10020", "X-Frame-Options Header Not Set", "1021", "http://t.example/a")
    found += _zap("10038", "CSP Header Not Set", "1021", "http://t.example/a")
    merged, stats = correlate(found)
    assert stats.raw == stats.unique == 2
    assert {f.title for f in merged} == {"X-Frame-Options Header Not Set", "CSP Header Not Set"}


def test_the_same_alert_on_two_routes_is_two_issues() -> None:
    merged, _ = correlate(_zap("10020", "XFO", "1021", "http://t.example/a", "http://t.example/b"))
    assert len({f.fingerprint for f in merged}) == 2


def test_the_same_route_on_two_hosts_is_two_issues() -> None:
    a = zap_alert_findings(_alert(instances=[{"uri": "https://staging.example/login"}]), "", "zap")
    b = zap_alert_findings(_alert(instances=[{"uri": "https://www.example/login"}]), "", "zap")
    merged, _ = correlate([*a, *b])
    assert len({f.fingerprint for f in merged}) == 2


def test_the_same_alert_at_the_same_place_keeps_its_identity_between_runs() -> None:
    first, _ = correlate(_zap("10020", "XFO", "1021", "http://t.example/a?session=1"))
    second, _ = correlate(_zap("10020", "XFO", "1021", "http://t.example/a?session=2"))
    assert first[0].fingerprint == second[0].fingerprint  # the query string is not identity


def test_dast_correlation_is_not_quadratic() -> None:
    """Every DAST finding used to share one candidate bucket (file "")."""
    uris = [f"http://t.example/p{i}" for i in range(6000)]
    start = time.monotonic()
    merged, stats = correlate(_zap("10020", "XFO", "1021", *uris))
    assert stats.unique == 6000 and len(merged) == 6000
    assert time.monotonic() - start < 10


def test_one_alert_on_three_urls_is_three_issues_not_one() -> None:
    """The third layer of the same bug: `core.issues.fallback_key` is deliberately path-free (so a
    moved function is not "new"), and for DAST it matched every URL an alert fired on to the first
    Issue made for it. Found by importing a real ZAP report: 130 findings became 15 Issues."""
    from core.issues import sync

    merged, _ = correlate(
        _zap(
            "10020", "XFO", "1021", "http://t.example/a", "http://t.example/b", "http://t.example/c"
        )
    )
    result = sync(merged, [], lambda: __import__("uuid").uuid4().hex)
    assert result.new_count == 3 and len({u.issue_id for u in result.updates}) == 3
