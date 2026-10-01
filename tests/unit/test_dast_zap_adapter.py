"""core.dast.adapters.zap's report parsing (Week 49 task 3, plan §22.4), against a hand-built ZAP
JSON report shaped exactly like a real one (see tests/integration/test_dast_adapters_live.py for the
real `docker run` + real report this was modeled on)."""

from __future__ import annotations

from core.dast.adapters.zap import _parse_report
from core.models import Category, Severity


def _report(*alerts: dict) -> dict:
    return {"site": [{"@name": "http://example.com", "alerts": list(alerts)}]}


def test_parses_a_simple_alert_into_a_dast_finding() -> None:
    findings = _parse_report(
        _report(
            {
                "pluginid": "10038",
                "name": "Content Security Policy (CSP) Header Not Set",
                "desc": "no CSP",
                "cweid": "693",
                "riskcode": "2",
                "riskdesc": "Medium (High)",
                "solution": "set a CSP",
                "reference": "https://example.org/csp\nhttps://example.org/csp2",
                "instances": [{"uri": "http://example.com/"}],
            }
        )
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.taxonomy.category is Category.DAST
    assert f.taxonomy.cwe == ("CWE-693",)
    assert f.scoring.normalized_severity is Severity.MEDIUM
    assert f.location.route == "/"
    assert f.remediation.references == ["https://example.org/csp", "https://example.org/csp2"]


def test_one_alert_fans_out_into_one_finding_per_instance() -> None:
    findings = _parse_report(
        _report(
            {
                "pluginid": "10049",
                "name": "Storable and Cacheable Content",
                "riskcode": "0",
                "instances": [
                    {"uri": "http://example.com/"},
                    {"uri": "http://example.com/sitemap.xml"},
                ],
            }
        )
    )
    assert {f.location.route for f in findings} == {"/", "/sitemap.xml"}
    assert len({f.id for f in findings}) == 2


def test_alerts_sharing_a_plugin_id_and_uri_get_distinct_ids() -> None:
    """A real live scan found this: ZAP's rule 90004 reports three alerts (COEP/COOP/CORP) that all
    share pluginid 90004 against the same uri -- an id keyed on (pluginid, uri) alone collides and
    silently drops two of the three findings when written to the DB's (scan_id, finding_id) unique
    constraint. Regression test for that real bug."""
    findings = _parse_report(
        _report(
            {
                "pluginid": "90004",
                "name": "Cross-Origin-Embedder-Policy Header Missing or Invalid",
                "riskcode": "1",
                "instances": [{"uri": "http://example.com/"}],
            },
            {
                "pluginid": "90004",
                "name": "Cross-Origin-Opener-Policy Header Missing or Invalid",
                "riskcode": "1",
                "instances": [{"uri": "http://example.com/"}],
            },
            {
                "pluginid": "90004",
                "name": "Cross-Origin-Resource-Policy Header Missing or Invalid",
                "riskcode": "1",
                "instances": [{"uri": "http://example.com/"}],
            },
        )
    )
    assert len(findings) == 3
    assert len({f.id for f in findings}) == 3


def test_a_negative_cweid_means_no_cwe() -> None:
    findings = _parse_report(
        _report({"pluginid": "1", "name": "x", "riskcode": "0", "cweid": "-1", "instances": [{}]})
    )
    assert findings[0].taxonomy.cwe == ()


def test_unknown_riskcode_defaults_to_info() -> None:
    findings = _parse_report(
        _report({"pluginid": "1", "name": "x", "riskcode": "99", "instances": [{"uri": "x"}]})
    )
    assert findings[0].scoring.normalized_severity is Severity.INFO


def test_an_alert_with_no_instances_falls_back_to_the_site_itself() -> None:
    findings = _parse_report(_report({"pluginid": "1", "name": "x", "riskcode": "0"}))
    assert len(findings) == 1
    assert findings[0].location.route == "/"
