"""core.dast.adapters.zap's report parsing (Week 49 task 3, plan §22.4), against a hand-built ZAP
JSON report shaped exactly like a real one (see tests/integration/test_dast_adapters_live.py for the
real `docker run` + real report this was modeled on), and its egress-proxy wiring (Week 49b, plan
§22.4 follow-up)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from core.dast.adapters import zap
from core.dast.adapters.zap import _parse_report
from core.dast.proxy import ProxyConfig
from core.models import Category, Severity


def _fake_run_writing_empty_report(monkeypatch: Any) -> dict[str, list[str]]:
    """`run_zap_baseline` requires a report.json to exist in the mounted tmp dir or it raises --
    these argv-focused tests don't care about the scan result, only what argv it built, so the fake
    just writes a minimal valid report wherever `-v <tmp>:/zap/wrk:rw` points."""
    captured: dict[str, list[str]] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        captured["argv"] = argv
        host_dir = argv[argv.index("-v") + 1].split(":")[0]
        (Path(host_dir) / "report.json").write_text('{"site": []}')
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(zap.subprocess, "run", fake_run)
    return captured


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


def test_without_a_proxy_the_argv_has_no_proxy_config_or_add_host(monkeypatch: Any) -> None:
    captured = _fake_run_writing_empty_report(monkeypatch)
    zap.run_zap_baseline("https://example.com/")
    assert "-z" not in captured["argv"]
    assert "--add-host" not in captured["argv"]


def test_with_a_proxy_the_argv_configures_zaps_own_httpproxy_option(monkeypatch: Any) -> None:
    """Regression test for a real finding: ZAP's Network add-on reads its upstream-proxy setting
    from `network.connection.httpProxy.*`, not the legacy `network.connectionParam.proxyChain*` key
    family -- confirmed live by inspecting the add-on's own compiled option keys and then watching a
    real `zap-baseline.py` run actually route through a real `BackgroundProxy` only once the correct
    keys were used. See the module docstring."""
    captured = _fake_run_writing_empty_report(monkeypatch)
    zap.run_zap_baseline(
        "https://example.com/", proxy=ProxyConfig(host="host.docker.internal", port=4567)
    )
    argv = captured["argv"]
    assert "--add-host" in argv
    assert argv[argv.index("--add-host") + 1] == "host.docker.internal:host-gateway"
    z_index = argv.index("-z")
    z_value = argv[z_index + 1]
    assert "network.connection.httpProxy.enabled=true" in z_value
    assert "network.connection.httpProxy.host=host.docker.internal" in z_value
    assert "network.connection.httpProxy.port=4567" in z_value
