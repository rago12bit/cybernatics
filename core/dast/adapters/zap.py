"""OWASP ZAP baseline scan: the passive tier every DAST campaign runs, active or not (Week 49 task
3, plan §22.4). Baseline mode only spiders and passively observes traffic -- it never sends an
attack payload -- which is exactly why it's safe to run against any ownership-verified target
without the stricter gating an active scan needs.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

_RISK_TO_SEVERITY = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}


class ZapError(Exception):
    pass


def run_zap_baseline(target_url: str, *, timeout_s: int = 300) -> list[Finding]:
    """Runs `zap-baseline.py` for real in a throwaway container, against `target_url`. `-I` treats
    a WARN-level alert as informational for ZAP's own exit code (it still appears in the JSON report
    at its real risk level) -- a scan that only turned up WARN-level alerts must not be reported as
    "failed," the campaign's finding list is the actual result, not ZAP's own pass/fail verdict."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        tmp_path.chmod(0o777)  # the zap container runs as its own non-root user, not this one
        argv = [
            "docker", "run", "--rm",
            "-v", f"{tmp_path}:/zap/wrk:rw",
            ZAP_IMAGE, "zap-baseline.py",
            "-t", target_url,
            "-J", "report.json",
            "-I",
        ]  # fmt: skip
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ZapError(f"zap-baseline timed out after {timeout_s}s") from exc
        except FileNotFoundError as exc:
            raise ZapError("docker is not available") from exc
        report_path = tmp_path / "report.json"
        if not report_path.exists():
            stderr = proc.stderr.decode("utf-8", errors="replace")[-2000:]
            raise ZapError(f"zap-baseline produced no report (exit {proc.returncode}): {stderr}")
        data = json.loads(report_path.read_text())
    return _parse_report(data)


def _parse_report(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            cwe_id = str(alert.get("cweid", "-1"))
            cwe = (f"CWE-{cwe_id}",) if cwe_id not in ("-1", "0", "") else ()
            severity = _RISK_TO_SEVERITY.get(str(alert.get("riskcode", "0")), Severity.INFO)
            plugin_id = str(alert.get("pluginid", "0"))
            references = [r for r in alert.get("reference", "").split("\n") if r.strip()]
            instances = alert.get("instances") or [{"uri": site_name}]
            alert_name = alert.get("name", "")
            for instance in instances:
                uri = instance.get("uri", site_name)
                route = urlsplit(uri).path or "/"
                # Plugin id alone is not a unique key: ZAP's own 90004 rule reports three distinct
                # alerts (COEP/COOP/CORP, each a separate `alert` entry) that all share pluginid
                # 90004 against the same uri -- found by running a real scan, not by inspection; the
                # alert's name is what actually distinguishes them.
                digest = hashlib.sha256(f"{alert_name}|{uri}".encode()).hexdigest()[:12]
                findings.append(
                    Finding(
                        id=f"zap-{plugin_id}-{digest}",
                        title=alert.get("name", "ZAP finding"),
                        description=alert.get("desc", ""),
                        location=Location(path="", start_line=0, end_line=0, route=route),
                        taxonomy=Taxonomy(category=Category.DAST, cwe=cwe),
                        scoring=Scoring(
                            normalized_severity=severity,
                            native_severity={"zap": alert.get("riskdesc", "")},
                        ),
                        evidence=Evidence(
                            reported_by=["zap-baseline"], rule_ids={"zap-baseline": [plugin_id]}
                        ),
                        remediation=Remediation(
                            summary=alert.get("solution", ""),
                            references=references,
                            generated_by="static",
                        ),
                    )
                )
    return findings
