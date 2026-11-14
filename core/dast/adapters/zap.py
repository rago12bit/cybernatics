"""OWASP ZAP baseline scan: the passive tier every DAST campaign runs, active or not (Week 49 task
3, plan §22.4). Baseline mode only spiders and passively observes traffic -- it never sends an
attack payload -- which is exactly why it's safe to run against any ownership-verified target
without the stricter gating an active scan needs.

Passing `proxy` (Week 49b, plan §22.4 follow-up) points ZAP's own outbound HTTP client at the
campaign's egress proxy via `network.connection.httpProxy.{enabled,host,port}` -- confirmed live
against a real running `core.dast.proxy.BackgroundProxy` to be the config ZAP's Network add-on
actually reads at daemon start (`-config network.connectionParam.*`, the legacy pre-add-on key
family, is silently ignored by the version this image ships). Live-verified consequence worth
keeping in mind when reading a campaign's audit log: ZAP's own background "check for updates" and
telemetry calls (`news.zaproxy.org`, `cfu.zaproxy.org`, `tel.zaproxy.org`) go out on the same proxy
and get correctly refused, since they aren't the verified target -- that's the scope enforcement
working as designed, not a scan failure, and the baseline scan itself completes and reports findings
normally regardless.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from core.config import scratch_dir
from core.dast.mapping import zap_alert_findings
from core.dast.proxy import ProxyConfig
from core.models import Finding
from core.sandbox.output import OutputRefused, read_output

ZAP_IMAGE = (  # 2.17.0, what `stable` pointed to on 2026-10-14
    "ghcr.io/zaproxy/zaproxy:2.17.0"
    "@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2"
)


#: A baseline report is a few hundred kilobytes; this is far above one.
MAX_REPORT_BYTES = 64 * 1024 * 1024

#: What every container Bulwark starts carries (core.sandbox.docker_runtime), as far as a scanner
#: that needs the network and a writable home can: no capabilities, no way to gain privileges, and
#: the label `core.maintenance.cleanup_containers` finds an orphan by -- without it a ZAP container
#: whose worker was killed was never cleaned up.
CONTAINER_FLAGS = (
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--label=bulwark.managed=1",
)


class ZapError(Exception):
    pass


def run_zap_baseline(
    target_url: str, *, timeout_s: int = 300, proxy: ProxyConfig | None = None
) -> list[Finding]:
    """Runs `zap-baseline.py` for real in a throwaway container, against `target_url`. `-I` treats
    a WARN-level alert as informational for ZAP's own exit code (it still appears in the JSON report
    at its real risk level) -- a scan that only turned up WARN-level alerts must not be reported as
    "failed," the campaign's finding list is the actual result, not ZAP's own pass/fail verdict."""
    # Under the scratch directory, like every other path a container is given: the host's Docker
    # daemon mounts it, so it must be a path the worker's container and the host both have.
    with tempfile.TemporaryDirectory(prefix="bulwark-zap-", dir=scratch_dir()) as tmp:
        tmp_path = Path(tmp)
        tmp_path.chmod(0o777)  # the zap container runs as its own non-root user, not this one
        name = f"bulwark-zap-{uuid.uuid4().hex[:8]}"
        argv = ["docker", "run", "--rm", "--name", name, *CONTAINER_FLAGS]
        if proxy is not None:
            # See core.dast.adapters.nuclei.run_nuclei for why this flag is unconditional whenever
            # a proxy is configured: host.docker.internal needs it on Linux, and it's a no-op on
            # macOS Docker Desktop where the hostname already resolves.
            argv += ["--add-host", "host.docker.internal:host-gateway"]
        argv += [
            "-v", f"{tmp_path}:/zap/wrk:rw",
            ZAP_IMAGE, "zap-baseline.py",
            "-t", target_url,
            "-J", "report.json",
            "-I",
        ]  # fmt: skip
        if proxy is not None:
            argv += [
                "-z",
                f"-config network.connection.httpProxy.enabled=true "
                f"-config network.connection.httpProxy.host={proxy.host} "
                f"-config network.connection.httpProxy.port={proxy.port}",
            ]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            # Stopping the `docker` client does not stop the container: kill it by name.
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            raise ZapError(f"zap-baseline timed out after {timeout_s}s") from exc
        except FileNotFoundError as exc:
            raise ZapError("docker is not available") from exc
        try:  # the container wrote it: a regular file of a sane size, or nothing is read
            report = read_output(tmp_path / "report.json", MAX_REPORT_BYTES)
        except OutputRefused as exc:
            raise ZapError(f"zap-baseline's report was not readable: {exc}") from exc
        if report is None:
            stderr = proc.stderr.decode("utf-8", errors="replace")[-2000:]
            raise ZapError(f"zap-baseline produced no report (exit {proc.returncode}): {stderr}")
    try:
        data = json.loads(report)
    except ValueError as exc:
        raise ZapError("zap-baseline's report is not JSON") from exc
    if not isinstance(data, dict):
        raise ZapError("zap-baseline's report is not a JSON object")
    return _parse_report(data)


def _parse_report(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            findings.extend(zap_alert_findings(alert, site_name, "zap", reported_by="zap-baseline"))
    return findings
