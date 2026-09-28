import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.scan import scan

FIXTURE = Path(__file__).parent.parent / "fixtures" / "vuln-py"


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _assert_all_ok(tool_status: dict[str, dict[str, Any]], *tools: str) -> None:
    """`{t: v["status"] for t, v in ...} == {...}` (the previous shape of this assertion) drops
    `error` -- the real container stderr `core/scan.py`'s `_execute_tool` already captured -- before
    the comparison, so a CI-only "trivy: error" failure had no way to say *why* short of a second
    person reading this file's diff by hand. This is the one thing that class of failure is
    missing, not a fix for it: these Docker-sandboxed tests are real infrastructure (see
    `docs/v2-week34-verification.md` and `docs/v2-week35-verification.md` for two prior,
    unreproduced-locally occurrences), reproducible only on a CI runner's actual resource
    constraints, not something to paper over here."""
    statuses = {t: tool_status[t]["status"] for t in tools}
    bad = {
        t: tool_status[t].get("error", "(no error detail)") for t in tools if statuses[t] != "ok"
    }
    assert not bad, f"tool(s) not ok: {bad}"


#: Real, CI-only infrastructure flakiness (see `_assert_all_ok`'s docstring), not a code path:
#: retrying still fails a genuine regression, since the code doesn't change between attempts.
_flaky = pytest.mark.flaky(reruns=2, reruns_delay=3)


@_flaky
@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_bandit_end_to_end() -> None:
    r = scan(FIXTURE, ["bandit"])
    _assert_all_ok(r.tool_status, "bandit")
    assert {x for f in r.findings for x in f.evidence.rule_ids.get("bandit", [])} >= {
        "B608",
        "B602",
    }


@_flaky
@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_all_tools_end_to_end_and_secret_never_leaks() -> None:
    r = scan(FIXTURE, ["bandit", "semgrep", "gitleaks"])
    _assert_all_ok(r.tool_status, "bandit", "semgrep", "gitleaks")
    reporters = {t for f in r.findings for t in f.evidence.reported_by}
    assert reporters == {"bandit", "semgrep", "gitleaks"}
    assert "8f3b9c1d7e2a4f6b" not in str([f.to_dict() for f in r.findings])


DEPS = Path(__file__).parent.parent / "fixtures" / "vuln-deps"


@_flaky
@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_sca_iac_and_container_tools_end_to_end() -> None:
    r = scan(DEPS, ["trivy", "osv-scanner"])
    _assert_all_ok(r.tool_status, "trivy", "osv-scanner")
    cats = {f.taxonomy.category.value for f in r.findings}
    assert {"sca", "iac", "container"} <= cats
    lodash = {
        t
        for f in r.findings
        if f.package and f.package.name == "lodash" and "CVE-2018-16487" in f.taxonomy.cve
        for t in f.evidence.reported_by
    }
    assert lodash == {"trivy", "osv-scanner"}  # both tools independently found it


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_sandbox_has_no_network_and_readonly_rootfs() -> None:
    def sh(cmd: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
             "--user=10001:10001", "--entrypoint", "sh", "bulwark/bandit:1.7.10", "-c", cmd],
            capture_output=True, text=True,
        )  # fmt: skip

    assert (
        sh(
            "python -c \"import urllib.request as u; u.urlopen('http://1.1.1.1', timeout=3)\""
        ).returncode
        != 0
    )
    assert sh("touch /etc/pwned").returncode != 0
