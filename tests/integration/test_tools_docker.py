import shutil
import subprocess
from pathlib import Path

import pytest

from core.scan import scan

FIXTURE = Path(__file__).parent.parent / "fixtures" / "vuln-py"


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_bandit_end_to_end() -> None:
    r = scan(FIXTURE, ["bandit"])
    assert r.tool_status["bandit"]["status"] == "ok"
    assert {x for f in r.findings for x in f.evidence.rule_ids.get("bandit", [])} >= {
        "B608",
        "B602",
    }


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_all_tools_end_to_end_and_secret_never_leaks() -> None:
    r = scan(FIXTURE, ["bandit", "semgrep", "gitleaks"])
    assert {t: v["status"] for t, v in r.tool_status.items()} == {
        "bandit": "ok",
        "semgrep": "ok",
        "gitleaks": "ok",
    }
    reporters = {t for f in r.findings for t in f.evidence.reported_by}
    assert reporters == {"bandit", "semgrep", "gitleaks"}
    assert "8f3b9c1d7e2a4f6b" not in str([f.to_dict() for f in r.findings])


DEPS = Path(__file__).parent.parent / "fixtures" / "vuln-deps"


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_sca_iac_and_container_tools_end_to_end() -> None:
    r = scan(DEPS, ["trivy", "osv-scanner"])
    assert {t: v["status"] for t, v in r.tool_status.items()} == {
        "trivy": "ok",
        "osv-scanner": "ok",
    }
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
