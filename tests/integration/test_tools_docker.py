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
    assert {f.evidence.rule_ids["bandit"] for f in r.findings} >= {"B608", "B602"}


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
