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
