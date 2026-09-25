"""Each tier-2 scanner run for real in its sandbox on the repository's fixtures."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from core.adapters.dockle import IMAGE_ARCHIVE
from core.scan import ADAPTERS, scan

FIX = Path(__file__).parent.parent / "fixtures"


def _ready(*tools: str) -> bool:
    if (
        not shutil.which("docker")
        or subprocess.run(["docker", "info"], capture_output=True).returncode != 0
    ):
        return False
    return all(
        subprocess.run(
            ["docker", "image", "inspect", ADAPTERS[t].spec.image], capture_output=True
        ).returncode
        == 0
        for t in tools
    )


def test_gosec_finds_injection_including_taint_analysis() -> None:
    if not _ready("gosec"):
        pytest.skip("gosec image not built")
    r = scan(FIX / "vuln-go", ["gosec"])
    rules = {
        rule for f in r.findings for rule in f.evidence.rule_ids["gosec"]
    }  # correlation may merge rules
    assert {"G202", "G204", "G401"} <= rules
    assert {
        "G701",
        "G702",
        "G705",
    } & rules, "taint analysis disappeared: /tmp is probably too small for the Go build cache"
    assert r.tool_status["gosec"]["status"] == "ok"


def test_checkov_reads_its_own_output_file_name() -> None:
    if not _ready("checkov"):
        pytest.skip("checkov image not built")
    r = scan(FIX / "vuln-deps", ["checkov"])
    assert r.tool_status["checkov"]["status"] == "ok"
    assert any(f.evidence.rule_ids["checkov"][0].startswith("CKV_DOCKER") for f in r.findings)
    assert all(f.taxonomy.category.value == "iac" for f in r.findings)


def test_grype_agrees_with_trivy_and_osv_on_the_same_dependency() -> None:
    if not _ready("grype", "trivy", "osv-scanner"):
        pytest.skip("images not built")
    r = scan(FIX / "vuln-deps", ["trivy", "osv-scanner", "grype"])
    lodash = [f for f in r.findings if f.package and f.package.name == "lodash"]
    assert lodash and any(
        "grype" in f.evidence.reported_by and f.evidence.agreement_count >= 2 for f in lodash
    )


def test_dockle_lints_a_saved_image() -> None:
    if (
        not _ready("dockle")
        or subprocess.run(
            ["docker", "image", "inspect", "alpine:3.20"], capture_output=True
        ).returncode
        != 0
    ):
        pytest.skip("dockle image or alpine:3.20 not available")
    with tempfile.TemporaryDirectory() as t:
        subprocess.run(
            ["docker", "save", "--output", f"{t}/{IMAGE_ARCHIVE}", "alpine:3.20"], check=True
        )
        r = scan(Path(t), ["dockle"])
    assert r.tool_status["dockle"]["status"] == "ok"
    assert "CIS-DI-0001" in {f.evidence.rule_ids["dockle"][0] for f in r.findings}
