"""`bulwark supply-chain analyze` (plan §20.5): typosquat detection and OpenSSF Scorecard for
direct dependencies, run over a previously-generated SBOM."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "bom-ref": "root",
            "name": "myproject",
            "version": "1.0.0",
            "purl": "pkg:npm/myproject@1.0.0",
        },
        {"bom-ref": "a", "name": "reqeusts", "version": "1.0.0", "purl": "pkg:pypi/reqeusts@1.0.0"},
        {
            "bom-ref": "b",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        },
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}],
}


def test_analyze_writes_a_report_with_typosquats_and_dependency_sets(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(SBOM))
    out = tmp_path / "report.json"
    r = runner.invoke(
        app,
        ["supply-chain", "analyze", "--sbom", str(sbom), "--output", str(out), "--no-scorecard"],
    )
    assert r.exit_code == 0, r.output
    report = json.loads(out.read_text())
    assert len(report["typosquats"]) == 1
    assert "reqeusts" in report["typosquats"][0]["title"]
    assert report["scorecard"] == {}  # --no-scorecard: no network calls made
    assert set(report["direct_dependencies"]) == {
        "pkg:pypi/reqeusts@1.0.0",
        "pkg:pypi/requests@2.31.0",
    }


def test_analyze_exits_2_on_an_invalid_sbom(tmp_path: Path) -> None:
    sbom = tmp_path / "bad.json"
    sbom.write_text("not json")
    r = runner.invoke(
        app,
        ["supply-chain", "analyze", "--sbom", str(sbom), "--output", str(tmp_path / "out.json")],
    )
    assert r.exit_code == 2
