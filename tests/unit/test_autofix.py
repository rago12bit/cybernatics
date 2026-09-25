from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core.adapters.semgrep import SemgrepAdapter
from core.correlation import correlate
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.sarif import _patch_from_fixes, parse_sarif

LINE = "    subprocess.call(cmd, shell=True)"


def fix(new: str, sc: int = 32, ec: int = 36, line: int = 3) -> dict:
    return {
        "artifactChanges": [
            {
                "artifactLocation": {"uri": "/src/app.py"},
                "replacements": [
                    {
                        "deletedRegion": {
                            "startLine": line,
                            "endLine": line,
                            "startColumn": sc,
                            "endColumn": ec,
                        },
                        "insertedContent": {"text": new},
                    }
                ],
            }
        ],
    }


def result(fixes: list | None, snippet: str = LINE, end: int = 3) -> dict:
    return {
        "ruleId": "r",
        "message": {"text": "m"},
        "level": "warning",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/src/app.py"},
                       "region": {"startLine": 3, "endLine": end, "snippet": {"text": snippet}}}}],
        "fixes": fixes,
    }  # fmt: skip


def patch(fixes: list | None, snippet: str = LINE, end: int = 3) -> str | None:
    return _patch_from_fixes(result(fixes, snippet, end), "app.py", 3, end, snippet)


def test_semgrep_style_fix_becomes_a_one_line_unified_diff() -> None:
    p = patch([fix("    subprocess.call(cmd, shell=False)")])
    assert p == (
        "--- a/app.py\n+++ b/app.py\n@@ -3,1 +3,1 @@\n"
        "-    subprocess.call(cmd, shell=True)\n+    subprocess.call(cmd, shell=False)\n"
    )


@pytest.mark.skipif(shutil.which("patch") is None, reason="needs the patch tool")
def test_patch_applies_with_the_real_patch_tool(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(f"import subprocess\ndef run(cmd):\n{LINE}\n    return 1\n")
    p = patch([fix("    subprocess.call(cmd, shell=False)")])
    assert p
    (tmp_path / "x.diff").write_text(p)
    subprocess.run(["patch", "-p1", "-i", "x.diff"], cwd=tmp_path, check=True, capture_output=True)
    assert "shell=False" in (tmp_path / "app.py").read_text()


@pytest.mark.parametrize(
    "why,fixes,kw",
    [
        ("no fixes", None, {}),
        ("two fixes", [fix("    subprocess.call(cmd, shell=False)")] * 2, {}),
        ("unchanged text", [fix(LINE)], {}),
        ("multi-line insert", [fix("a\n    b")], {}),
        ("prefix not preserved", [fix("    other.call(cmd, shell=False)")], {}),
        ("suffix not preserved", [fix("    subprocess.call(cmd, shell=False")], {}),
        ("bad columns", [fix("    subprocess.call(cmd, shell=False)", sc=40, ec=36)], {}),
        ("fix on another line", [fix("    subprocess.call(cmd, shell=False)", line=9)], {}),
        ("multi-line finding", [fix("    subprocess.call(cmd, shell=False)")], {"end": 4}),
        ("empty insert", [fix("")], {}),
    ],
)
def test_unsafe_or_odd_fixes_are_dropped(why: str, fixes: list | None, kw: dict) -> None:
    assert patch(fixes, **kw) is None, why


def test_malformed_fix_never_raises() -> None:
    assert patch([{"artifactChanges": "nope"}]) is None
    assert patch([{}]) is None


def test_parse_sarif_carries_the_patch_onto_the_finding() -> None:
    doc = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [result([fix("    subprocess.call(cmd, shell=False)")])],
            }
        ]
    }
    [f] = parse_sarif(json.dumps(doc).encode(), tool="semgrep", category=Category.SAST)
    assert f.remediation.suggested_patch and "shell=False" in f.remediation.suggested_patch
    assert f.remediation.generated_by == "static"


def test_semgrep_asks_for_fixes_without_modifying_files() -> None:
    cmd = SemgrepAdapter().build_command(Path("/t"), Path("/o.sarif"))
    assert "--autofix" in cmd and "--dryrun" in cmd


def _f(tool: str, patch_text: str | None) -> Finding:
    f = Finding(id=f"{tool}:1", title=tool, description="", location=Location("a.py", 3, 3, LINE),
                taxonomy=Taxonomy(Category.SAST, cwe=("CWE-78",)))  # fmt: skip
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = [tool]
    f.evidence.rule_ids = {tool: ["r"]}
    f.remediation.suggested_patch = patch_text
    return f


def test_merged_finding_keeps_a_patch_from_any_reporting_tool() -> None:
    merged, _ = correlate([_f("bandit", None), _f("semgrep", "PATCH")])
    assert len(merged) == 1 and merged[0].remediation.suggested_patch == "PATCH"
