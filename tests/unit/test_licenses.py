from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("gen_licenses", ROOT / "scripts" / "gen-licenses.py")
assert spec and spec.loader
gl = importlib.util.module_from_spec(spec)
sys.modules["gen_licenses"] = gl
spec.loader.exec_module(gl)


class Meta(dict):  # type: ignore[type-arg]
    def get_all(self, key: str) -> list[str] | None:
        return self.get(key)  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    "meta,expected",
    [
        ({"License-Expression": "MIT"}, "MIT"),
        ({"License": "Apache-2.0"}, "Apache-2.0"),
        (
            {"License": "x" * 200, "Classifier": ["License :: OSI Approved :: BSD License"]},
            "BSD License",
        ),
        (
            {
                "License": "multi\nline text",
                "Classifier": ["License :: OSI Approved :: MIT License"],
            },
            "MIT License",
        ),
        ({}, "UNKNOWN"),
    ],
)
def test_license_strings_are_normalised_or_reported_unknown(meta: dict, expected: str) -> None:  # type: ignore[type-arg]
    assert gl.norm_license(Meta(meta)) == expected


def test_policy_denies_network_copyleft_and_unknown_but_allows_weak_copyleft() -> None:
    py = {
        "good": ("1", "MIT"),
        "lg": ("1", "LGPL-3.0-only"),
        "bad": ("1", "AGPL-3.0-or-later"),
        "mystery": ("1", "UNKNOWN"),
    }
    npm = {
        "web": [
            ("a", "1", "MIT", False),
            ("b", "1", "SSPL-1.0", False),
            ("devonly", "1", "AGPL-3.0", True),
            ("c", "1", "UNKNOWN", True),
        ]
    }
    problems = gl.policy_problems(py, npm)
    text = "\n".join(problems)
    assert (
        "bad 1: denied" in text and "mystery 1: license could not" in text and "b 1: denied" in text
    )
    assert (
        "lg" not in text and "devonly" not in text
    )  # weak copyleft passes; a dev-only tool is not shipped
    assert "npm (web) c 1: license could not" in text  # but an unknown license is always a problem


def test_every_scanner_and_docker_directory_has_a_license_entry() -> None:
    assert gl.coverage_problems() == []


def test_a_new_scanner_without_an_entry_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(gl.TOOLS, "grype", gl.TOOLS["grype"])
    monkeypatch.delitem(gl.TOOLS, "grype")
    assert any("grype" in p for p in gl.coverage_problems())


def test_the_repository_passes_its_own_policy() -> None:
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen-licenses.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr


def test_report_lists_tools_data_python_npm_and_weak_copyleft(tmp_path: Path) -> None:
    py = {"psycopg": ("3", "LGPL-3.0-only"), "fastapi": ("0.1", "MIT")}
    npm = {"web app": [("react", "19", "MIT", False), ("vitest", "5", "MIT", True)]}
    md = gl.render(py, npm)
    for s in (
        "| grype | Apache-2.0",
        "| Grafana",
        "OWASP Cheat Sheet Series",
        "| fastapi | 0.1 | MIT |",
        "web app (1 runtime, 1 development)",
        "psycopg: LGPL-3.0-only",
    ):
        assert s.lower() in md.lower(), s
    assert "vitest" not in md  # development-only packages are counted, not listed


def test_the_committed_report_is_current_in_structure() -> None:
    md = (ROOT / "THIRD_PARTY_LICENSES.md").read_text()
    for tool in gl.TOOLS:
        assert f"| {tool} |" in md, f"{tool} missing: run scripts/gen-licenses.py"
