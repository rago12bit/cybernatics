"""Static checks on the GitHub Action, which cannot be run outside GitHub."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from core.scan import ADAPTERS

ROOT = Path(__file__).resolve().parents[2]
ACTION = yaml.safe_load((ROOT / "action" / "action.yml").read_text())
STEPS = ACTION["runs"]["steps"]


def test_is_a_composite_action_with_documented_inputs() -> None:
    assert ACTION["runs"]["using"] == "composite"
    for name in (
        "path",
        "tools",
        "fail-on",
        "upload-sarif",
        "comment",
        "compare-base",
        "github-token",
    ):
        assert ACTION["inputs"][name]["description"], name
    assert ACTION["inputs"]["fail-on"]["default"] == "high"


def test_no_expression_is_interpolated_into_a_shell_script() -> None:
    # `${{ ... }}` inside run: is script injection (a branch name or PR title becomes code). Values must
    # reach the shell only through env:.
    for step in STEPS:
        if "run" in step:
            assert "${{" not in step["run"], step.get("name")
            assert step.get("shell") == "bash", step.get("name")


def test_third_party_actions_are_pinned_to_commit_shas() -> None:
    uses = [s["uses"] for s in STEPS if "uses" in s]
    assert uses
    for u in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u.split(" ")[0]), u


def test_build_script_tags_match_the_adapters() -> None:
    script = (ROOT / "action" / "build-images.sh").read_text()
    for name, adapter in ADAPTERS.items():
        image = adapter.info.image if hasattr(adapter, "info") else adapter.spec.image  # type: ignore[attr-defined]
        assert image in script, f"{name}: {image}"


def test_every_dockerfile_directory_the_script_builds_exists() -> None:
    for d in re.findall(
        r"^build \S+ (\S+)$", (ROOT / "action" / "build-images.sh").read_text(), re.M
    ):
        assert (ROOT / "docker" / d / "Dockerfile").is_file(), d


def test_sarif_upload_and_comment_never_hide_the_gate() -> None:
    upload = next(
        s for s in STEPS if s.get("uses", "").startswith("github/codeql-action/upload-sarif")
    )
    assert upload["continue-on-error"] is True and "always()" in upload["if"]
    enforce = STEPS[-1]
    assert "gate-exit" in enforce["if"] and "exit 1" in enforce["run"]


def test_outputs_reference_a_step_that_exists() -> None:
    ids = {s.get("id") for s in STEPS}
    for out in ACTION["outputs"].values():
        assert re.search(r"steps\.(\w+)\.outputs", out["value"]).group(1) in ids  # type: ignore[union-attr]


@pytest.mark.skipif(__import__("shutil").which("bash") is None, reason="needs bash")
def test_shell_scripts_have_valid_syntax() -> None:
    import subprocess

    subprocess.run(["bash", "-n", str(ROOT / "action" / "build-images.sh")], check=True)
    for step in STEPS:
        if "run" in step:
            subprocess.run(["bash", "-n"], input=step["run"].encode(), check=True)


def test_inputs_are_wired_to_the_steps_that_use_them() -> None:
    env = {s["id"]: s["env"] for s in STEPS if s.get("id") in ("scan", "compare")}
    assert env["scan"]["SCAN_PATH"] == "${{ inputs.path }}"
    assert env["scan"]["TOOLS"] == "${{ inputs.tools }}"
    assert env["scan"]["COMPARE_BASE"] == "${{ inputs.compare-base }}"
    assert env["compare"]["FAIL_ON"] == "${{ inputs.fail-on }}"
    comment = next(s for s in STEPS if s.get("name", "").startswith("Comment"))
    assert comment["env"]["GITHUB_TOKEN"] == "${{ inputs.github-token }}"
    assert comment["env"]["PR_NUMBER"] == "${{ github.event.pull_request.number }}"
