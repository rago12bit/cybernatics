"""Static checks on the GitHub Action, which cannot be run outside GitHub."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from core.scan import ADAPTERS, DEFAULT_TOOLS

ROOT = Path(__file__).resolve().parents[2]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
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
        "cache",
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
    for name, adapter in (
        (n, ADAPTERS[n]) for n in DEFAULT_TOOLS
    ):  # tier 2 images are built separately
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
    assert env["scan"]["CACHE"] == "${{ inputs.cache }}"
    assert env["compare"]["FAIL_ON"] == "${{ inputs.fail-on }}"
    assert env["compare"]["POLICY_FILE"] == "${{ inputs.policy-file }}"
    sbom = next(s for s in STEPS if s.get("id") == "sbom")
    assert sbom["env"]["SCAN_PATH"] == "${{ inputs.path }}" and "inputs.sbom" in sbom["if"]
    comment = next(s for s in STEPS if s.get("name", "").startswith("Comment"))
    assert comment["env"]["GITHUB_TOKEN"] == "${{ inputs.github-token }}"
    assert comment["env"]["PR_NUMBER"] == "${{ github.event.pull_request.number }}"


def test_opa_is_only_installed_when_a_policy_file_is_actually_configured() -> None:
    """Plan §20.4's OPA install must not run (and slow down) every scan when no org has set a
    policy -- only when `policy-file` is actually given."""
    opa_step = next(s for s in STEPS if s.get("name", "").startswith("Install OPA"))
    assert opa_step["if"] == "${{ inputs.policy-file != '' }}"


def test_the_compare_step_only_passes_policy_when_a_policy_file_is_set() -> None:
    compare = next(s for s in STEPS if s.get("id") == "compare")
    assert "POLICY_FILE" in compare["run"] and "--policy" in compare["run"]
    assert '[ -n "$POLICY_FILE" ]' in compare["run"]


def test_policy_violations_output_is_wired_to_the_compare_step() -> None:
    assert (
        ACTION["outputs"]["policy-violations"]["value"]
        == "${{ steps.compare.outputs.policy-violations }}"
    )


def test_result_cache_is_restored_before_scanning_and_saved_after_with_a_matching_path() -> None:
    """Plan §20.1/§36: the cache directory named in the scan step's --cache-dir must be exactly the
    one restore/save operate on, or the cache would silently do nothing."""
    restore = next(s for s in STEPS if s.get("uses", "").startswith("actions/cache/restore"))
    save = next(s for s in STEPS if s.get("uses", "").startswith("actions/cache/save"))
    scan = next(s for s in STEPS if s.get("id") == "scan")["run"]
    assert restore["with"]["path"] == save["with"]["path"] == "~/.bulwark-result-cache"
    assert "$HOME/.bulwark-result-cache" in scan and "--cache-dir" in scan
    assert "inputs.cache" in restore["if"] and "inputs.cache" in save["if"]
    assert "always()" in save["if"]  # must still run (and thus save progress) after a failed step
    # restore happens strictly before the scan step that would use it; save strictly after
    assert STEPS.index(restore) < STEPS.index(next(s for s in STEPS if s.get("id") == "scan"))
    assert STEPS.index(save) > STEPS.index(next(s for s in STEPS if s.get("id") == "scan"))


def test_pull_requests_take_ignore_rules_from_the_base_commit_not_the_change() -> None:
    scan = next(s for s in STEPS if s.get("id") == "scan")["run"]
    assert 'git show "$BASE_SHA:' in scan and "--ignore-file" in scan
    assert scan.index("--ignore-file") < scan.index("bulwark scan")  # set up before the first scan


def test_the_self_scan_workflow_uses_this_action_and_gates_only_pull_requests() -> None:
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "bulwark.yml").read_text())
    trigger = wf.get("on") or wf[True]  # PyYAML parses a bare `on` key as boolean True
    assert "pull_request" in trigger and trigger["push"]["branches"] == ["main"]
    steps = wf["jobs"]["scan"]["steps"]
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", steps[0]["uses"].split(" ")[0])
    assert steps[1]["uses"] == "./"
    fail_on = steps[1]["with"]["fail-on"]
    assert "pull_request" in fail_on and "'high'" in fail_on and "'none'" in fail_on
    assert (
        wf["permissions"]["security-events"] == "write" and wf["permissions"]["contents"] == "read"
    )
