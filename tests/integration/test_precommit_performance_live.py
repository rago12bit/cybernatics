"""Live proof of the pre-commit hook's two-second budget (plan §23, Week 51 task 4) -- not a mock
or a synthetic fixture, but this project's own real `core/` source tree (240+ real Python files),
copied into a fresh git repository, staged in full, and run through the real `bulwark precommit
run` CLI command (`typer`'s CliRunner -- in-process, so this excludes Python interpreter start-up;
`PrecommitResult.elapsed_seconds`, asserted separately below, is the pure scan-logic number and is
what the plan's two-second figure is actually about).

Needs only `git` and a Python environment with this project installed -- no Docker, no database,
no network, no third-party account -- so unlike most of this week's other live tests, it always
runs in CI.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

# The plan's own 2s target, for the pure scan time (core.precommit.runner.scan_files' own
# PrecommitResult.elapsed_seconds -- git subprocess calls and parsing, not process start-up).
SCAN_BUDGET_SECONDS = 2.0
# Looser, for this in-process test's own wall-clock: catches a gross regression (e.g.
# reintroducing one `git show` subprocess per file instead of one batched `cat-file --batch`
# call -- see git_staged.py's own docstring for that exact regression) without being sensitive to
# CI-runner variance the way the tight scan-only budget above is.
WALL_BUDGET_SECONDS = 4.0


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_scanning_this_projects_entire_core_tree_stays_under_the_time_budget(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    core_src = project_root / "core"
    assert core_src.is_dir(), "expected to find this project's own core/ package"

    dest = tmp_path / "core"
    shutil.copytree(
        core_src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )  # fmt: skip

    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "add", "-A")

    staged = subprocess.run(
        ["git", "-C", str(tmp_path), "diff", "--cached", "--name-only"],
        capture_output=True, check=True, text=True,
    ).stdout.splitlines()  # fmt: skip
    assert len(staged) > 200, f"expected a few hundred real files staged, got {len(staged)}"

    wall_start = time.monotonic()
    result = runner.invoke(app, ["precommit", "run", "--repo", str(tmp_path), "--json"])
    wall_elapsed = time.monotonic() - wall_start

    assert result.exit_code in (0, 1), result.output  # 1 is fine: this repo's own code may trip a
    # real, legitimate finding (and has, historically -- see core/precommit/sast_scan.py's own
    # test fixtures for examples); what matters here is that it finished, and finished fast.
    body = json.loads(result.output)
    assert body["files_scanned"] > 200
    assert body["elapsed_seconds"] < SCAN_BUDGET_SECONDS, (
        f"pure scan time for {body['files_scanned']} real files was "
        f"{body['elapsed_seconds']}s, over the {SCAN_BUDGET_SECONDS}s plan budget"
    )
    assert wall_elapsed < WALL_BUDGET_SECONDS, (
        f"scanning {len(staged)} real files took {wall_elapsed:.2f}s wall-clock, over the "
        f"{WALL_BUDGET_SECONDS}s regression budget"
    )
