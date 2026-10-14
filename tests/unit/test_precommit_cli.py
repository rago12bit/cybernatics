"""`bulwark precommit run/install/uninstall` (Week 51 task 4, plan §23): the CLI surface over
core.precommit, exercised against real temporary git repositories and real `git commit`s -- this
is the one Week 51 task that needs no Docker, database or third-party account to verify end to end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    # The hook runs `bulwark` from PATH: put this interpreter's own scripts first, so the test does
    # not depend on whether the shell that started pytest had the virtualenv activated.
    bin_dir = str(Path(sys.executable).parent)
    env = {**os.environ, "PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")}
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    return tmp_path


def test_run_with_no_staged_files_passes_cleanly(repo: Path) -> None:
    r = runner.invoke(app, ["precommit", "run", "--repo", str(repo)])
    assert r.exit_code == 0, r.output


def test_run_blocks_on_a_staged_secret(repo: Path) -> None:
    (repo / "creds.py").write_text("aws_key = 'AKIAABCDEFGHIJKLMNOP'\n")
    _git(repo, "add", "creds.py")
    r = runner.invoke(app, ["precommit", "run", "--repo", str(repo)])
    assert r.exit_code == 1
    assert "AWS access key ID" in r.output
    assert "BLOCK" in r.output


def test_run_passes_once_the_secret_is_removed_and_restaged(repo: Path) -> None:
    (repo / "creds.py").write_text("aws_key = 'AKIAABCDEFGHIJKLMNOP'\n")
    _git(repo, "add", "creds.py")
    assert runner.invoke(app, ["precommit", "run", "--repo", str(repo)]).exit_code == 1
    (repo / "creds.py").write_text("# no secrets here\n")
    _git(repo, "add", "creds.py")
    assert runner.invoke(app, ["precommit", "run", "--repo", str(repo)]).exit_code == 0


def test_run_json_output_reports_the_finding_and_elapsed_time(repo: Path) -> None:
    (repo / "creds.py").write_text("aws_key = 'AKIAABCDEFGHIJKLMNOP'\n")
    _git(repo, "add", "creds.py")
    r = runner.invoke(app, ["precommit", "run", "--repo", str(repo), "--json"])
    assert r.exit_code == 1
    body = json.loads(r.output)
    assert body["files_scanned"] == 1
    assert body["blocking"] == 1
    assert len(body["findings"]) == 1
    assert body["elapsed_seconds"] < 2.0


def test_run_with_file_args_reads_from_disk_pre_commit_framework_style(tmp_path: Path) -> None:
    f = tmp_path / "creds.py"
    f.write_text("aws_key = 'AKIAABCDEFGHIJKLMNOP'\n")
    r = runner.invoke(app, ["precommit", "run", str(f)])
    assert r.exit_code == 1
    assert "AWS access key ID" in r.output


def test_fail_on_medium_blocks_a_medium_severity_finding(repo: Path) -> None:
    (repo / "a.py").write_text("pickle.loads(data)\n")  # MEDIUM
    _git(repo, "add", "a.py")
    assert (
        runner.invoke(app, ["precommit", "run", "--repo", str(repo)]).exit_code == 0
    )  # HIGH floor
    r = runner.invoke(app, ["precommit", "run", "--repo", str(repo), "--fail-on", "MEDIUM"])
    assert r.exit_code == 1


def test_bulwarkignore_suppresses_a_matched_finding(repo: Path) -> None:
    (repo / ".bulwarkignore").write_text("vendor/\n")
    (repo / "vendor").mkdir()
    (repo / "vendor" / "lib.py").write_text("aws_key = 'AKIAABCDEFGHIJKLMNOP'\n")
    _git(repo, "add", "-A")
    r = runner.invoke(app, ["precommit", "run", "--repo", str(repo)])
    assert r.exit_code == 0, r.output
    assert "ignored" in r.output


def test_run_on_a_non_git_directory_fails_with_a_clear_error(tmp_path: Path) -> None:
    r = runner.invoke(app, ["precommit", "run", "--repo", str(tmp_path)])
    assert r.exit_code == 2
    assert "error" in r.output.lower()


def test_install_writes_an_executable_hook_that_a_real_commit_exercises(repo: Path) -> None:
    r = runner.invoke(app, ["precommit", "install", "--repo", str(repo)])
    assert r.exit_code == 0, r.output
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.is_file()
    assert os.access(hook, os.X_OK)

    (repo / "creds.py").write_text("aws_key = 'AKIAABCDEFGHIJKLMNOP'\n")
    _git(repo, "add", "creds.py")
    commit = _git(repo, "commit", "-m", "add creds")
    assert commit.returncode != 0  # the real hook, invoked by real `git commit`, blocked it --
    assert b"[BLOCK]" in commit.stdout + commit.stderr  # for the secret, not for a missing command

    (repo / "creds.py").write_text("# clean\n")
    _git(repo, "add", "creds.py")
    commit = _git(repo, "commit", "-m", "clean")
    assert commit.returncode == 0, commit.stderr.decode()


def test_install_refuses_to_overwrite_an_existing_hook_without_force(repo: Path) -> None:
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho custom\n")
    r = runner.invoke(app, ["precommit", "install", "--repo", str(repo)])
    assert r.exit_code == 1
    assert "already exists" in r.output


def test_install_on_a_non_git_directory_fails(tmp_path: Path) -> None:
    r = runner.invoke(app, ["precommit", "install", "--repo", str(tmp_path)])
    assert r.exit_code == 1


def test_uninstall_removes_a_bulwark_installed_hook(repo: Path) -> None:
    runner.invoke(app, ["precommit", "install", "--repo", str(repo)])
    r = runner.invoke(app, ["precommit", "uninstall", "--repo", str(repo)])
    assert r.exit_code == 0
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_uninstall_refuses_to_remove_a_hook_it_did_not_install(repo: Path) -> None:
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho custom\n")
    r = runner.invoke(app, ["precommit", "uninstall", "--repo", str(repo)])
    assert r.exit_code == 1
    assert (hooks_dir / "pre-commit").exists()


def test_uninstall_with_no_hook_installed_is_a_no_op(repo: Path) -> None:
    r = runner.invoke(app, ["precommit", "uninstall", "--repo", str(repo)])
    assert r.exit_code == 0
