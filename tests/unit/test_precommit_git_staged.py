"""core.precommit.git_staged: reads the INDEX content of staged files, not the working tree, using
a real git repository per test (Week 51 task 4, plan §23) -- this module is nothing but a thin,
testable wrapper over real `git` subprocess calls, so there is no value in mocking them."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.precommit.git_staged import list_staged_paths, load_staged_files, read_staged_blob


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    return tmp_path


def test_list_staged_paths_only_includes_staged_files(repo: Path) -> None:
    (repo / "staged.py").write_text("a = 1\n")
    (repo / "unstaged.py").write_text("b = 2\n")
    _git(repo, "add", "staged.py")
    assert list_staged_paths(repo) == ["staged.py"]


def test_list_staged_paths_sees_only_the_staged_version_not_further_edits(repo: Path) -> None:
    (repo / "a.py").write_text("version-1\n")
    _git(repo, "add", "a.py")
    (repo / "a.py").write_text("version-2-not-yet-staged\n")
    assert read_staged_blob(repo, "a.py") == "version-1\n"


def test_read_staged_blob_returns_none_for_a_nonexistent_path(repo: Path) -> None:
    assert read_staged_blob(repo, "does-not-exist.py") is None


def test_load_staged_files_batches_every_staged_file(repo: Path) -> None:
    (repo / "a.py").write_text("a = 1\n")
    (repo / "b.py").write_text("b = 2\n")
    _git(repo, "add", "a.py", "b.py")
    files = {f.path: f.text for f in load_staged_files(repo)}
    assert files == {"a.py": "a = 1\n", "b.py": "b = 2\n"}


def test_load_staged_files_treats_non_utf8_content_as_binary(repo: Path) -> None:
    (repo / "bin.dat").write_bytes(b"\xff\xfe\x00\x01not-utf8")
    _git(repo, "add", "bin.dat")
    [f] = load_staged_files(repo)
    assert f.path == "bin.dat"
    assert f.text is None


def test_a_deleted_staged_file_is_excluded(repo: Path) -> None:
    (repo / "a.py").write_text("a = 1\n")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-m", "initial")
    (repo / "a.py").unlink()
    _git(repo, "add", "a.py")  # stages the deletion
    assert list_staged_paths(repo) == []


def test_empty_index_yields_no_staged_files(repo: Path) -> None:
    assert list_staged_paths(repo) == []
    assert load_staged_files(repo) == []


def test_binary_content_with_embedded_newline_bytes_is_read_correctly_by_the_batch_call(
    repo: Path,
) -> None:
    """The batch reader parses `git cat-file --batch` output by exact byte size, not by scanning
    for a trailing newline -- this is the case that would break if it scanned instead, since the
    content itself contains newline bytes before its true end."""
    content = b"line1\nline2\nline3-not-utf8-\xff\xfe\n"
    (repo / "weird.dat").write_bytes(content)
    (repo / "normal.py").write_text("x = 1\n")
    _git(repo, "add", "weird.dat", "normal.py")
    files = {f.path: f for f in load_staged_files(repo)}
    assert files["weird.dat"].text is None  # not valid UTF-8 -- correctly treated as binary
    assert files["normal.py"].text == "x = 1\n"  # the file read *after* it in the batch is intact
