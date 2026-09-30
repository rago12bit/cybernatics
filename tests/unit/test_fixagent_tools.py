"""Path containment and the read/search/call-path tools (plan §21.2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.fixagent.context import gather_context
from core.fixagent.tools import ToolError, get_call_path, read_file, search_code
from core.models import Category, Finding, Location, Taxonomy

SRC = """import sqlite3


def get_user(uid):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE id=" + uid).fetchone()


def handler(request):
    uid = request.args["id"]
    return get_user(uid)
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    d = tmp_path / "repo"
    (d / "app").mkdir(parents=True)
    (d / "app" / "users.py").write_text(SRC)
    return d


@pytest.mark.parametrize(
    "bad",
    ["../../../etc/passwd", "/etc/passwd", "app/../../etc/passwd", ""],
)
def test_path_containment_rejects_every_escape_attempt(repo: Path, bad: str) -> None:
    with pytest.raises(ToolError):
        read_file(repo, bad)


def test_path_containment_allows_ordinary_relative_paths(repo: Path) -> None:
    assert "sqlite3" in read_file(repo, "app/users.py")


def test_read_file_numbers_lines_and_respects_a_range(repo: Path) -> None:
    out = read_file(repo, "app/users.py", start_line=4, end_line=6)
    lines = out.splitlines()
    assert len(lines) == 3 and lines[0].startswith("    4 | def get_user")


def test_read_file_rejects_a_missing_file(repo: Path) -> None:
    with pytest.raises(ToolError, match="no such file"):
        read_file(repo, "nope.py")


def test_search_code_finds_real_matches_and_reports_line_numbers(repo: Path) -> None:
    out = search_code(repo, "sqlite3")
    assert "app/users.py:1:" in out and "app/users.py:5:" in out


def test_search_code_reports_no_matches_plainly(repo: Path) -> None:
    assert search_code(repo, "nonexistent_xyz") == "(no matches)"


def test_search_code_rejects_an_oversized_query(repo: Path) -> None:
    with pytest.raises(ToolError):
        search_code(repo, "x" * 300)


def _finding() -> Finding:
    return Finding(
        "f1", "SQL injection", "String-built SQL",
        Location("app/users.py", 6, 6, "x"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip


def test_get_call_path_finds_the_enclosing_function_and_its_real_caller(repo: Path) -> None:
    ctx = gather_context(repo, _finding())
    out = get_call_path(ctx, "app/users.py", 6)
    assert "get_user" in out and "is called by" in out and "handler" in out


def test_get_call_path_is_honest_about_no_enclosing_function(repo: Path) -> None:
    ctx = gather_context(repo, _finding())
    out = get_call_path(ctx, "app/users.py", 1)  # the top-level import line
    assert "no enclosing function found" in out


def test_gather_context_carries_the_findings_own_taint_path_through(repo: Path) -> None:
    from core.models import TaintPathStep

    f = Finding(
        "f1", "SQL injection", "d", Location("app/users.py", 6, 6, "x"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
        taint_path=(TaintPathStep("app/routes.py", 3, "user input enters here", False, "x"),),
    )  # fmt: skip
    ctx = gather_context(repo, f)
    assert ctx.taint_path == f.taint_path
