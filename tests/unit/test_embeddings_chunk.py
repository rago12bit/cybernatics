"""core.embeddings.chunk: function-level chunking off a real core.codeintel analysis (plan §21.5)."""

from __future__ import annotations

from pathlib import Path

from core.codeintel import analyze
from core.codeintel.models import CodeGraph, Symbol
from core.embeddings.chunk import MAX_CHUNK_CHARS, _safe_read, chunk_checkout


def test_chunks_one_real_python_file_at_function_granularity(tmp_path: Path) -> None:
    (tmp_path / "users.py").write_text(
        "def get_user(uid):\n"
        "    return db.execute('SELECT * FROM users WHERE id=?', (uid,))\n"
        "\n"
        "\n"
        "def delete_user(uid):\n"
        "    db.execute('DELETE FROM users WHERE id=?', (uid,))\n"
    )
    graph = analyze(tmp_path)
    chunks = chunk_checkout(tmp_path, graph)
    assert {c.symbol_name for c in chunks} == {"get_user", "delete_user"}
    get_user = next(c for c in chunks if c.symbol_name == "get_user")
    assert get_user.path == "users.py"
    assert get_user.language == "python"
    assert get_user.kind == "function"
    assert "SELECT * FROM users" in get_user.text
    assert "DELETE FROM users" not in get_user.text  # chunk boundary excludes the sibling function


def test_two_files_are_both_read_and_chunked(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def f():\n    pass\n")
    (tmp_path / "b.py").write_text("def g():\n    pass\n")
    graph = analyze(tmp_path)
    chunks = chunk_checkout(tmp_path, graph)
    assert {(c.path, c.symbol_name) for c in chunks} == {("a.py", "f"), ("b.py", "g")}


def test_a_symbol_whose_file_cannot_be_read_produces_no_chunk_not_a_crash(tmp_path: Path) -> None:
    # A symbol referencing a path outside the checkout (should never happen from a real analyze()
    # call, but chunk_checkout must not trust it blindly -- same chokepoint principle as
    # core.hypotheses.service._safe_read).
    evil = Symbol("evil", "../outside.py", "f", "f", "function", 1, 1, "python")
    graph = CodeGraph(symbols={evil.id: evil}, all_symbols=(evil,))
    assert chunk_checkout(tmp_path, graph) == []


def test_safe_read_rejects_absolute_and_escaping_paths(tmp_path: Path) -> None:
    (tmp_path / "in.py").write_text("x = 1\n")
    assert _safe_read(tmp_path, "in.py") == "x = 1\n"
    assert _safe_read(tmp_path, "/etc/passwd") is None
    assert _safe_read(tmp_path, "../outside.py") is None
    assert _safe_read(tmp_path, "") is None
    assert _safe_read(tmp_path, "missing.py") is None


def test_an_oversized_chunk_is_skipped_not_truncated(tmp_path: Path) -> None:
    huge_body = "\n".join(f"    x{i} = {i}" for i in range(MAX_CHUNK_CHARS // 8))
    (tmp_path / "huge.py").write_text(f"def huge():\n{huge_body}\n")
    graph = analyze(tmp_path)
    chunks = chunk_checkout(tmp_path, graph)
    assert chunks == []


def test_an_empty_function_body_produces_no_chunk(tmp_path: Path) -> None:
    # A symbol range that resolves to nothing but whitespace (e.g. a stub) shouldn't become a
    # zero-content vector.
    stub = Symbol("stub", "s.py", "f", "f", "function", 2, 3, "python")
    (tmp_path / "s.py").write_text("def f():\n    \n    \n")
    graph = CodeGraph(symbols={stub.id: stub}, all_symbols=(stub,))
    assert chunk_checkout(tmp_path, graph) == []
