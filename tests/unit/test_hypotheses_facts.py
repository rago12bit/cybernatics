"""core.hypotheses.facts: deterministic candidate generation (plan §21.4)."""

from __future__ import annotations

from core.codeintel.models import CodeGraph, Entrypoint, Symbol
from core.hypotheses.facts import looks_like_auth_marker, missing_auth_candidates


def _graph(entrypoints: list[Entrypoint], symbols: dict[str, Symbol]) -> CodeGraph:
    return CodeGraph(symbols=symbols, entrypoints=entrypoints)


def _sym(sid: str, path: str, line: int) -> Symbol:
    return Symbol(sid, path, "f", "f", "function", line, line, "python")


def test_a_route_with_no_marker_beside_a_protected_sibling_is_a_candidate() -> None:
    protected = Entrypoint("a.py:list_users:10", "flask", "GET", "/users", ("login_required",))
    unprotected = Entrypoint("a.py:delete_user:20", "flask", "DELETE", "/users/1")
    symbols = {
        protected.symbol_id: _sym(protected.symbol_id, "a.py", 10),
        unprotected.symbol_id: _sym(unprotected.symbol_id, "a.py", 20),
    }
    graph = _graph([protected, unprotected], symbols)
    candidates = missing_auth_candidates(graph)
    assert len(candidates) == 1
    assert candidates[0].route == unprotected
    assert candidates[0].protected_siblings == (protected,)


def test_a_file_with_no_protected_route_at_all_produces_no_candidates() -> None:
    a = Entrypoint("a.py:x:1", "flask", "GET", "/a")
    b = Entrypoint("a.py:y:2", "flask", "GET", "/b")
    symbols = {a.symbol_id: _sym(a.symbol_id, "a.py", 1), b.symbol_id: _sym(b.symbol_id, "a.py", 2)}
    assert missing_auth_candidates(_graph([a, b], symbols)) == []


def test_a_fully_protected_file_produces_no_candidates() -> None:
    a = Entrypoint("a.py:x:1", "flask", "GET", "/a", ("login_required",))
    b = Entrypoint("a.py:y:2", "flask", "GET", "/b", ("login_required",))
    symbols = {a.symbol_id: _sym(a.symbol_id, "a.py", 1), b.symbol_id: _sym(b.symbol_id, "a.py", 2)}
    assert missing_auth_candidates(_graph([a, b], symbols)) == []


def test_candidates_from_different_files_do_not_cross_contaminate() -> None:
    protected = Entrypoint("a.py:x:1", "flask", "GET", "/a", ("login_required",))
    unrelated = Entrypoint("b.py:y:1", "flask", "GET", "/b")  # different file, no protected sibling
    symbols = {
        protected.symbol_id: _sym(protected.symbol_id, "a.py", 1),
        unrelated.symbol_id: _sym(unrelated.symbol_id, "b.py", 1),
    }
    assert missing_auth_candidates(_graph([protected, unrelated], symbols)) == []


def test_looks_like_auth_marker_is_case_insensitive() -> None:
    assert looks_like_auth_marker("LOGIN_REQUIRED")
    assert looks_like_auth_marker("RequireAuth")
    assert not looks_like_auth_marker("cache_response")


def test_candidates_are_sorted_by_file_then_line() -> None:
    protected = Entrypoint("a.py:p:1", "flask", "GET", "/p", ("login_required",))
    late = Entrypoint("a.py:late:30", "flask", "GET", "/late")
    early = Entrypoint("a.py:early:5", "flask", "GET", "/early")
    symbols = {
        protected.symbol_id: _sym(protected.symbol_id, "a.py", 1),
        late.symbol_id: _sym(late.symbol_id, "a.py", 30),
        early.symbol_id: _sym(early.symbol_id, "a.py", 5),
    }
    candidates = missing_auth_candidates(_graph([protected, late, early], symbols))
    assert [c.route.symbol_id for c in candidates] == [early.symbol_id, late.symbol_id]
