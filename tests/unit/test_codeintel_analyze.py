"""core/codeintel::analyze() (plan §20.2): the end-to-end walk over a real directory tree, across
languages, wiring extraction and resolution together."""

from __future__ import annotations

from pathlib import Path

import pytest

from core import codeintel


def test_analyzes_a_multi_language_repo_and_resolves_a_cross_file_call(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def caller():\n    helper()\n")
    (tmp_path / "b.py").write_text("def helper():\n    pass\n")
    (tmp_path / "c.js").write_text("function jsFunc() { return 1; }\n")

    graph = codeintel.analyze(tmp_path)
    assert graph.languages == frozenset({"python", "javascript"})
    names = {s.qualified_name for s in graph.symbols.values()}
    assert {"caller", "helper", "jsFunc"} <= names
    caller_id = next(sid for sid, s in graph.symbols.items() if s.qualified_name == "caller")
    helper_id = next(sid for sid, s in graph.symbols.items() if s.qualified_name == "helper")
    assert any(e.caller_id == caller_id and e.callee_id == helper_id for e in graph.edges)


def test_skips_dependency_and_vcs_directories(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("function shouldNotAppear() {}\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hooks.py").write_text("def alsoIgnored():\n    pass\n")
    (tmp_path / "real.py").write_text("def realFunc():\n    pass\n")

    graph = codeintel.analyze(tmp_path)
    names = {s.qualified_name for s in graph.symbols.values()}
    assert "realFunc" in names
    assert "shouldNotAppear" not in names and "alsoIgnored" not in names


def test_an_unparsable_file_is_counted_not_fatal(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def f(:\n")
    (tmp_path / "fine.py").write_text("def ok():\n    pass\n")

    graph = codeintel.analyze(tmp_path)
    assert graph.files_unparsed == 1 and graph.files_parsed == 1
    assert any(s.qualified_name == "ok" for s in graph.symbols.values())


def test_a_file_type_with_no_extractor_is_silently_skipped(tmp_path: Path) -> None:
    (tmp_path / "readme.md").write_text("# hello\n")
    (tmp_path / "data.json").write_text("{}\n")
    graph = codeintel.analyze(tmp_path)
    assert graph.symbols == {}
    assert graph.files_parsed == 0 and graph.files_unparsed == 0


def test_an_entrypoint_found_in_one_file_can_be_walked_to_a_function_defined_in_another(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text('@app.get("/users")\ndef list_users():\n    return fetch()\n')
    (tmp_path / "db.py").write_text("def fetch():\n    pass\n")

    graph = codeintel.analyze(tmp_path)
    assert len(graph.entrypoints) == 1
    ep = graph.entrypoints[0]
    calls = graph.calls_from(ep.symbol_id)
    assert len(calls) == 1 and calls[0].callee_id is not None
    assert graph.symbols[calls[0].callee_id].qualified_name == "fetch"


def test_analyze_or_none_never_raises_even_on_a_missing_root() -> None:
    assert codeintel.analyze_or_none(Path("/does/not/exist/at/all")) is not None
    # os.walk on a missing root simply yields nothing -- an empty, valid graph, not an exception.


def test_analyze_or_none_catches_a_real_failure_and_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a: object, **kw: object) -> None:
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(codeintel, "analyze", boom)
    assert codeintel.analyze_or_none(tmp_path) is None


def test_an_oversized_file_is_skipped(tmp_path: Path) -> None:
    big = tmp_path / "huge.py"
    big.write_text("def f():\n    pass\n" + "# padding\n" * 200_000)
    assert big.stat().st_size > codeintel.MAX_FILE_BYTES
    graph = codeintel.analyze(tmp_path)
    assert graph.symbols == {}


def test_stops_after_max_files_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codeintel, "MAX_FILES", 2)
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text(f"def fn{i}():\n    pass\n")
    graph = codeintel.analyze(tmp_path)
    assert graph.files_parsed <= 2
