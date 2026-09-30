"""core.attackpath.checkout.build_graph: clone, analyze, and always clean up the tempdir -- even
when clone or analyze raises."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.attackpath.checkout import build_graph
from core.codeintel.models import CodeGraph


@pytest.fixture
def fake_clone(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str | None]]:
    calls: list[tuple[str, str | None]] = []

    def _clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        calls.append((source_ref, ref))
        (dest / "a.py").write_text("def f():\n    return 1\n")
        return dest

    monkeypatch.setattr("core.attackpath.checkout.clone_repo", _clone)
    return calls


def test_build_graph_clones_and_analyzes(fake_clone: list[tuple[str, str | None]]) -> None:
    graph = build_graph("https://example.com/x.git", "main")
    assert isinstance(graph, CodeGraph)
    assert fake_clone == [("https://example.com/x.git", "main")]
    assert any(s.name == "f" for s in graph.all_symbols)


def test_build_graph_removes_the_tempdir_even_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Path] = {}

    def _clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        captured["dest"] = dest
        raise RuntimeError("clone failed")

    monkeypatch.setattr("core.attackpath.checkout.clone_repo", _clone)
    with pytest.raises(RuntimeError):
        build_graph("https://example.com/x.git", None)
    assert not captured["dest"].exists()
