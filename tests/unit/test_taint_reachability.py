"""core/taint/reachability.py: attaching a concrete taint path to a matching Finding and feeding
taint reachability into the shared risk-scoring signal (plan §20.3, §28.3)."""

from __future__ import annotations

from core.models import Category, Finding, Location, Taxonomy
from core.taint.models import TaintFinding, TaintHop
from core.taint.reachability import TAINT_CONFIRMED_CONFIDENCE, attach_taint_paths, build_index


def _finding(category: Category = Category.SAST, path: str = "app.py", line: int = 10) -> Finding:
    return Finding(
        id="x", title="SQL Injection", description="d",
        location=Location(path, line, line),
        taxonomy=Taxonomy(category),
    )  # fmt: skip


def _taint_finding(path: str = "app.py", line: int = 10) -> TaintFinding:
    return TaintFinding(
        entrypoint_symbol_id="app.py:view:1",
        category="sql_injection",
        sink_path=path,
        sink_line=line,
        sink_name="execute",
        hops=(TaintHop("app.py:view:1", "app.py", 4, "HTTP entrypoint: GET /search (flask)"),),
    )


def test_attach_taint_paths_matches_a_sast_finding_at_the_sinks_location() -> None:
    f = _finding()
    tf = _taint_finding()
    out = attach_taint_paths([f], [tf])
    assert len(out) == 1
    assert len(out[0].taint_path) == 2
    assert out[0].taint_path[-1].is_sink is True
    assert out[0].taint_path[-1].path == "app.py" and out[0].taint_path[-1].line == 10
    assert out[0].taint_path[0].is_sink is False


def test_attach_taint_paths_bumps_confidence_but_never_lowers_it() -> None:
    f = _finding()
    f.scoring.confidence = 0.95  # already higher than TAINT_CONFIRMED_CONFIDENCE
    out = attach_taint_paths([f], [_taint_finding()])
    assert out[0].scoring.confidence == 0.95

    f2 = _finding()
    f2.scoring.confidence = 0.3
    out2 = attach_taint_paths([f2], [_taint_finding()])
    assert out2[0].scoring.confidence == TAINT_CONFIRMED_CONFIDENCE


def test_a_finding_with_no_matching_sink_location_is_returned_unchanged() -> None:
    f = _finding(path="other.py", line=99)
    out = attach_taint_paths([f], [_taint_finding()])
    assert out[0].taint_path == ()
    assert out[0] is f  # not even copied, since nothing changed


def test_a_non_sast_finding_is_never_matched_even_at_the_same_location() -> None:
    """An SCA finding happening to share a (path, line) with a taint sink must not be enriched --
    taint analysis only ever says something about code (SAST), never about a dependency."""
    f = _finding(category=Category.SCA)
    out = attach_taint_paths([f], [_taint_finding()])
    assert out[0].taint_path == ()


def test_no_taint_findings_at_all_returns_the_input_list_untouched() -> None:
    f = _finding()
    out = attach_taint_paths([f], [])
    assert out == [f]


def test_build_index_groups_by_sink_location() -> None:
    tf1 = _taint_finding(path="a.py", line=1)
    tf2 = _taint_finding(path="a.py", line=1)  # two paths reaching the same sink
    tf3 = _taint_finding(path="b.py", line=2)
    index = build_index([tf1, tf2, tf3])
    assert len(index.by_location[("a.py", 1)]) == 2
    assert len(index.by_location[("b.py", 2)]) == 1


def test_taint_index_assess_returns_reachable_true_for_a_matching_sast_finding() -> None:
    index = build_index([_taint_finding()])
    r = index.assess(_finding())
    assert r is not None and r.reachable is True
    assert "taint path" in r.reason


def test_taint_index_assess_returns_none_for_no_match_or_non_sast() -> None:
    index = build_index([_taint_finding()])
    assert index.assess(_finding(path="nowhere.py")) is None
    assert index.assess(_finding(category=Category.SCA)) is None


def test_attach_taint_paths_reads_a_snippet_from_the_workspace_when_root_is_given(
    tmp_path,
) -> None:
    (tmp_path / "app.py").write_text(
        "line1\nline2\nline3\nline4 = cursor.execute(q)\nline5\nline6\n"
    )
    tf = TaintFinding(
        entrypoint_symbol_id="app.py:view:1", category="sql_injection",
        sink_path="app.py", sink_line=4, sink_name="execute",
        hops=(),
    )  # fmt: skip
    out = attach_taint_paths([_finding(line=4)], [tf], root=tmp_path)
    step = out[0].taint_path[0]
    assert step.is_sink is True
    assert "cursor.execute(q)" in step.snippet
    assert "line2" in step.snippet and "line6" in step.snippet  # +/- 2 lines of context


def test_attach_taint_paths_without_root_leaves_snippets_empty() -> None:
    out = attach_taint_paths([_finding()], [_taint_finding()])
    assert all(step.snippet == "" for step in out[0].taint_path)


def test_attach_taint_paths_with_an_unreadable_path_yields_an_empty_snippet_not_a_crash(
    tmp_path,
) -> None:
    out = attach_taint_paths(
        [_finding(path="missing.py")], [_taint_finding(path="missing.py")], root=tmp_path
    )
    assert out[0].taint_path[0].snippet == ""
