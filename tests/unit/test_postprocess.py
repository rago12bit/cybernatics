"""core/postprocess.py::finalize(): the one shared path (CLI and API) that maps, attaches taint
paths, scores, and redacts every scan's findings (plan §20.3's "reachability v2 feeds scoring")."""

from __future__ import annotations

from core.codeintel.models import CodeGraph
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.postprocess import finalize
from core.risk import Feeds
from core.taint import TaintResult
from core.taint.models import TaintFinding, TaintHop


def _finding() -> Finding:
    f = Finding(
        id="x", title="SQL Injection", description="d",
        location=Location("app.py", 10, 10),
        taxonomy=Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip
    f.scoring.normalized_severity = Severity.HIGH
    return f


def _feeds() -> Feeds:
    return Feeds(epss={}, kev=set(), epss_loaded=True)


def _taint_result() -> TaintResult:
    tf = TaintFinding(
        entrypoint_symbol_id="app.py:view:1",
        category="sql_injection",
        sink_path="app.py",
        sink_line=10,
        sink_name="execute",
        hops=(TaintHop("app.py:view:1", "app.py", 4, "HTTP entrypoint: GET /search (flask)"),),
    )
    return TaintResult(graph=CodeGraph(), summaries={}, findings=[tf])


def test_a_taint_confirmed_finding_scores_higher_than_the_same_finding_without_taint() -> None:
    baseline = finalize([_finding()], feeds=_feeds())[0]
    enriched = finalize([_finding()], feeds=_feeds(), taint=_taint_result())[0]
    assert enriched.scoring.risk_score > baseline.scoring.risk_score
    assert baseline.scoring.reachable is None
    assert enriched.scoring.reachable is True
    assert len(enriched.taint_path) == 2


def test_finalize_with_no_taint_result_behaves_exactly_as_before(monkeypatch) -> None:
    """`taint=None` (the default) must not change finalize's own existing behavior at all."""
    a = finalize([_finding()], feeds=_feeds())[0]
    b = finalize([_finding()], feeds=_feeds(), taint=None)[0]
    assert a.scoring.risk_score == b.scoring.risk_score
    assert a.taint_path == b.taint_path == ()


def test_finalize_with_an_empty_taint_result_leaves_findings_unchanged() -> None:
    empty = TaintResult(graph=CodeGraph(), summaries={}, findings=[])
    baseline = finalize([_finding()], feeds=_feeds())[0]
    out = finalize([_finding()], feeds=_feeds(), taint=empty)[0]
    assert out.scoring.risk_score == baseline.scoring.risk_score
    assert out.taint_path == ()
