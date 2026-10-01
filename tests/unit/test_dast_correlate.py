"""core.dast.correlate's "confirmed at runtime" matching (Week 49 task 4, plan §22.4)."""

from __future__ import annotations

from core.dast.correlate import correlate_dast_with_sast
from core.dast.routes import RouteHandler
from core.models import Category, Finding, Location, Taxonomy


def _dast(route: str, cwe: tuple[str, ...], finding_id: str = "d1") -> Finding:
    return Finding(
        id=finding_id, title="t", description="d",
        location=Location(path="", start_line=0, end_line=0, route=route),
        taxonomy=Taxonomy(category=Category.DAST, cwe=cwe),
    )  # fmt: skip


def _sast(path: str, line: int, cwe: tuple[str, ...], finding_id: str = "s1") -> Finding:
    return Finding(
        id=finding_id, title="t", description="d",
        location=Location(path=path, start_line=line, end_line=line, route=""),
        taxonomy=Taxonomy(category=Category.SAST, cwe=cwe),
    )  # fmt: skip


def test_matches_a_dast_finding_to_a_sast_finding_near_the_same_handler() -> None:
    handlers = [RouteHandler(route="/login", path="app/routes.py", line=42)]
    dast = [_dast("/login", ("CWE-89",))]
    sast = [_sast("app/routes.py", 45, ("CWE-89",))]
    confirmations = correlate_dast_with_sast(dast, sast, handlers)
    assert len(confirmations) == 1
    assert confirmations[0].dast_finding_id == "d1"
    assert confirmations[0].sast_finding_id == "s1"
    assert confirmations[0].route == "/login"


def test_matches_via_cwe_family_not_just_exact_cwe() -> None:
    """CWE-259 (hardcoded password) and CWE-798 (hardcoded credentials) are the same family
    (core.correlation.engine.CWE_FAMILY) -- a DAST finding reporting one and a SAST finding
    reporting the other should still correlate."""
    handlers = [RouteHandler(route="/admin", path="app.py", line=10)]
    dast = [_dast("/admin", ("CWE-798",))]
    sast = [_sast("app.py", 10, ("CWE-259",))]
    assert len(correlate_dast_with_sast(dast, sast, handlers)) == 1


def test_no_match_when_the_route_has_no_known_handler() -> None:
    handlers = [RouteHandler(route="/other", path="app.py", line=10)]
    dast = [_dast("/login", ("CWE-89",))]
    sast = [_sast("app.py", 10, ("CWE-89",))]
    assert correlate_dast_with_sast(dast, sast, handlers) == []


def test_no_match_when_cwes_are_unrelated() -> None:
    handlers = [RouteHandler(route="/login", path="app.py", line=10)]
    dast = [_dast("/login", ("CWE-89",))]
    sast = [_sast("app.py", 10, ("CWE-79",))]
    assert correlate_dast_with_sast(dast, sast, handlers) == []


def test_no_match_when_the_sast_finding_is_in_a_different_file() -> None:
    handlers = [RouteHandler(route="/login", path="app.py", line=10)]
    dast = [_dast("/login", ("CWE-89",))]
    sast = [_sast("other.py", 10, ("CWE-89",))]
    assert correlate_dast_with_sast(dast, sast, handlers) == []


def test_no_match_when_the_sast_finding_is_far_from_the_handler() -> None:
    handlers = [RouteHandler(route="/login", path="app.py", line=10)]
    dast = [_dast("/login", ("CWE-89",))]
    sast = [_sast("app.py", 500, ("CWE-89",))]
    assert correlate_dast_with_sast(dast, sast, handlers) == []


def test_a_dast_finding_with_no_route_is_never_matched() -> None:
    handlers = [RouteHandler(route="/login", path="app.py", line=10)]
    dast = [_dast("", ("CWE-89",))]
    sast = [_sast("app.py", 10, ("CWE-89",))]
    assert correlate_dast_with_sast(dast, sast, handlers) == []


def test_a_wildcard_route_matches_a_concrete_observed_path() -> None:
    handlers = [RouteHandler(route="/assets/*/campaigns", path="api/main.py", line=648)]
    dast = [_dast("/assets/9c1a2b3c/campaigns", ("CWE-918",))]
    sast = [_sast("api/main.py", 650, ("CWE-918",))]
    assert len(correlate_dast_with_sast(dast, sast, handlers)) == 1
