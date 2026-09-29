"""core/supplychain/dependency_view.py (plan §20.5): which path in the dependency graph pulls in a
package."""

from __future__ import annotations

from core.sbom.syft import Sbom
from core.supplychain.dependency_view import path_to


def _sbom(graph: dict[str, tuple[str, ...]], roots: frozenset[str]) -> Sbom:
    return Sbom(raw=b"", components=0, spec_version="1.6", ecosystems={}, graph=graph, roots=roots)


def test_path_to_a_direct_dependency() -> None:
    sbom = _sbom({"root": ("once",)}, frozenset({"root"}))
    assert path_to(sbom, "once") == ("root", "once")


def test_path_to_a_transitive_dependency_walks_through_the_direct_one() -> None:
    sbom = _sbom({"root": ("once",), "once": ("wrappy",)}, frozenset({"root"}))
    assert path_to(sbom, "wrappy") == ("root", "once", "wrappy")


def test_path_to_a_root_itself_is_just_the_root() -> None:
    sbom = _sbom({"root": ("once",)}, frozenset({"root"}))
    assert path_to(sbom, "root") == ("root",)


def test_path_to_an_unknown_purl_is_none() -> None:
    sbom = _sbom({"root": ("once",)}, frozenset({"root"}))
    assert path_to(sbom, "nonexistent") is None


def test_the_shortest_path_is_returned_when_two_routes_exist() -> None:
    # root -> a -> target, and root -> target directly: the direct one is shorter.
    sbom = _sbom({"root": ("a", "target"), "a": ("target",)}, frozenset({"root"}))
    assert path_to(sbom, "target") == ("root", "target")


def test_a_cycle_in_the_graph_does_not_loop_forever() -> None:
    sbom = _sbom({"root": ("a",), "a": ("b",), "b": ("a",)}, frozenset({"root"}))
    assert path_to(sbom, "b") == ("root", "a", "b")


def test_no_graph_data_at_all_is_none_not_a_fabricated_route() -> None:
    sbom = _sbom({}, frozenset())
    assert path_to(sbom, "anything") is None
