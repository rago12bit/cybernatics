"""core/taint/go_flow.py: intra-procedural taint tracking and function-summary computation for Go,
via tree-sitter (plan §20.3)."""

from __future__ import annotations

import pytest
from tree_sitter import Language, Parser

from core.taint.catalog import load_catalog
from core.taint.go_flow import analyze_function, param_names
from core.taint.models import SOURCE, FunctionSummary, SinkHit


@pytest.fixture
def cat():
    return load_catalog("go")


@pytest.fixture
def parser():
    import tree_sitter_go as go

    return Parser(Language(go.language()))


def _fn(parser, src: bytes):
    return parser.parse(src).root_node.children[1]  # [0] is the package_clause


def test_direct_source_to_sink_is_found(parser, cat) -> None:
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + userId
	db.Query(query)
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1
    assert sinks[0].sink_name == "Query" and sinks[0].category == "sql_injection"


def test_a_sink_with_no_tainted_argument_is_not_reported(parser, cat) -> None:
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	db.Query("SELECT 1")
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert sinks == []


def test_branch_taint_is_unioned_not_path_sensitive(parser, cat) -> None:
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	var userId string
	if true {
		userId = r.URL.Query().Get("id")
	} else {
		userId = "const"
	}
	db.Query(userId)
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_range_loop_propagates_iterable_taint_to_the_loop_variable(parser, cat) -> None:
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	for _, v := range ids {
		exec.Command(v)
	}
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1 and sinks[0].sink_name == "Command"


def test_c_style_for_loop_initializer_is_not_skipped(parser, cat) -> None:
    """Regression test: a C-style `for init; cond; post { }`'s clauses live inside their own
    `for_clause` node (distinct from the `range_clause` a `for ... range` loop uses) -- previously
    nothing looked inside it at all, so `id`'s own taint (from a tainted initializer) was silently
    lost before the body ever ran."""
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	for id := r.URL.Query().Get("id"); id != ""; id = "" {
		db.Query(id)
	}
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_summary_records_which_param_reaches_the_return_value(parser, cat) -> None:
    src = b"package main\nfunc identity(x string) string { return x }"
    returns, sinks = analyze_function(
        _fn(parser, src), "util.go", {"x": frozenset({0})}, lambda n: None, {}, cat
    )
    assert returns == frozenset({0}) and sinks == []


def test_summary_records_a_sink_reachable_from_its_own_parameter(parser, cat) -> None:
    src = b"package main\nfunc helper(x string) { db.Query(x) }"
    returns, sinks = analyze_function(
        _fn(parser, src), "db.go", {"x": frozenset({0})}, lambda n: None, {}, cat
    )
    assert returns == frozenset()
    assert len(sinks) == 1 and sinks[0].params == frozenset({0}) and sinks[0].path == "db.go"


def test_a_real_two_hop_call_reaches_the_real_sink_through_a_callee_summary(parser, cat) -> None:
    helper_summary = FunctionSummary(
        symbol_id="db.go:helper:1",
        sinks=(SinkHit(frozenset({0}), "db.go", 1, "Query", "sql_injection"),),
        returns=frozenset(),
    )
    src = b"""
package main
func view(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	helper(userId)
}
"""
    _, sinks = analyze_function(
        _fn(parser, src),
        "view.go",
        {"r": frozenset({SOURCE})},
        lambda n: "db.go:helper:1" if n == "helper" else None,
        {"db.go:helper:1": helper_summary},
        cat,
    )
    assert len(sinks) == 1
    assert sinks[0].path == "db.go" and sinks[0].line == 1
    assert sinks[0].params == frozenset({SOURCE})


def test_an_unresolved_callee_passes_taint_through_conservatively(parser, cat) -> None:
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	safeLooking := transform(userId)
	db.Query(safeLooking)
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_param_names_for_a_function_declaration(parser) -> None:
    src = b"package main\nfunc f(a string, b int) {}"
    assert param_names(_fn(parser, src)) == ["a", "b"]


def test_else_if_chain_merges_taint_across_all_branches(parser, cat) -> None:
    src = b"""
package main
func handler(w http.ResponseWriter, r *http.Request) {
	var userId string
	if false {
		userId = "const1"
	} else if true {
		userId = r.URL.Query().Get("id")
	} else {
		userId = "const2"
	}
	db.Query(userId)
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "main.go", {"r": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1
