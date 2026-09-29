"""core/taint/js_flow.py: intra-procedural taint tracking and function-summary computation for
JavaScript/TypeScript, via tree-sitter (plan §20.3)."""

from __future__ import annotations

import pytest
from tree_sitter import Language, Parser

from core.taint.catalog import load_catalog
from core.taint.js_flow import analyze_function, param_names
from core.taint.models import SOURCE, FunctionSummary, SinkHit


@pytest.fixture
def cat():
    return load_catalog("javascript")


@pytest.fixture
def parser():
    import tree_sitter_javascript as js

    return Parser(Language(js.language()))


def _fn(parser, src: bytes):
    return parser.parse(src).root_node.children[0]


def test_direct_source_to_sink_is_found(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var userId = req.query.id;
  var query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "routes.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1
    assert sinks[0].sink_name == "query" and sinks[0].category == "sql_injection"


def test_a_sink_with_no_tainted_argument_is_not_reported(parser, cat) -> None:
    src = b'function handler(req, res) { db.query("SELECT 1"); }'
    _, sinks = analyze_function(
        _fn(parser, src), "routes.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert sinks == []


def test_sanitizer_removes_taint(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var userId = req.query.id;
  var safe = escape(userId);
  db.query("SELECT " + safe);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "routes.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert sinks == []


def test_template_literal_and_ternary_propagate_taint(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var q = req.query.q;
  var cmd = q ? q : "default";
  exec(`echo ${cmd}`);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "routes.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1 and sinks[0].sink_name == "exec"


def test_branch_taint_is_unioned_not_path_sensitive(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var userId;
  if (true) {
    userId = req.query.id;
  } else {
    userId = "const";
  }
  db.query(userId);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_summary_records_which_param_reaches_the_return_value(parser, cat) -> None:
    src = b"function identity(x) { return x; }"
    returns, sinks = analyze_function(
        _fn(parser, src), "util.js", {"x": frozenset({0})}, lambda n: None, {}, cat
    )
    assert returns == frozenset({0}) and sinks == []


def test_summary_records_a_sink_reachable_from_its_own_parameter(parser, cat) -> None:
    src = b"function helper(x) { db.query(x); }"
    returns, sinks = analyze_function(
        _fn(parser, src), "db.js", {"x": frozenset({0})}, lambda n: None, {}, cat
    )
    assert returns == frozenset()
    assert len(sinks) == 1 and sinks[0].params == frozenset({0}) and sinks[0].path == "db.js"


def test_a_real_two_hop_call_reaches_the_real_sink_through_a_callee_summary(parser, cat) -> None:
    helper_summary = FunctionSummary(
        symbol_id="db.js:helper:1",
        sinks=(SinkHit(frozenset({0}), "db.js", 1, "query", "sql_injection"),),
        returns=frozenset(),
    )
    src = b"function view(req, res) { var userId = req.query.id; helper(userId); }"
    _, sinks = analyze_function(
        _fn(parser, src),
        "view.js",
        {"req": frozenset({SOURCE})},
        lambda n: "db.js:helper:1" if n == "helper" else None,
        {"db.js:helper:1": helper_summary},
        cat,
    )
    assert len(sinks) == 1
    assert sinks[0].path == "db.js" and sinks[0].line == 1
    assert sinks[0].params == frozenset({SOURCE})


def test_an_unresolved_callee_passes_taint_through_conservatively(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var userId = req.query.id;
  var safeLooking = transform(userId);
  db.query(safeLooking);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_param_names_for_a_function_declaration(parser) -> None:
    src = b"function f(a, b) {}"
    assert param_names(_fn(parser, src)) == ["a", "b"]


@pytest.fixture
def ts_parser():
    import tree_sitter_typescript as ts

    return Parser(Language(ts.language_typescript()))


def test_param_names_handles_typescripts_required_parameter_wrapping(ts_parser) -> None:
    """Found via real-world validation (docs/v2-week38-verification.md): tree-sitter-typescript
    wraps every arrow-function parameter in a `required_parameter` node, even with no type
    annotation at all -- plain JavaScript's grammar never does this, so a `param_names` that only
    recognized a bare `identifier` silently returned no parameters for any TypeScript handler,
    meaning its `req`-like source was never seeded at all."""
    src = b"const f = (req: Request, res: Response) => {};"
    fn = ts_parser.parse(src).root_node.children[0].children[1].child_by_field_name("value")
    assert param_names(fn) == ["req", "res"]


def test_typescript_as_cast_does_not_strip_taint(ts_parser, cat) -> None:
    """Found via real-world validation: a `value as T` cast (and `value!`, `value satisfies T`)
    produced no case in `expr_taint`, so the fallthrough `frozenset()` silently dropped taint
    through any type cast -- a very common pattern in real TypeScript handler code."""
    src = b"""
app.get("/search", (req, res) => {
  const q: string = req.query.q as string;
  db.query("SELECT * FROM t WHERE name = '" + q + "'");
});
"""
    tree = ts_parser.parse(src)
    call = tree.root_node.children[0].named_children[0]
    handler = call.child_by_field_name("arguments").named_children[1]
    _, sinks = analyze_function(
        handler, "routes.ts", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_for_of_loop_target_inherits_iterable_taint(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var ids = req.query.ids;
  for (const i of ids) {
    db.query(i);
  }
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_while_loop_body_is_walked(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var q = req.query.q;
  while (q) {
    db.query(q);
    q = null;
  }
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_c_style_for_loop_initializer_is_not_skipped(parser, cat) -> None:
    """Regression test: `for (let i = ...; ...; ...)`'s initializer is a direct child of
    `for_statement`, not the body -- it was previously never visited at all, so `i`'s own taint
    (from a tainted initializer) was silently lost."""
    src = b"""
function handler(req, res) {
  for (let i = req.query.id; i; i = null) {
    db.query(i);
  }
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_compound_assignment_combines_old_and_new_taint(parser, cat) -> None:
    """Regression test: `x += y` is its own tree-sitter node type (`augmented_assignment_expression`),
    distinct from plain `assignment_expression` -- it previously matched no branch in `visit()` at
    all, so it was a silent no-op that never updated `x`'s taint."""
    src = b"""
function handler(req, res) {
  var q = "SELECT ";
  q += req.query.id;
  db.query(q);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_try_catch_merges_taint_across_body_and_handler(parser, cat) -> None:
    src = b"""
function handler(req, res) {
  var q;
  try {
    q = req.query.q;
  } catch (e) {
    q = "safe";
  }
  db.query(q);
}
"""
    _, sinks = analyze_function(
        _fn(parser, src), "a.js", {"req": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1
