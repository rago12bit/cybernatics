"""core/taint/python_flow.py: intra-procedural taint tracking and function-summary computation
for Python (plan §20.3)."""

from __future__ import annotations

import ast

import pytest

from core.taint.catalog import load_catalog
from core.taint.models import SOURCE, FunctionSummary, SinkHit
from core.taint.python_flow import analyze_function, param_names


@pytest.fixture
def cat():
    return load_catalog("python")


def _fn(src: str) -> ast.FunctionDef:
    return ast.parse(src).body[0]  # type: ignore[return-value]


def test_direct_source_to_sink_is_found(cat) -> None:
    src = """
def view(request):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1
    assert sinks[0].sink_name == "execute" and sinks[0].category == "sql_injection"
    assert sinks[0].params == frozenset({SOURCE})


def test_a_sink_with_no_tainted_argument_is_not_reported(cat) -> None:
    src = """
def view(request):
    cursor.execute("SELECT * FROM users")
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert sinks == []


def test_sanitizer_removes_taint(cat) -> None:
    src = """
def view(request):
    user_id = request.args.get("id")
    safe_id = escape(user_id)
    cursor.execute("SELECT " + safe_id)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert sinks == []


def test_reassignment_with_a_clean_value_removes_taint(cat) -> None:
    src = """
def view(request):
    user_id = request.args.get("id")
    user_id = "constant"
    cursor.execute(user_id)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert sinks == []


def test_fstring_propagates_taint(cat) -> None:
    src = """
def view(request):
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_summary_records_which_param_reaches_the_return_value(cat) -> None:
    src = """
def identity(x):
    return x
"""
    returns, sinks = analyze_function(
        _fn(src), "util.py", {"x": frozenset({0})}, lambda n: None, {}, cat
    )
    assert returns == frozenset({0}) and sinks == []


def test_summary_records_a_sink_reachable_from_its_own_parameter(cat) -> None:
    src = """
def helper(x):
    cursor.execute(x)
"""
    returns, sinks = analyze_function(
        _fn(src), "db.py", {"x": frozenset({0})}, lambda n: None, {}, cat
    )
    assert returns == frozenset()
    assert len(sinks) == 1 and sinks[0].params == frozenset({0}) and sinks[0].path == "db.py"


def test_a_global_source_sink_propagates_unconditionally_through_any_caller(cat) -> None:
    """`log_user_agent` reads Flask's `request` global directly (not through a parameter), so its
    exposure is unconditional -- calling it from anywhere propagates the finding, even from a
    caller with no connection to `request` in its own parameters at all."""
    helper_src = """
def log_user_agent():
    cursor.execute("INSERT INTO log VALUES ('" + request.headers.get("User-Agent") + "')")
"""
    helper_fn = _fn(helper_src)
    _, h_sinks = analyze_function(
        helper_fn, "log.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(h_sinks) == 1 and h_sinks[0].params == frozenset({SOURCE})
    helper_summary = FunctionSummary("log.py:log_user_agent:1", tuple(h_sinks), frozenset())

    caller_src = """
def some_unrelated_function():
    log_user_agent()
"""
    _, c_sinks = analyze_function(
        _fn(caller_src),
        "other.py",
        {},
        lambda n: "log.py:log_user_agent:1" if n == "log_user_agent" else None,
        {"log.py:log_user_agent:1": helper_summary},
        cat,
    )
    assert len(c_sinks) == 1
    assert c_sinks[0].path == "log.py" and c_sinks[0].params == frozenset({SOURCE})


def test_a_real_two_hop_call_reaches_the_real_sink_through_a_callee_summary(cat) -> None:
    """`view` calls `helper`, which is where the real `cursor.execute` lives -- the finding must
    report `helper`'s own file and line, not `view`'s, even though the taint started in `view`."""
    helper_summary = FunctionSummary(
        symbol_id="db.py:helper:1",
        sinks=(SinkHit(frozenset({0}), "db.py", 3, "execute", "sql_injection"),),
        returns=frozenset(),
    )
    src = """
def view(request):
    user_id = request.args.get("id")
    helper(user_id)
"""
    _, sinks = analyze_function(
        _fn(src),
        "app.py",
        {"request": frozenset({SOURCE})},
        lambda n: "db.py:helper:1" if n == "helper" else None,
        {"db.py:helper:1": helper_summary},
        cat,
    )
    assert len(sinks) == 1
    assert sinks[0].path == "db.py" and sinks[0].line == 3
    assert sinks[0].params == frozenset({SOURCE})
    assert len(sinks[0].hops) == 1
    assert sinks[0].hops[0].symbol_id == "db.py:helper:1"
    assert (
        sinks[0].hops[0].path == "app.py" and sinks[0].hops[0].line == 4
    )  # the `helper(user_id)` call


def test_an_unresolved_callee_passes_taint_through_conservatively(cat) -> None:
    """No summary exists for `transform` (unresolved, or a third-party function): the safer
    default for a security tool is to assume taint survives the call, not to silently drop it."""
    src = """
def view(request):
    user_id = request.args.get("id")
    safe_looking = transform(user_id)
    cursor.execute(safe_looking)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_branch_taint_is_unioned_not_path_sensitive(cat) -> None:
    """A documented over-approximation (module docstring): both branches feed the same tainted-name
    map, so a variable tainted in only one branch is still seen as tainted afterward."""
    src = """
def view(request):
    if True:
        user_id = request.args.get("id")
    else:
        user_id = "constant"
    cursor.execute(user_id)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_param_names_returns_positional_and_keyword_only_params() -> None:
    src = "def f(a, b, *, c):\n    pass\n"
    assert param_names(_fn(src)) == ["a", "b", "c"]


def test_augmented_assignment_propagates_taint(cat) -> None:
    src = """
def view(request):
    q = ""
    q += request.args.get("id")
    cursor.execute(q)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_annotated_assignment_propagates_taint(cat) -> None:
    src = """
def view(request):
    q: str = request.args.get("id")
    cursor.execute(q)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_with_statement_bound_name_propagates_taint(cat) -> None:
    src = """
def view(request):
    with open(request.args.get("id")) as q:
        cursor.execute(q)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_try_except_merges_taint_across_body_and_handler(cat) -> None:
    src = """
def view(request):
    try:
        q = request.args.get("id")
    except Exception:
        q = "safe"
    cursor.execute(q)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_for_loop_target_inherits_iterable_taint(cat) -> None:
    src = """
def view(request):
    ids = request.args.getlist("id")
    for i in ids:
        cursor.execute(i)
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_list_comprehension_propagates_taint(cat) -> None:
    src = """
def view(request):
    ids = request.args.getlist("id")
    cleaned = [i for i in ids]
    cursor.execute(cleaned[0])
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1


def test_boolop_and_dict_literal_propagate_taint(cat) -> None:
    src = """
def view(request):
    q = request.args.get("id") or "default"
    d = {"k": q}
    cursor.execute(d["k"])
"""
    _, sinks = analyze_function(
        _fn(src), "app.py", {"request": frozenset({SOURCE})}, lambda n: None, {}, cat
    )
    assert len(sinks) == 1
