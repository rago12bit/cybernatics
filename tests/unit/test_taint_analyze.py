"""core.taint::analyze() (plan §20.3): the end-to-end walk wiring core.codeintel's call graph,
per-language flow analysis, and the call-graph worklist together, across real directory trees."""

from __future__ import annotations

from pathlib import Path

import pytest

from core import taint


def test_a_real_cross_file_sqli_is_found_with_a_full_hop_chain(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n\n"
        '@app.route("/search")\n'
        "def search():\n"
        '    q = request.args.get("q")\n'
        "    return helper(q)\n\n"
        "def helper(term):\n"
        '    query = "SELECT * FROM t WHERE name = \'" + term + "\'"\n'
        "    return db.execute(query)\n"
    )
    result = taint.analyze(tmp_path)
    assert len(result.graph.entrypoints) == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "sql_injection"
    assert finding.sink_path == "app.py" and finding.sink_name == "execute"
    assert len(finding.hops) == 2
    assert "entrypoint" in finding.hops[0].description.lower()
    assert "helper" in finding.hops[1].description


def test_a_sanitized_value_produces_no_finding(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n\n"
        '@app.route("/search")\n'
        "def search():\n"
        '    q = request.args.get("q")\n'
        "    safe = escape(q)\n"
        '    return db.execute("SELECT * FROM t WHERE name = \'" + safe + "\'")\n'
    )
    result = taint.analyze(tmp_path)
    assert result.findings == []


def test_no_sink_at_all_produces_no_finding(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n\n"
        '@app.route("/hello")\n'
        "def hello():\n"
        '    return "hi " + request.args.get("name")\n'
    )
    result = taint.analyze(tmp_path)
    assert result.findings == []


def test_a_real_javascript_express_sqli_is_found(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "app.get('/search', (req, res) => {\n"
        "  var q = req.query.q;\n"
        '  db.query("SELECT * FROM t WHERE name = \'" + q + "\'");\n'
        "});\n"
    )
    result = taint.analyze(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].category == "sql_injection"


def test_a_real_typescript_express_sqli_is_found(tmp_path: Path) -> None:
    """Regression for a real bug found via validation: tree-sitter-typescript wraps every arrow
    function parameter in a `required_parameter` node, so before the fix a TypeScript handler's
    `req`-like source was never seeded at all -- this app.py-level test is what first caught it,
    since none of the synthetic JS-only tests exercised the TypeScript grammar."""
    (tmp_path / "routes.ts").write_text(
        'app.get("/search", (req, res) => {\n'
        "  const q: string = req.query.q as string;\n"
        '  db.query("SELECT * FROM t WHERE name = \'" + q + "\'");\n'
        "});\n"
    )
    result = taint.analyze(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].category == "sql_injection"


def test_a_real_go_command_injection_is_found(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '\tcmd := r.URL.Query().Get("cmd")\n'
        "\texec.Command(cmd)\n"
        "}\n\n"
        "func main() {\n"
        '\thttp.HandleFunc("/run", handler)\n'
        "}\n"
    )
    result = taint.analyze(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].category == "command_injection"


def test_analyze_or_none_never_raises_even_on_a_missing_root() -> None:
    assert taint.analyze_or_none(Path("/does/not/exist/at/all")) is not None


def test_analyze_or_none_catches_a_real_failure_and_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a: object, **kw: object) -> None:
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(taint, "analyze", boom)
    assert taint.analyze_or_none(tmp_path) is None


def test_a_named_handler_route_registration_resolves_to_the_real_handlers_body(
    tmp_path: Path,
) -> None:
    """`app.get('/login', sessionHandler.displayLoginPage)` mints a synthetic entrypoint symbol
    with no body of its own (`core.codeintel.js_lang`) -- the engine must follow its one call edge
    to `SessionHandler.displayLoginPage`'s real body to find anything at all. This is the exact
    pattern that makes NodeGoat's own routing work (see docs/v2-week38-verification.md)."""
    (tmp_path / "routes.js").write_text(
        'const sessionHandler = require("./session");\n'
        'app.get("/login", sessionHandler.displayLoginPage);\n'
    )
    (tmp_path / "session.js").write_text(
        "function SessionHandler(db) {\n"
        "  this.displayLoginPage = (req, res) => {\n"
        '    db.query("SELECT * FROM users WHERE id = " + req.query.id);\n'
        "  };\n"
        "}\n"
        "module.exports = SessionHandler;\n"
    )
    result = taint.analyze(tmp_path)
    assert len(result.graph.entrypoints) == 1
    assert len(result.findings) == 1
    assert result.findings[0].sink_path == "session.js"


def test_an_unresolvable_redirect_produces_no_finding_and_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text('app.get("/x", someUndefinedModule.handler);\n')
    result = taint.analyze(tmp_path)
    assert len(result.graph.entrypoints) == 1
    assert result.findings == []


def test_the_same_sink_reached_by_two_call_paths_is_reported_once(tmp_path: Path) -> None:
    """`view` reaches `shared`'s one real sink through two different branches (`a` and `b`) --
    still one real vulnerability, not two, so `find_taint_paths` de-dupes by the sink's own
    location rather than by how many internal paths lead to it."""
    (tmp_path / "app.py").write_text(
        "from flask import request\n\n"
        '@app.route("/x")\n'
        "def view():\n"
        '    q = request.args.get("q")\n'
        "    if q:\n"
        "        a(q)\n"
        "    else:\n"
        "        b(q)\n\n"
        "def a(x):\n"
        "    shared(x)\n\n"
        "def b(x):\n"
        "    shared(x)\n\n"
        "def shared(x):\n"
        "    cursor.execute(x)\n"
    )
    result = taint.analyze(tmp_path)
    assert len(result.findings) == 1


def test_mutual_recursion_does_not_hang_summary_computation(tmp_path: Path) -> None:
    """Two functions that call each other must not loop forever in the worklist -- bounded by
    `engine.MAX_WORKLIST_PASSES`, and this test's own timeout (via pytest-timeout-free real
    execution) is the actual proof it terminates at all."""
    (tmp_path / "app.py").write_text(
        "from flask import request\n\n"
        '@app.route("/x")\n'
        "def a(n):\n"
        "    if n > 0:\n"
        "        return b(n - 1)\n"
        '    return request.args.get("q")\n\n'
        "def b(n):\n"
        "    return a(n)\n"
    )
    result = taint.analyze(tmp_path)  # must simply return, not hang
    assert result.graph.files_parsed == 1
