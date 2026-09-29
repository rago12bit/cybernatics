"""core/codeintel/js_lang.py: symbols, calls and entrypoints via tree-sitter (plan §20.2)."""

from __future__ import annotations

from core.codeintel.js_lang import extract


def test_function_declaration_and_method_become_symbols() -> None:
    src = b"""
function top() {}
class Handler {
  method() {}
}
"""
    u = extract("app.js", src)
    by_name = {s.qualified_name: s for s in u.symbols}
    assert by_name["top"].kind == "function"
    assert by_name["Handler.method"].kind == "method"


def test_const_arrow_function_becomes_a_named_symbol() -> None:
    src = b"const handler = (req, res) => { res.send(1); };"
    u = extract("app.js", src)
    assert any(s.name == "handler" for s in u.symbols)


def test_const_function_expression_becomes_a_named_symbol() -> None:
    """`const x = function () {}` uses tree-sitter's `function_expression` node type, distinct
    from both `arrow_function` and the bare `function` keyword node -- a plain `("arrow_function",
    "function")` type check silently misses it entirely."""
    src = b"const handler = function (req, res) { res.send(1); };"
    u = extract("app.js", src)
    assert any(s.name == "handler" for s in u.symbols)


def test_express_route_with_inline_function_keyword_handler_gets_its_own_symbol() -> None:
    src = b"""
app.get('/users', function (req, res) {
  res.send(getUsers());
});
"""
    u = extract("routes.js", src)
    assert len(u.entrypoints) == 1
    calls = [c for c in u.calls if c[0] == u.entrypoints[0].symbol_id]
    assert "getUsers" in [c[1] for c in calls]


def test_calls_are_attributed_to_the_enclosing_function() -> None:
    src = b"""
function caller() { helper(); }
function helper() {}
"""
    u = extract("app.js", src)
    caller_id = next(s.id for s in u.symbols if s.name == "caller")
    assert (caller_id, "helper", 2) in u.calls


def test_method_call_uses_the_property_name() -> None:
    src = b"""
function f() { obj.doThing(); }
"""
    u = extract("app.js", src)
    caller_id = next(s.id for s in u.symbols if s.name == "f")
    assert (caller_id, "doThing", 2) in u.calls


def test_express_route_with_inline_handler_gets_its_own_symbol_and_body_calls() -> None:
    src = b"""
app.get('/users', (req, res) => {
  res.send(getUsers());
});
"""
    u = extract("routes.js", src)
    assert len(u.entrypoints) == 1
    ep = u.entrypoints[0]
    assert ep.framework == "express" and ep.method == "GET" and ep.path == "/users"
    calls = [c for c in u.calls if c[0] == ep.symbol_id]
    assert ("getUsers" in [c[1] for c in calls]) and ("send" in [c[1] for c in calls])


def test_express_route_with_named_handler_calls_it_by_name() -> None:
    src = b"""
router.post('/login', loginHandler);
"""
    u = extract("routes.js", src)
    ep = u.entrypoints[0]
    assert ep.framework == "express" and ep.method == "POST" and ep.path == "/login"
    assert (ep.symbol_id, "loginHandler", 2) in u.calls


def test_express_route_with_object_method_handler_calls_it_by_name() -> None:
    """`app.get('/login', sessionHandler.displayLoginPage)` -- a handler referenced as a method on
    a controller object (a `member_expression`, not a bare `identifier`), exactly NodeGoat's own
    routing style."""
    src = b"""
app.get('/login', sessionHandler.displayLoginPage);
"""
    u = extract("routes.js", src)
    ep = u.entrypoints[0]
    assert ep.framework == "express" and ep.method == "GET" and ep.path == "/login"
    assert (ep.symbol_id, "displayLoginPage", 2) in u.calls


def test_a_single_argument_get_call_is_not_an_entrypoint() -> None:
    """Entrypoint detection needs a path *and* a handler argument; `cache.get('key')` (one
    argument, no handler to attach an Entrypoint to) must not produce one, even though it matches
    the verb name."""
    src = b"const value = cache.get('key');"
    u = extract("app.js", src)
    assert u.entrypoints == []


def test_nextjs_app_router_exported_verb_functions_are_entrypoints() -> None:
    src = b"""
export async function GET(req) { return NextResponse.json(await list()); }
export async function POST(req) { return NextResponse.json(await create()); }
"""
    u = extract("app/api/users/[id]/route.ts", src, typescript=True)
    by_method = {e.method: e for e in u.entrypoints}
    assert by_method["GET"].framework == "nextjs" and by_method["GET"].path == "/api/users/[id]"
    assert by_method["POST"].path == "/api/users/[id]"


def test_nextjs_pages_api_default_export_is_an_entrypoint() -> None:
    src = b"export default function handler(req, res) { res.json(getData()); }"
    u = extract("pages/api/data.ts", src, typescript=True)
    assert len(u.entrypoints) == 1
    ep = u.entrypoints[0]
    assert ep.framework == "nextjs" and ep.path == "/api/data"


def test_a_route_file_outside_app_or_pages_is_not_treated_as_nextjs() -> None:
    src = b"export function GET() {}"
    u = extract("src/route.ts", src, typescript=True)
    assert u.entrypoints == []


def test_constructor_function_this_method_assignment_becomes_a_symbol() -> None:
    """The pre-ES6-class "constructor function" idiom -- `this.method = (req, res) => {...}`
    inside `function Foo(db) {...}` -- still common in real code (NodeGoat's whole route layer is
    written this way). Without this case, these methods never become Symbols at all and every
    route that calls them stays permanently unresolved."""
    src = b"""
function SessionHandler(db) {
  this.displayLoginPage = (req, res) => {
    res.render('login');
  };
}
"""
    u = extract("session.js", src)
    by_name = {s.qualified_name: s for s in u.symbols}
    assert "SessionHandler.displayLoginPage" in by_name
    sid = by_name["SessionHandler.displayLoginPage"].id
    assert (sid, "render", 4) in u.calls


def test_commonjs_module_exports_property_assignment_becomes_a_symbol() -> None:
    src = b"module.exports.getUsers = function () { return db.find(); };"
    u = extract("controller.js", src)
    assert any(s.name == "getUsers" for s in u.symbols)


def test_syntax_error_is_reported_as_unparsed_not_raised() -> None:
    u = extract("broken.js", b"function f( {")
    assert u.parsed is False
