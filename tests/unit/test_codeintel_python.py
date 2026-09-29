"""core/codeintel/python_lang.py: symbols, calls and entrypoints via `ast` (plan §20.2)."""

from __future__ import annotations

from core.codeintel.python_lang import extract


def test_functions_and_methods_become_symbols_with_qualified_names() -> None:
    src = """
def top_level():
    pass

class Handler:
    def method(self):
        pass
"""
    u = extract("app.py", src)
    by_name = {s.qualified_name: s for s in u.symbols}
    assert by_name["top_level"].kind == "function"
    assert by_name["Handler.method"].kind == "method"


def test_calls_are_attributed_to_the_enclosing_function() -> None:
    src = """
def caller():
    helper()

def helper():
    pass
"""
    u = extract("app.py", src)
    caller_id = next(s.id for s in u.symbols if s.name == "caller")
    assert (caller_id, "helper", 3) in u.calls


def test_module_level_calls_have_no_caller_and_are_not_recorded() -> None:
    src = "run_at_import_time()\n"
    u = extract("app.py", src)
    assert u.calls == []


def test_decorator_call_is_not_mistaken_for_a_call_the_function_body_makes() -> None:
    """A decorator runs at definition time, in the enclosing scope -- not every time the decorated
    function itself is called."""
    src = """
@app.get("/x")
def handler():
    do_work()
"""
    u = extract("app.py", src)
    caller_id = next(s.id for s in u.symbols if s.name == "handler")
    calls = [c for c in u.calls if c[0] == caller_id]
    assert calls == [(caller_id, "do_work", 4)]


def test_fastapi_route_decorator_is_an_entrypoint() -> None:
    src = """
@app.get("/users/{id}")
def get_user(id):
    pass
"""
    u = extract("app.py", src)
    assert len(u.entrypoints) == 1
    ep = u.entrypoints[0]
    assert ep.framework == "fastapi" and ep.method == "GET" and ep.path == "/users/{id}"


def test_flask_route_decorator_reads_methods_kwarg() -> None:
    src = """
@app.route("/login", methods=["GET", "POST"])
def login():
    pass
"""
    u = extract("app.py", src)
    ep = u.entrypoints[0]
    assert ep.framework == "flask" and ep.method == "GET,POST" and ep.path == "/login"


def test_flask_route_without_methods_defaults_to_get() -> None:
    src = """
@app.route("/home")
def home():
    pass
"""
    u = extract("app.py", src)
    assert u.entrypoints[0].method == "GET"


def test_django_urlpatterns_produces_an_entrypoint_and_a_call_to_the_view() -> None:
    src = """
from . import views
urlpatterns = [
    path("users/", views.list_users),
]
"""
    u = extract("urls.py", src)
    assert len(u.entrypoints) == 1
    ep = u.entrypoints[0]
    assert ep.framework == "django" and ep.method == "" and ep.path == "users/"
    assert (ep.symbol_id, "list_users", 4) in u.calls  # line of the `path(...)` entry itself


def test_two_urlpatterns_entries_with_the_same_route_string_get_distinct_symbol_ids() -> None:
    """Regression test: every entry in one `urlpatterns = [...]` list shares the assignment's own
    line, so keying the synthetic symbol by that line (instead of the entry's own) made two routes
    with the same path string collide on the same symbol_id -- silently losing one of them when
    resolve.py's `symbols[s.id] = s` overwrote it."""
    src = """
from . import views
urlpatterns = [
    path("items/", views.list_items, name="list"),
    path("items/", views.create_item, name="create"),
]
"""
    u = extract("urls.py", src)
    assert len(u.entrypoints) == 2
    assert len({ep.symbol_id for ep in u.entrypoints}) == 2
    assert {c[1] for c in u.calls} == {"list_items", "create_item"}


def test_a_non_route_decorator_is_not_treated_as_an_entrypoint() -> None:
    src = """
@staticmethod
def helper():
    pass

@cache.memoize()
def compute():
    pass
"""
    u = extract("app.py", src)
    assert u.entrypoints == []


def test_syntax_error_is_reported_as_unparsed_not_raised() -> None:
    u = extract("broken.py", "def f(:\n")
    assert u.parsed is False
    assert u.symbols == []
