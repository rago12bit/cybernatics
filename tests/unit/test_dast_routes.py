"""core.dast.routes's FastAPI/Flask-style decorator extraction (Week 49 task 4, plan §22.4)."""

from __future__ import annotations

from pathlib import Path

from core.dast.routes import (
    extract_routes_from_source,
    extract_routes_from_workspace,
    normalize_route_pattern,
    route_matches,
)


def test_extracts_a_simple_fastapi_get_route() -> None:
    source = """
@app.get("/healthz")
def healthz():
    return {"ok": True}
"""
    handlers = extract_routes_from_source(source, "api/main.py")
    assert len(handlers) == 1
    assert handlers[0].route == "/healthz"
    assert handlers[0].path == "api/main.py"
    # ast.FunctionDef.lineno is the `def` line itself, not the decorator above it -- closer to
    # where the handler's actual body (and any vulnerable code in it) lives.
    assert handlers[0].line == 3


def test_extracts_a_path_parameter_route_as_a_wildcard() -> None:
    source = """
@app.get("/assets/{asset_id}/overview")
def get_overview(asset_id: str):
    pass
"""
    handlers = extract_routes_from_source(source, "api/main.py")
    assert handlers[0].route == "/assets/*/overview"


def test_extracts_an_async_def_route() -> None:
    source = """
@router.post("/scans")
async def create_scan(body):
    pass
"""
    handlers = extract_routes_from_source(source, "api/main.py")
    assert len(handlers) == 1
    assert handlers[0].route == "/scans"


def test_extracts_flask_style_route_decorator() -> None:
    source = """
@app.route("/login", methods=["POST"])
def login():
    pass
"""
    handlers = extract_routes_from_source(source, "app.py")
    assert handlers[0].route == "/login"


def test_ignores_non_http_decorators() -> None:
    source = """
@dataclass
@property
def not_a_route():
    pass
"""
    assert extract_routes_from_source(source, "x.py") == []


def test_ignores_a_decorator_with_a_non_string_first_argument() -> None:
    source = """
@app.get(SOME_CONSTANT)
def dynamic_route():
    pass
"""
    assert extract_routes_from_source(source, "x.py") == []


def test_a_syntax_error_yields_no_routes_instead_of_raising() -> None:
    assert extract_routes_from_source("def broken(:\n", "x.py") == []


def test_normalize_route_pattern_strips_trailing_slash_and_params() -> None:
    assert normalize_route_pattern("/assets/{id}/issues/{issue_id}/") == "/assets/*/issues/*"
    assert normalize_route_pattern("/") == "/"


def test_route_matches_a_concrete_path_against_a_wildcard_pattern() -> None:
    assert route_matches("/assets/*/campaigns", "/assets/9c1a2b3c/campaigns") is True
    assert route_matches("/assets/*/campaigns", "/assets/9c1a2b3c/issues") is False
    assert route_matches("/assets/*/campaigns", "/assets/a/b/campaigns") is False


def test_route_matches_handles_trailing_slashes_on_either_side() -> None:
    assert route_matches("/healthz", "/healthz/") is True
    assert route_matches("/healthz/", "/healthz") is True


def test_extract_routes_from_workspace_walks_every_python_file(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.py").write_text('@app.get("/a")\ndef a():\n    pass\n')
    (tmp_path / "b.py").write_text('@app.post("/b")\ndef b():\n    pass\n')
    (tmp_path / "not_python.txt").write_text('@app.get("/ignored")')
    handlers = extract_routes_from_workspace(tmp_path)
    assert {h.route for h in handlers} == {"/a", "/b"}


def test_live_against_bulwark_s_own_api_main_finds_the_real_new_routes() -> None:
    """A real, checkable example rather than a synthetic one: this project's own api/main.py has
    well over a thousand lines and dozens of real FastAPI routes, including the ones this very week
    added (/assets/web, /assets/{id}/verify, /assets/{id}/campaigns) -- extracting them for real is
    a stronger proof the decorator-matching logic works than any hand-built fixture alone."""
    source = (Path(__file__).resolve().parents[2] / "api" / "main.py").read_text()
    handlers = extract_routes_from_source(source, "api/main.py")
    routes = {h.route for h in handlers}
    assert "/assets/web" in routes
    assert "/assets/*/verify" in routes
    assert "/assets/*/campaigns" in routes
    assert len(handlers) > 30  # this file has dozens of real routes
