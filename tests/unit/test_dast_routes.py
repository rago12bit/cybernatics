"""core.dast.routes: route extraction (code graph and decorators) and path normalization
(Week 49 task 4, plan §22.4)."""

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


def test_each_frameworks_path_parameters_normalize_to_one_wildcard() -> None:
    assert normalize_route_pattern("/users/<int:user_id>/posts") == "/users/*/posts"  # Flask
    assert normalize_route_pattern("users/<int:pk>/") == "/users/*"  # Django, no leading slash
    assert normalize_route_pattern("/api/products/:id") == "/api/products/*"  # Express
    assert normalize_route_pattern("/p/:id?/edit") == "/p/*/edit"  # Express, optional
    assert normalize_route_pattern("/api/orders/[id]") == "/api/orders/*"  # Next.js
    assert normalize_route_pattern("GET /items/{id}") == "/items/*"  # Go 1.22 net/http
    # Parameters that span segments.
    assert normalize_route_pattern("/docs/[...slug]") == "/docs/**"
    assert normalize_route_pattern("/[[...all]]") == "/**"
    assert normalize_route_pattern("/files/*") == "/files/**"


def test_a_catch_all_matches_one_or_more_segments_and_a_parameter_exactly_one() -> None:
    assert route_matches("/docs/**", "/docs/a/b/c") is True
    assert route_matches("/docs/**", "/docs") is False
    assert route_matches("/docs/*", "/docs/a/b") is False


MULTI_FRAMEWORK = {
    "shop/urls.py": (
        "from django.urls import path, re_path\nfrom . import views\n\n"
        "urlpatterns = [\n"
        '    path("search/", views.search),\n'
        '    re_path(r"^legacy/(?P<slug>[-\\w]+)/$", views.legacy),\n'
        "]\n"
    ),
    "shop/views.py": (
        "from django.db import connection\n\n"
        "def search(request):\n"
        '    q = request.GET["q"]\n'
        "    connection.cursor().execute(\"SELECT * FROM t WHERE name = '%s'\" % q)\n\n"
        "def legacy(request, slug):\n"
        "    return None\n"
    ),
    "server.js": (
        'const express = require("express");\nconst app = express();\n'
        'app.get("/api/products/:id", (req, res) => { res.send(req.params.id); });\n'
    ),
    "app/api/orders/[id]/route.ts": "export async function GET(request: Request) { return Response.json({}); }\n",
    "api.py": (
        'from fastapi import FastAPI\napp = FastAPI()\n\n@app.get("/assets/{asset_id}")\n'
        "def asset(asset_id: str):\n    return {}\n"
    ),
}


def _workspace(root: Path) -> Path:
    for rel, source in MULTI_FRAMEWORK.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(source)
    return root


def test_routes_come_from_every_framework_code_intelligence_knows(tmp_path: Path) -> None:
    """The decorator extractor sees only the FastAPI route here; the code graph sees all of them.
    A Django route's handler is the view it names, in views.py, not its line in urls.py; a regex
    route is skipped rather than guessed at."""
    from core.codeintel import analyze
    from core.dast.routes import RouteHandler, routes_from_graph

    root = _workspace(tmp_path)
    assert [h.route for h in extract_routes_from_workspace(root)] == ["/assets/*"]
    assert routes_from_graph(analyze(root)) == [
        RouteHandler("/api/orders/*", "app/api/orders/[id]/route.ts", 1),
        RouteHandler("/api/products/*", "server.js", 3),
        RouteHandler("/assets/*", "api.py", 5),
        RouteHandler("/search", "shop/views.py", 3),
    ]


def test_a_django_views_sql_injection_is_confirmed_by_a_dast_finding_on_its_url(
    tmp_path: Path,
) -> None:
    """End to end on real code intelligence: before, no Django route reached the route map, so this
    could never be confirmed at runtime."""
    from core.codeintel import analyze
    from core.dast.correlate import correlate_dast_with_sast
    from core.dast.routes import routes_from_graph
    from core.models import Category, Finding, Location, Taxonomy

    handlers = routes_from_graph(analyze(_workspace(tmp_path)))
    dast = Finding(id="d1", title="SQL injection", description="",
                   location=Location(path="", start_line=0, end_line=0, route="/search"),
                   taxonomy=Taxonomy(category=Category.DAST, cwe=("CWE-89",)))  # fmt: skip
    sast = Finding(id="s1", title="SQL built from a string", description="",
                   location=Location(path="shop/views.py", start_line=5, end_line=5, route=""),
                   taxonomy=Taxonomy(category=Category.SAST, cwe=("CWE-89",)))  # fmt: skip
    [confirmed] = correlate_dast_with_sast([dast], [sast], handlers)
    assert (confirmed.sast_finding_id, confirmed.route) == ("s1", "/search")
