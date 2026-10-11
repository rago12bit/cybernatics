"""Extracting "this URL route is handled here" from source (Week 49 task 4, plan §22.4) -- the
"code intelligence" `core.dast.correlate` needs to turn a DAST finding's URL path into a file and
line a SAST finding might also be reported against.

Two sources. `routes_from_graph` reads the HTTP entrypoints `core.codeintel` already finds for
every framework it knows (FastAPI, Flask, Django, Express, Next.js, Go's net/http), and is what a
scan uses. `extract_routes_from_source`/`_workspace` recognize only the FastAPI/Flask decorator
shape (`@app.get("/x")`, `@app.route("/x")`), with nothing but Python's `ast`; they are the fallback
when code intelligence did not run. Both normalize each framework's way of writing a path
parameter to one wildcard.

Still not seen: a route built from a runtime string, a Django regex route (`re_path`), and the
prefix an `include()` or a mounted router adds (the pattern is then the app-relative part, which a
full URL will not match). A route this misses just never gets a runtime confirmation -- a
conservative miss, not a false claim.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from core.codeintel.models import CodeGraph

_HTTP_DECORATOR_METHODS = frozenset({"get", "post", "put", "delete", "patch", "route"})
# One path segment's parameter, as each framework writes it: {id} (FastAPI, Go), <int:id> (Flask,
# Django), :id (Express), [id] (Next.js).
_PATH_PARAM = re.compile(r"\{[^/{}]+\}|<[^/<>]+>|:[A-Za-z_][\w]*\??|\[[^/\[\].]+\]")
# Any number of segments: Next.js [...slug] / [[...slug]], Express's bare *.
_CATCH_ALL = re.compile(r"\[\[?\.\.\.[^/\]]+\]\]?|(?<=/)\*(?=/|$)")
_GO_METHOD = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+")
_REGEX_ROUTE = re.compile(r"[\^$()?+|\\]")


@dataclass(frozen=True)
class RouteHandler:
    route: str  # normalized pattern, e.g. "/assets/*/campaigns"
    path: str  # file path, relative to the scanned workspace
    line: int  # 1-based line of the `def`, matching Location.start_line's convention


def normalize_route_pattern(route: str) -> str:
    """ "/assets/{asset_id}/campaigns" -> "/assets/*/campaigns", and likewise "<int:id>", ":id" and
    "[id]": a DAST finding's concrete URL ("/assets/9c1.../campaigns") has no way to know the
    framework's own parameter name, so both sides of the match are reduced to the same wildcard
    shape. A parameter that spans segments ("[...slug]", Express's "*") becomes "**". Django's
    patterns have no leading slash; one is added."""
    normalized = _CATCH_ALL.sub("**", _GO_METHOD.sub("", route.strip()))
    normalized = _PATH_PARAM.sub("*", normalized)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized.rstrip("/") or "/"


def route_matches(pattern: str, concrete_path: str) -> bool:
    concrete = concrete_path.rstrip("/") or "/"
    normalized_pattern = pattern.rstrip("/") or "/"
    regex = re.escape(normalized_pattern).replace(r"\*\*", ".+").replace(r"\*", "[^/]+")
    return re.match("^" + regex + "$", concrete) is not None


def _decorator_route(deco: ast.expr) -> str | None:
    if not isinstance(deco, ast.Call) or not isinstance(deco.func, ast.Attribute):
        return None
    if deco.func.attr not in _HTTP_DECORATOR_METHODS:
        return None
    if not deco.args:
        return None
    first = deco.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def extract_routes_from_source(source: str, path: str) -> list[RouteHandler]:
    """`path` is just carried through into each `RouteHandler` -- this function does no I/O of its
    own, so it can be unit-tested with an in-memory string. A syntax error in the file (incomplete
    edits, a non-Python file misdetected) yields no routes rather than raising: one unparsable file
    must not fail route extraction for the rest of the scan."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    handlers: list[RouteHandler] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            route = _decorator_route(deco)
            if route is not None:
                handlers.append(
                    RouteHandler(route=normalize_route_pattern(route), path=path, line=node.lineno)
                )
    return handlers


def extract_routes_from_workspace(root: Path, *, max_files: int = 2000) -> list[RouteHandler]:
    """Walks every `.py` file under `root` (a scan's checked-out workspace). `max_files` is a safety
    bound, not a tuning knob -- a workspace with more Python files than that is not what this was
    designed for, and scanning all of them anyway would make an ordinary SAST scan's duration
    unpredictable for a feature (DAST correlation) most of its callers never use."""
    handlers: list[RouteHandler] = []
    for i, file in enumerate(root.rglob("*.py")):
        if i >= max_files:
            break
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        handlers.extend(extract_routes_from_source(source, str(file.relative_to(root))))
    return handlers


def routes_from_graph(graph: CodeGraph) -> list[RouteHandler]:
    """Every HTTP entrypoint `core.codeintel` found, with its handler's file and line. A Django
    route is registered in urls.py and handled by the view it names: the graph keeps the
    registration as a small symbol whose one call is to that view, so the handler is that call's
    target (an unresolved view gives no handler: there is no location to match a SAST finding
    against). Regex routes are skipped rather than guessed at."""
    targets: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.callee_id is not None:
            targets.setdefault(edge.caller_id, []).append(edge.callee_id)
    handlers: list[RouteHandler] = []
    for entry in graph.entrypoints:
        symbol = graph.symbols.get(entry.symbol_id)
        if symbol is None or not entry.path:
            continue
        if entry.framework == "django":
            if _REGEX_ROUTE.search(entry.path):
                continue
            views = [graph.symbols[t] for t in targets.get(symbol.id, []) if t in graph.symbols]
            if not views:
                continue
            symbol = views[0]
        handlers.append(RouteHandler(normalize_route_pattern(entry.path), symbol.path,
                                     symbol.start_line))  # fmt: skip
    return sorted(set(handlers), key=lambda h: (h.route, h.path, h.line))
