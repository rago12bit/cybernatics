"""Extracting "this URL route is handled here" from Python source (Week 49 task 4, plan §22.4) --
the "code intelligence" `core.dast.correlate` needs to turn a DAST finding's URL path into a file
and line a SAST finding might also be reported against.

Recognizes the FastAPI/Flask-style decorator shape this very project's own `api/main.py` uses
(`@app.get("/assets/{id}")`, `@router.post(...)`, Flask's `@app.route("/x", methods=[...])`) via
Python's `ast` module -- no new parser dependency, and it can be (and is, in the live verification
test) run against Bulwark's own API module as a real, checkable example.

Deliberately NOT a general-purpose router/framework analyzer: it recognizes one decorator shape,
not Django's urls.py table, not a framework with no decorator-based routing, not a route built from
a runtime string. A route this misses just never gets a runtime-confirmation for it -- a
conservative miss, not a false claim.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

_HTTP_DECORATOR_METHODS = frozenset({"get", "post", "put", "delete", "patch", "route"})
_PATH_PARAM = re.compile(r"\{[^/{}]+\}")


@dataclass(frozen=True)
class RouteHandler:
    route: str  # normalized pattern, e.g. "/assets/*/campaigns"
    path: str  # file path, relative to the scanned workspace
    line: int  # 1-based line of the `def`, matching Location.start_line's convention


def normalize_route_pattern(route: str) -> str:
    """ "/assets/{asset_id}/campaigns" -> "/assets/*/campaigns": a DAST finding's concrete URL
    ("/assets/9c1.../campaigns") has no way to know the framework's own parameter name, so both
    sides of the match are reduced to the same wildcard shape."""
    normalized = _PATH_PARAM.sub("*", route)
    return normalized.rstrip("/") or "/"


def route_matches(pattern: str, concrete_path: str) -> bool:
    concrete = concrete_path.rstrip("/") or "/"
    normalized_pattern = pattern.rstrip("/") or "/"
    regex = "^" + re.escape(normalized_pattern).replace(r"\*", "[^/]+") + "$"
    return re.match(regex, concrete) is not None


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
