"""Extracting "this URL route is handled here" from source (Week 49 task 4, plan §22.4) -- the
"code intelligence" `core.dast.correlate` needs to turn a DAST finding's URL path into a file and
line a SAST finding might also be reported against.

Two sources. `routes_from_graph` reads the HTTP entrypoints `core.codeintel` already finds for
every framework it knows (FastAPI, Flask, Django, Express, Next.js, Go's net/http), and is what a
scan uses. `extract_routes_from_source`/`_workspace` recognize only the FastAPI/Flask decorator
shape (`@app.get("/x")`, `@app.route("/x")`), with nothing but Python's `ast`; they are the fallback
when code intelligence did not run. Both normalize each framework's way of writing a path
parameter to one wildcard.

A route from the graph already carries the prefixes its router is mounted under (`include()`,
`include_router`, `register_blueprint`, Express `use`; `core.codeintel.resolve.apply_mounts`). A
Django regex route is read when it is a plain path with capture groups (`regex_route_pattern`).
Still not seen: a route built from a runtime string, a regex with optional parts or alternation,
and mounts the extractors do not follow (docs/adr/0035). A route this misses just never gets a
runtime confirmation -- a conservative miss, not a false claim.
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
# A Django regex route's capture group, named or not, not itself optional or repeated.
_REGEX_GROUP = re.compile(r"\((?:\?P<\w+>)?((?:[^()\\]|\\.)*)\)(?![?*+{])")
_REGEX_ESCAPE = re.compile(r"\\([./\-_~])")
_REGEX_LEFT = re.compile(r"[\^$()?+*|\\\[\]{}]")


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


def regex_route_pattern(regex: str) -> str | None:
    """A Django regex route as a pattern `route_matches` reads, when it is a plain path with
    capture groups: r"^users/(?P<pk>[0-9]+)/$" -> "/users/*". A group that cannot hold a "/" is one
    segment ("*"); one with a bare "." in it (".+", ".*") may be several ("**"). Anything else
    left -- an optional part, an alternation, a character class outside a group -- is None: not
    guessed at."""
    body = regex.strip()
    body = body[1:] if body.startswith("^") else body
    body = body[:-1] if body.endswith("$") and not body.endswith("\\$") else body
    body = body[:-2] if body.endswith("\\Z") else body

    def group(m: re.Match[str]) -> str:
        if m.group(1).startswith("?") or "|" in m.group(1):
            return m.group(0)  # (?:...), a lookahead, an alternation: left, so refused below
        inner = re.sub(r"\[[^\]]*\]", "", m.group(1))  # a class like [^/] says nothing of "."
        return "\x01" if "." in inner.replace("\\.", "") else "\x00"

    body = _REGEX_ESCAPE.sub(r"\1", _REGEX_GROUP.sub(group, body))
    if _REGEX_LEFT.search(body):
        return None
    # Wildcards go in last: normalizing reads a lone "*" segment as Express's catch-all.
    return normalize_route_pattern(body).replace("\x01", "**").replace("\x00", "*")


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
    against). A regex route that is not a plain path is skipped rather than guessed at."""
    targets: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.callee_id is not None:
            targets.setdefault(edge.caller_id, []).append(edge.callee_id)
    handlers: list[RouteHandler] = []
    for entry in graph.entrypoints:
        symbol = graph.symbols.get(entry.symbol_id)
        if symbol is None or not entry.path:
            continue
        route = normalize_route_pattern(entry.path)
        if entry.framework == "django":
            if _REGEX_ROUTE.search(entry.path):
                regex = regex_route_pattern(entry.path)
                if regex is None:
                    continue
                route = regex
            views = [graph.symbols[t] for t in targets.get(symbol.id, []) if t in graph.symbols]
            if not views:
                continue
            symbol = views[0]
        handlers.append(RouteHandler(route, symbol.path, symbol.start_line))
    return sorted(set(handlers), key=lambda h: (h.route, h.path, h.line))
