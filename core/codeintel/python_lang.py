"""Python extraction (plan §20.2): symbols, call sites and entrypoints via the standard `ast`
module -- no tree-sitter-python dependency needed, the same choice `core/reachability/imports.py`
already made for Python (a real parser already ships with the interpreter)."""

from __future__ import annotations

import ast

from core.codeintel.models import Entrypoint, FileUnit, Symbol, symbol_id

_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "options", "head"})


def _attr_chain_name(node: ast.expr) -> str | None:
    """`app.get` -> "get"; bare `Name` -> its id; anything else (a subscript, a call) -> None."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _string_const(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _decorator_name(dec: ast.expr) -> str | None:
    """The name a decorator is written under -- `@login_required` -> "login_required",
    `@auth.requires_role("admin")` -> "requires_role", `@app.get(...)` -> "get". Used only to test
    against a keyword heuristic (`core.hypotheses.facts`), never resolved to a real definition."""
    if isinstance(dec, ast.Call):
        return _attr_chain_name(dec.func)
    return _attr_chain_name(dec)


def _route_entrypoint(fn: ast.FunctionDef | ast.AsyncFunctionDef, sid: str) -> Entrypoint | None:
    """`@app.get("/path")` (FastAPI) or `@app.route("/path", methods=[...])` (Flask) -- and their
    equivalents on any object named like a router (`router.get(...)`, `api.route(...)`): matched by
    decorator *shape* (an HTTP-verb-or-`route` method call with a string path), not by which package
    was actually imported, since reliably resolving that needs far more than decorator inspection.
    A false positive is a decorator that merely looks like a route registration; documented, not
    hidden, same as the plan's own instruction for this whole feature.

    Every OTHER decorator on the same function becomes an `auth_markers` entry (plan §21.4) --
    whatever it's actually called, not filtered to a known auth allowlist here (that judgement is
    `core.hypotheses.facts`'s, kept out of extraction so the two stay independently testable)."""
    route_index: int | None = None
    framework = method = path = ""
    for i, dec in enumerate(fn.decorator_list):
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
            continue
        verb = dec.func.attr.lower()
        p = _string_const(dec.args[0]) if dec.args else None
        if p is None:
            continue
        if verb in _HTTP_METHODS:
            route_index, framework, method, path = i, "fastapi", verb.upper(), p
            break
        if verb == "route":
            methods = next((kw.value for kw in dec.keywords if kw.arg == "methods"), None)
            verbs = (
                sorted({v.upper() for m in methods.elts if (v := _string_const(m))})
                if isinstance(methods, ast.List)
                else ["GET"]
            )
            route_index, framework, method, path = i, "flask", ",".join(verbs), p
            break
    if route_index is None:
        return None
    markers = tuple(
        name
        for i, dec in enumerate(fn.decorator_list)
        if i != route_index and (name := _decorator_name(dec))
    )
    return Entrypoint(sid, framework, method, path, markers)


class _Extractor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.unit = FileUnit(path=path, language="python")
        self._scope: list[tuple[str, bool]] = []  # (name, is_class), outermost first
        self._callers: list[str] = []  # symbol ids of enclosing functions, for call edges

    def _qualified_name(self, name: str) -> str:
        return ".".join((*(n for n, _ in self._scope), name)) if self._scope else name

    def _in_class(self) -> bool:
        return bool(self._scope) and self._scope[-1][1]

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = self._qualified_name(node.name)
        kind = "method" if self._in_class() else "function"
        sid = symbol_id(self.path, qname, node.lineno)
        end = getattr(node, "end_lineno", None) or node.lineno
        self.unit.symbols.append(
            Symbol(sid, self.path, node.name, qname, kind, node.lineno, end, "python")
        )
        entry = _route_entrypoint(node, sid)
        if entry is not None:
            self.unit.entrypoints.append(entry)
        # Decorators run at *definition* time, in the enclosing scope -- visited before this
        # function's own frame is pushed, or `@app.get(...)` would wrongly look like a call the
        # function makes on every invocation of itself.
        for dec in node.decorator_list:
            self.visit(dec)
        self._scope.append((node.name, False))
        self._callers.append(sid)
        for stmt in node.body:
            self.visit(stmt)
        self._callers.pop()
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802 - ast visitor naming
        self._scope.append((node.name, True))
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._function(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if self._callers:
            name = _attr_chain_name(node.func)
            if name:
                self.unit.calls.append((self._callers[-1], name, node.lineno))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self._django_urlpatterns(node)
        self.generic_visit(node)

    def _django_urlpatterns(self, node: ast.Assign) -> None:
        """`urlpatterns = [path("route/", view), re_path(r"^route/$", view), ...]` -- Django names
        no HTTP verb in urls.py itself (a view decides which methods it accepts), so `method` is
        left blank rather than guessed."""
        if not any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets):
            return
        if not isinstance(node.value, ast.List):
            return
        for elt in node.value.elts:
            if not (isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name)):
                continue
            if elt.func.id not in ("path", "re_path", "url") or not elt.args:
                continue
            route = _string_const(elt.args[0])
            view_name = _attr_chain_name(elt.args[1]) if len(elt.args) > 1 else None
            if route is None or not view_name:
                continue
            # No symbol to attach this route to yet (the view is defined elsewhere, possibly in
            # another file) -- represent the registration itself as a tiny synthetic function
            # whose one call is to the view, so resolve.py can link it by name like any other call.
            # Keyed by the route *entry's* own line (elt.lineno), not the enclosing `urlpatterns =
            # [...]` assignment's line (node.lineno): every entry in one list shares the latter, so
            # two routes with the same path string (a real, if unusual, case -- e.g. the same path
            # registered under different names for A/B testing) would otherwise collide on the same
            # symbol_id and silently overwrite each other in resolve.py's `symbols` dict.
            qname = f"urlpatterns:{route}"
            sid = symbol_id(self.path, qname, elt.lineno)
            self.unit.symbols.append(
                Symbol(
                    sid, self.path, "urlpatterns", qname, "function",
                    elt.lineno, elt.lineno, "python",
                )  # fmt: skip
            )
            self.unit.entrypoints.append(Entrypoint(sid, "django", "", route))
            self.unit.calls.append((sid, view_name, elt.lineno))


def extract(path: str, source: str) -> FileUnit:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return FileUnit(path=path, language="python", parsed=False)
    ext = _Extractor(path)
    ext.visit(tree)
    return ext.unit
