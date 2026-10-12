"""Python extraction (plan §20.2): symbols, call sites and entrypoints via the standard `ast`
module -- no tree-sitter-python dependency needed, the same choice `core/reachability/imports.py`
already made for Python (a real parser already ships with the interpreter)."""

from __future__ import annotations

import ast

from core.codeintel.models import (
    Entrypoint,
    FileUnit,
    Mount,
    Symbol,
    join_route,
    symbol_id,
)

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
    framework = method = path = router = ""
    for i, dec in enumerate(fn.decorator_list):
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
            continue
        router = dec.func.value.id if isinstance(dec.func.value, ast.Name) else ""
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
    return Entrypoint(sid, framework, method, path, markers, router)


def _package(path: str) -> list[str]:
    """The dotted package a file is in, from its path: "app/api/main.py" -> ["app", "api"]."""
    return path.split("/")[:-1]


def _kw(call: ast.Call, name: str) -> str | None:
    return next((_string_const(k.value) for k in call.keywords if k.arg == name), None)


def _kw_name(call: ast.Call, name: str) -> str:
    """The constant a keyword argument names, when it is not a literal: `prefix=API_PREFIX` or
    `prefix=settings.API_V1_STR` -> the last name; "" otherwise."""
    value = next((k.value for k in call.keywords if k.arg == name), None)
    return _attr_chain_name(value) or "" if isinstance(value, (ast.Name, ast.Attribute)) else ""


def _attr_parts(node: ast.expr) -> list[str] | None:
    """`a.b.c` -> ["a", "b", "c"]; None for anything but names and attributes."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return [node.id, *reversed(parts)]


class _Extractor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.unit = FileUnit(path=path, language="python")
        self._scope: list[tuple[str, bool]] = []  # (name, is_class), outermost first
        self._callers: list[str] = []  # symbol ids of enclosing functions, for call edges
        # A name this file imported -> (module, attribute or ""): `from shop import urls` binds
        # "urls" to ("shop", "urls"); `import shop.urls as u` binds "u" to ("shop.urls", "").
        self._imports: dict[str, tuple[str, str]] = {}

    # --- imports and mounts (prefixes `resolve.apply_mounts` adds to routes) ----------------------

    def _absolute(self, module: str | None, level: int) -> str:
        if not level:
            return module or ""
        base = _package(self.path)
        base = base[: len(base) - (level - 1)] if level > 1 else base
        return ".".join([*base, *([module] if module else [])])

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            if alias.asname:
                self._imports[alias.asname] = (alias.name, "")
            else:
                head = alias.name.split(".")[0]
                self._imports[head] = (head, "")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = self._absolute(node.module, node.level)
        for alias in node.names:
            self._imports[alias.asname or alias.name] = (module, alias.name)

    def _target(self, node: ast.expr, *, urls_module: bool = False) -> tuple[str, str] | None:
        """What `include_router(...)`/`register_blueprint(...)` names, as (module, router):
        `users.router` -> ("app.users", "router"), an imported `router` -> its module and name, a
        router of this file -> ("", name). Django's `include(...)` names a whole urls module
        (`urls_module`), by a dotted string or an imported module: (module, "urlpatterns")."""
        if (dotted := _string_const(node)) is not None:
            return (dotted, "urlpatterns") if urls_module else None
        parts = _attr_parts(node)
        if not parts or parts[0] not in self._imports:
            return ("", parts[0]) if parts and len(parts) == 1 and not urls_module else None
        module, attr = self._imports[parts[0]]
        full = [p for p in (module, attr, *parts[1:]) if p]
        if urls_module:
            return ".".join(full), "urlpatterns"
        return ".".join(full[:-1]), full[-1]

    def _mount(self, node: ast.Call) -> None:
        if not (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)):
            return
        how = node.func.attr
        if how not in ("include_router", "register_blueprint") or not node.args:
            return
        target = self._target(node.args[0])
        if target is None:
            return
        key = "prefix" if how == "include_router" else "url_prefix"
        prefix, named = _kw(node, key), _kw_name(node, key)
        replaces = how == "register_blueprint" and (prefix is not None or bool(named))
        self.unit.mounts.append(Mount(self.path, node.func.value.id, prefix or "", *target,
                                      replaces=replaces, prefix_name=named))  # fmt: skip

    def _router_prefix(self, node: ast.Assign) -> None:
        """`router = APIRouter(prefix="/u")`, `bp = Blueprint("u", __name__, url_prefix="/u")`."""
        call = node.value
        if not (isinstance(call, ast.Call) and len(node.targets) == 1):
            return
        target = node.targets[0]
        kind = _attr_chain_name(call.func)
        key = {"APIRouter": "prefix", "Blueprint": "url_prefix"}.get(kind or "")
        if not key or not isinstance(target, ast.Name):
            return
        if prefix := _kw(call, key):
            self.unit.prefixes[target.id] = prefix
        elif named := _kw_name(call, key):
            self.unit.prefix_names[target.id] = named

    def _constant(self, target: ast.expr, value: ast.expr | None) -> None:
        """`NAME = "..."` or `NAME: str = "..."` outside any function (a module or a class body)."""
        if not self._callers and isinstance(target, ast.Name):
            if (literal := _string_const(value)) is not None:
                self.unit.constants.setdefault(target.id, literal)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self._constant(node.target, node.value)
        self.generic_visit(node)

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
        self._mount(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets):
            self._django_urlpatterns(node.value)
        self._router_prefix(node)
        if len(node.targets) == 1:
            self._constant(node.targets[0], node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        if isinstance(node.target, ast.Name) and node.target.id == "urlpatterns":
            self._django_urlpatterns(node.value)  # `urlpatterns += [...]`
        self.generic_visit(node)

    def _django_urlpatterns(self, value: ast.expr, prefix: str = "") -> None:
        """`urlpatterns = [path("route/", view), re_path(r"^route/$", view), ...]` -- Django names
        no HTTP verb in urls.py itself (a view decides which methods it accepts), so `method` is
        left blank rather than guessed. `path("api/", include("shop.urls"))` mounts another urls
        module under "api/"; `include([...])`, a list in place, is read here, under its prefix."""
        if not isinstance(value, ast.List):
            return
        for elt in value.elts:
            if not (isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name)):
                continue
            if elt.func.id not in ("path", "re_path", "url") or not elt.args:
                continue
            route = _string_const(elt.args[0])
            if route is None:
                continue
            arg = elt.args[1] if len(elt.args) > 1 else None
            if isinstance(arg, ast.Call) and _attr_chain_name(arg.func) == "include" and arg.args:
                included = arg.args[0]
                if isinstance(included, ast.Tuple) and included.elts:  # include((patterns, "app"))
                    included = included.elts[0]
                if isinstance(included, ast.List):
                    self._django_urlpatterns(included, join_route(prefix, route))
                elif (target := self._target(included, urls_module=True)) is not None:
                    self.unit.mounts.append(Mount(self.path, "urlpatterns",
                                                  join_route(prefix, route), *target))  # fmt: skip
                continue
            route = join_route(prefix, route)
            view_name = _attr_chain_name(arg) if arg is not None else None
            if not view_name:
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
            self.unit.entrypoints.append(Entrypoint(sid, "django", "", route, (), "urlpatterns"))
            self.unit.calls.append((sid, view_name, elt.lineno))


def extract(path: str, source: str) -> FileUnit:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return FileUnit(path=path, language="python", parsed=False)
    ext = _Extractor(path)
    ext.visit(tree)
    return ext.unit
