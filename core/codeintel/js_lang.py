"""JavaScript/TypeScript extraction (plan §20.2): symbols, call sites and entrypoints via
tree-sitter, the same grammars `core/reachability/imports.py` already parses JS/TS with.

Only *named* functions (declarations, methods, `const x = () => {}`) and inline route-handler
callbacks (the one place an anonymous function needs its own identity, to attach an Entrypoint to)
get their own Symbol. An ordinary inline callback elsewhere (`.map(x => ...)`, a `setTimeout`
callback) has its calls folded into whichever named function encloses it, rather than becoming a
call-graph node of its own -- a deliberate simplification: for the reachability question this graph
exists to answer ("is X reachable from an entrypoint"), a call made from inside a closure is exactly
as reachable as the function that created the closure, so nothing is lost by not giving it a
separate identity, and the graph stays proportional to *named* code structure instead of every
closure literal.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from core.codeintel.models import Entrypoint, FileUnit, Symbol, symbol_id

_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "options", "head"})
_EXPRESS_METHODS = _HTTP_METHODS | {"all"}  # Express also routes generically on `.all(...)`
_NEXT_APP_ROUTE = re.compile(r"(^|/)app/(.*)/route\.(t|j)sx?$")
_NEXT_PAGES_API = re.compile(r"(^|/)pages/api/(.*)\.(t|j)sx?$")


def _parser(typescript: bool):  # type: ignore[no-untyped-def]
    from tree_sitter import Language, Parser

    if typescript:
        import tree_sitter_typescript as ts

        return Parser(Language(ts.language_typescript()))
    import tree_sitter_javascript as js

    return Parser(Language(js.language()))


_PARSERS: dict[bool, object] = {}


def _text(node) -> str:  # type: ignore[no-untyped-def]
    raw = node.text.decode("utf-8", "replace") if node.text else ""
    return raw


def _string_literal(node) -> str | None:  # type: ignore[no-untyped-def]
    if node is None or node.type != "string":
        return None
    return _text(node).strip("'\"`")


def _callee_name(func_node) -> str | None:  # type: ignore[no-untyped-def]
    if func_node is None:
        return None
    if func_node.type == "identifier":
        return _text(func_node)
    if func_node.type == "member_expression":
        prop = func_node.child_by_field_name("property")
        return _text(prop) if prop is not None else None
    return None


def _next_route_path(rel_path: str) -> tuple[str, str] | None:
    """("app", "/api/users/[id]") for app/api/users/[id]/route.ts, or ("pages", "/api/users") for
    pages/api/users.ts -- close to Next.js's real convention, not exact: route groups `(name)` are
    not stripped, and a `[...slug]` catch-all is left as-is rather than expanded."""
    m = _NEXT_APP_ROUTE.search(rel_path)
    if m:
        return "app", "/" + m.group(2)
    m = _NEXT_PAGES_API.search(rel_path)
    if m:
        return "pages", "/api/" + m.group(2)
    return None


class _Extractor:
    def __init__(self, path: str, language: str) -> None:
        self.path = path
        self.unit = FileUnit(path=path, language=language)
        self._scope: list[tuple[str, bool]] = []  # (name, is_class)
        self._callers: list[str] = []
        self._anon_count = 0
        self._next_route = _next_route_path(path)
        # Byte spans already fully handled (symbol registered, body walked) by a special case
        # (e.g. an inline route handler) so the generic recursion in visit() doesn't process the
        # same node a second time with the wrong (or no) caller context.
        self._handled: set[tuple[int, int]] = set()

    def _qualified_name(self, name: str) -> str:
        return ".".join((*(n for n, _ in self._scope), name)) if self._scope else name

    def _in_class(self) -> bool:
        return bool(self._scope) and self._scope[-1][1]

    def _add_symbol(self, name: str, node, exported: bool) -> str:  # type: ignore[no-untyped-def]
        qname = self._qualified_name(name)
        sid = symbol_id(self.path, qname, node.start_point[0] + 1)
        kind = "method" if self._in_class() else "function"
        self.unit.symbols.append(
            Symbol(
                sid, self.path, name, qname, kind,
                node.start_point[0] + 1, node.end_point[0] + 1, self.unit.language,
            )  # fmt: skip
        )
        if self._next_route is not None and not self._scope:
            kind_, route = self._next_route
            if kind_ == "app" and exported and name.lower() in _HTTP_METHODS:
                self.unit.entrypoints.append(Entrypoint(sid, "nextjs", name.upper(), route))
            elif kind_ == "pages" and exported and name in ("default", "handler"):
                self.unit.entrypoints.append(Entrypoint(sid, "nextjs", "", route))
        return sid

    def _walk_function_body(self, sid: str, body) -> None:  # type: ignore[no-untyped-def]
        self._callers.append(sid)
        self.visit(body)
        self._callers.pop()

    def _express_entrypoint(self, call_node) -> None:  # type: ignore[no-untyped-def]
        """`app.get('/path', handler)` / `router.post('/path', mw, handler)` -- matched by shape
        (an HTTP-verb-or-`use`/`all` method call with a string path), the same documented,
        decorator-free heuristic core.codeintel.python_lang uses for Flask/FastAPI."""
        fn = call_node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return
        prop = fn.child_by_field_name("property")
        verb = _text(prop).lower() if prop is not None else ""
        if verb not in _EXPRESS_METHODS:
            return
        args = call_node.child_by_field_name("arguments")
        if args is None or not args.named_children:
            return
        path = _string_literal(args.named_children[0])
        if path is None:
            return
        handler = args.named_children[-1]
        # Every argument between the path and the final handler is middleware -- e.g. `router.get(
        # path, requireAuth, checkOwner, handler)`, or `passport.authenticate('jwt')` called inline
        # -- captured by name only (plan §21.4's `auth_markers`), the same "shape, not resolution"
        # heuristic `_express_entrypoint` itself already uses for the route registration.
        markers = tuple(
            n
            for a in args.named_children[1:-1]
            if (
                n := (
                    _callee_name(a.child_by_field_name("function"))
                    if a.type == "call_expression"
                    else _callee_name(a)
                )
            )
        )
        if handler.type in ("arrow_function", "function_expression"):
            # An inline handler has no other name to resolve it by: give it a synthetic one, walk
            # its body right here (with the correct caller context), and mark its span handled so
            # the generic recursion below doesn't re-visit it with the wrong caller.
            self._anon_count += 1
            sid = self._add_symbol(f"<route-handler-{self._anon_count}>", handler, exported=False)
            self.unit.entrypoints.append(Entrypoint(sid, "express", verb.upper(), path, markers))
            body = handler.child_by_field_name("body")
            if body is not None:
                self._walk_function_body(sid, body)
            self._handled.add((handler.start_byte, handler.end_byte))
        elif handler.type in ("identifier", "member_expression"):
            # A named reference -- a bare function (`app.get('/x', loginHandler)`) or, just as
            # common in practice (controller objects, e.g. NodeGoat's own routes:
            # `app.get('/login', sessionHandler.displayLoginPage)`), a method on one
            # (`_callee_name` already knows how to read either shape). The registration call
            # itself becomes a tiny synthetic symbol whose one call is to that name, exactly like
            # core.codeintel.python_lang's Django urlpatterns handling -- resolve.py links it by
            # name like any other call, once the real handler's own symbol is found elsewhere.
            name = _callee_name(handler)
            if name is None:
                return
            self._anon_count += 1
            qname = f"<route:{path}:{self._anon_count}>"
            sid = symbol_id(self.path, qname, call_node.start_point[0] + 1)
            self.unit.symbols.append(
                Symbol(
                    sid, self.path, "<route>", qname, "function",
                    call_node.start_point[0] + 1, call_node.start_point[0] + 1, self.unit.language,
                )  # fmt: skip
            )
            self.unit.entrypoints.append(Entrypoint(sid, "express", verb.upper(), path, markers))
            self.unit.calls.append((sid, name, handler.start_point[0] + 1))

    def visit(self, node) -> None:  # type: ignore[no-untyped-def]
        if (node.start_byte, node.end_byte) in self._handled:
            return
        t = node.type
        if t in ("function_declaration", "function_expression", "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else f"<anon-{id(node)}>"
            exported = node.parent is not None and node.parent.type == "export_statement"
            sid = self._add_symbol(name, node, exported)
            body = node.child_by_field_name("body")
            if body is not None:
                self._scope.append((name, False))
                self._walk_function_body(sid, body)
                self._scope.pop()
            return
        if t == "method_definition":
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else "<anon>"
            sid = self._add_symbol(name, node, exported=False)
            body = node.child_by_field_name("body")
            if body is not None:
                self._scope.append((name, False))
                self._walk_function_body(sid, body)
                self._scope.pop()
            return
        if t == "variable_declarator":
            value = node.child_by_field_name("value")
            name_node = node.child_by_field_name("name")
            is_fn = value is not None and value.type in ("arrow_function", "function_expression")
            if is_fn and name_node is not None:
                name = _text(name_node)
                exported = (
                    node.parent is not None
                    and node.parent.parent is not None
                    and node.parent.parent.type == "export_statement"
                )
                sid = self._add_symbol(name, value, exported)
                body = value.child_by_field_name("body")
                if body is not None:
                    self._scope.append((name, False))
                    self._walk_function_body(sid, body)
                    self._scope.pop()
                return
        if t == "assignment_expression":
            # `this.method = (req, res) => {...}` (the pre-ES6-class "constructor function" idiom,
            # still common in real code -- NodeGoat's whole route layer is written this way) and
            # `module.exports.foo = function () {...}` (CommonJS) both put a function's identity on
            # the right of an assignment whose left side names it, rather than in a declaration.
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            is_fn = right is not None and right.type in ("arrow_function", "function_expression")
            if is_fn and left is not None and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                if prop is not None:
                    name = _text(prop)
                    sid = self._add_symbol(name, right, exported=False)
                    body = right.child_by_field_name("body")
                    if body is not None:
                        self._scope.append((name, False))
                        self._walk_function_body(sid, body)
                        self._scope.pop()
                    return
        if t == "class_declaration":
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node is not None else "<anon>"
            self._scope.append((name, True))
            for c in node.children:
                self.visit(c)
            self._scope.pop()
            return
        if t == "call_expression":
            self._express_entrypoint(node)
            fn = node.child_by_field_name("function")
            callee = _callee_name(fn)
            if callee and self._callers:
                self.unit.calls.append((self._callers[-1], callee, node.start_point[0] + 1))
        for c in node.children:
            self.visit(c)


def extract(path: str, source: bytes, typescript: bool = False) -> FileUnit:
    language = "typescript" if typescript else "javascript"
    try:
        parser = _PARSERS.get(typescript) or _PARSERS.setdefault(typescript, _parser(typescript))
        tree = parser.parse(source)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a file we cannot parse is reported as such, never fatal
        return FileUnit(path=path, language=language, parsed=False)
    ext = _Extractor(PurePosixPath(path).as_posix(), language)
    ext.visit(tree.root_node)
    if tree.root_node.has_error:
        ext.unit.parsed = False
    return ext.unit
