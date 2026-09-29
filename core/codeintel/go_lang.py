"""Go extraction (plan §20.2): symbols, call sites and entrypoints via tree-sitter-go."""

from __future__ import annotations

from core.codeintel.models import Entrypoint, FileUnit, Symbol, symbol_id

_HANDLE_FUNCS = frozenset({"HandleFunc", "Handle"})

_PARSER: object | None = None


def _parser() -> object:
    global _PARSER
    if _PARSER is None:
        import tree_sitter_go as go
        from tree_sitter import Language, Parser

        _PARSER = Parser(Language(go.language()))
    return _PARSER


def _text(node) -> str:  # type: ignore[no-untyped-def]
    return node.text.decode("utf-8", "replace") if node.text else ""


def _string_literal(node) -> str | None:  # type: ignore[no-untyped-def]
    if node is None or node.type not in ("interpreted_string_literal", "raw_string_literal"):
        return None
    return _text(node).strip('`"')


def _receiver_type(method_node) -> str | None:  # type: ignore[no-untyped-def]
    """`func (s *Server) Handle()` -> "Server" -- the receiver, pointer or value, that qualifies
    the method's name (Go has no classes; a method is only ever grouped with its type this way)."""
    receiver = method_node.child_by_field_name("receiver")
    if receiver is None or not receiver.named_children:
        return None
    type_node = receiver.named_children[0].child_by_field_name("type")
    if type_node is None:
        return None
    if type_node.type == "pointer_type":
        type_node = type_node.named_children[0] if type_node.named_children else None
    return _text(type_node) if type_node is not None else None


def _callee_name(func_node) -> str | None:  # type: ignore[no-untyped-def]
    if func_node is None:
        return None
    if func_node.type == "identifier":
        return _text(func_node)
    if func_node.type == "selector_expression":
        field = func_node.child_by_field_name("field")
        return _text(field) if field is not None else None
    return None


class _Extractor:
    def __init__(self, path: str) -> None:
        self.path = path
        self.unit = FileUnit(path=path, language="go")

    def _add_symbol(self, name: str, qname: str, kind: str, node) -> str:  # type: ignore[no-untyped-def]
        sid = symbol_id(self.path, qname, node.start_point[0] + 1)
        self.unit.symbols.append(
            Symbol(
                sid, self.path, name, qname, kind,
                node.start_point[0] + 1, node.end_point[0] + 1, "go",
            )  # fmt: skip
        )
        return sid

    def _handle_func_entrypoint(self, call_node) -> None:  # type: ignore[no-untyped-def]
        """`http.HandleFunc("/path", handler)` / `mux.Handle("/path", handler)` -- any receiver
        object, matched by method name shape like the other languages' route-registration
        detection, since resolving whether `mux` is really a `*http.ServeMux` needs real type
        inference this pass doesn't do."""
        fn = call_node.child_by_field_name("function")
        if fn is None or fn.type != "selector_expression":
            return
        field = fn.child_by_field_name("field")
        if field is None or _text(field) not in _HANDLE_FUNCS:
            return
        args = call_node.child_by_field_name("arguments")
        if args is None or len(args.named_children) < 2:
            return
        path = _string_literal(args.named_children[0])
        if path is None:
            return
        handler = args.named_children[1]
        is_ref = handler.type in ("identifier", "selector_expression")
        name = _callee_name(handler) if is_ref else None
        if name is None:
            return
        # The registration call itself becomes a tiny synthetic symbol whose one call is to the
        # handler's name -- resolve.py links it by name, like Python's Django urlpatterns handling.
        qname = f"<route:{path}:{call_node.start_point[0] + 1}>"
        sid = self._add_symbol("<route>", qname, "function", call_node)
        self.unit.entrypoints.append(Entrypoint(sid, "net/http", "", path))
        self.unit.calls.append((sid, name, handler.start_point[0] + 1))

    def visit(self, node, caller: str | None) -> None:  # type: ignore[no-untyped-def]
        t = node.type
        if t == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = _text(name_node)
                sid = self._add_symbol(name, name, "function", node)
                body = node.child_by_field_name("body")
                if body is not None:
                    self.visit(body, sid)
                return
        elif t == "method_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = _text(name_node)
                recv = _receiver_type(node)
                qname = f"{recv}.{name}" if recv else name
                sid = self._add_symbol(name, qname, "method", node)
                body = node.child_by_field_name("body")
                if body is not None:
                    self.visit(body, sid)
                return
        elif t == "call_expression":
            self._handle_func_entrypoint(node)
            if caller is not None:
                callee = _callee_name(node.child_by_field_name("function"))
                if callee:
                    self.unit.calls.append((caller, callee, node.start_point[0] + 1))
        for c in node.children:
            self.visit(c, caller)


def extract(path: str, source: bytes) -> FileUnit:
    try:
        tree = _parser().parse(source)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a file we cannot parse is reported as such, never fatal
        return FileUnit(path=path, language="go", parsed=False)
    ext = _Extractor(path)
    ext.visit(tree.root_node, None)
    if tree.root_node.has_error:
        ext.unit.parsed = False
    return ext.unit
