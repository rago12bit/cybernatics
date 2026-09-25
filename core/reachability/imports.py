"""Which packages does a source file import? Parsed with real parsers, never executed.

Python uses the standard `ast` module; JavaScript and TypeScript use tree-sitter. Both give the set
of *package* names a file pulls in (relative imports and Node built-ins are not packages) plus every
string literal, so a package that is loaded by name from config (plugins, loaders) can be told apart
from one that is genuinely unused.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

MAX_FILE_BYTES = 1_000_000  # bounds parse time on a hostile or generated file
MAX_STRINGS = 5000

# Node built-ins that never come from a dependency (import "fs", "node:fs").
NODE_BUILTINS = frozenset(
    "assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel "
    "dns domain events fs http http2 https inspector module net os path perf_hooks process punycode "
    "querystring readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm "
    "wasi worker_threads zlib".split()
)


@dataclass
class FileImports:
    packages: set[str] = field(default_factory=set)
    strings: set[str] = field(default_factory=set)
    parsed: bool = True


def js_package(spec: str) -> str | None:
    """`lodash/fp` -> lodash, `@scope/pkg/x` -> @scope/pkg, `./x`, `node:fs`, `fs` -> None."""
    if not spec or spec[0] in "./" or "\\" in spec or spec.startswith(("node:", "data:", "http")):
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]
    return None if name in NODE_BUILTINS else name


def python_imports(source: str) -> FileImports:
    out = FileImports()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        out.parsed = False
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.packages.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                out.packages.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and node.args:
            fn = node.func
            called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            arg = node.args[0]
            if (
                called in ("import_module", "__import__")
                and isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
            ):
                out.packages.add(arg.value.split(".")[0])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(out.strings) < MAX_STRINGS and len(node.value) < 200:
                out.strings.add(node.value)
    return out


def _parser(typescript: bool):  # type: ignore[no-untyped-def]
    from tree_sitter import Language, Parser

    if typescript:
        import tree_sitter_typescript as ts

        return Parser(Language(ts.language_typescript()))
    import tree_sitter_javascript as js

    return Parser(Language(js.language()))


_PARSERS: dict[bool, object] = {}


def js_imports(source: bytes, typescript: bool = False) -> FileImports:
    out = FileImports()
    try:
        parser = _PARSERS.get(typescript) or _PARSERS.setdefault(typescript, _parser(typescript))
        tree = parser.parse(source)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - a file we cannot parse is reported as such, never fatal
        out.parsed = False
        return out
    if tree.root_node.has_error:
        out.parsed = False  # partial trees still yield imports below, but the file is not "clean"
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        t = n.type
        if t in ("import_statement", "export_statement"):
            src = n.child_by_field_name("source")
            if src is not None:
                _add(out, _text(src))
        elif t == "call_expression":
            fn, args = n.child_by_field_name("function"), n.child_by_field_name("arguments")
            if fn is not None and args is not None and args.named_children:
                first = args.named_children[0]
                if first.type == "string" and (
                    (fn.type == "identifier" and _text(fn) == "require") or fn.type == "import"
                ):
                    _add(out, _text(first))
        elif t == "string" and len(out.strings) < MAX_STRINGS:
            s = _text(n)
            if len(s) < 200:
                out.strings.add(s)
    return out


def _text(node) -> str:  # type: ignore[no-untyped-def]
    raw = node.text.decode("utf-8", "replace") if node.text else ""
    return raw.strip("'\"`")


def _add(out: FileImports, spec: str) -> None:
    pkg = js_package(spec)
    if pkg:
        out.packages.add(pkg)
