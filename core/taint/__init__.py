"""Taint analysis (plan §20.3): concrete source-to-sink paths from an HTTP entrypoint to a sink,
built directly on `core.codeintel`'s call graph (plan §20.2) rather than duplicating it.

`analyze(root)`/`analyze_or_none(root)` mirror `core.codeintel`'s own never-raises directory-walk
contract. Every file that contributed at least one `Symbol` is re-parsed here, independently of
`core.codeintel`'s own extraction pass, to recover the actual function bodies data-flow analysis
needs -- the same "each analysis parses its own files" precedent `core.codeintel` itself set next to
`core.reachability` (see ADR-0020), now extended one layer further rather than threading a shared
parse tree through three unrelated analyses.

A `Symbol`'s own `(path, start_line)` is enough to find its matching parsed node without re-deriving
qualified names or scope tracking a second time: every extractor mints a symbol's `start_line` from
that same node's own first line (`node.lineno` for `ast`, `node.start_point[0] + 1` for tree-sitter),
so collecting every function-like node in a fresh parse, keyed the same way, and looking a symbol up
by it is a exact, cheap bridge between the two independent parses.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core import codeintel
from core.codeintel.models import CodeGraph
from core.taint.catalog import Catalog, load_catalog
from core.taint.engine import ParsedFunction, compute_summaries, find_taint_paths
from core.taint.models import FunctionSummary, TaintFinding

log = logging.getLogger(__name__)

_JS_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "method_definition",
        "arrow_function",
    }
)
_GO_FUNCTION_TYPES = frozenset({"function_declaration", "method_declaration"})


@dataclass
class TaintResult:
    graph: CodeGraph
    summaries: dict[str, FunctionSummary] = field(default_factory=dict)
    findings: list[TaintFinding] = field(default_factory=list)


def _python_nodes(source: bytes) -> dict[int, Any]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    return {
        n.lineno: n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _tree_sitter_nodes(tree_root: Any, types: frozenset[str]) -> dict[int, Any]:
    out: dict[int, Any] = {}

    def walk(node: Any) -> None:
        if node.type in types:
            out[node.start_point[0] + 1] = node
        for c in node.children:
            walk(c)

    walk(tree_root)
    return out


def _js_nodes(source: bytes, typescript: bool) -> dict[int, Any]:
    from tree_sitter import Language, Parser

    if typescript:
        import tree_sitter_typescript as ts

        parser = Parser(Language(ts.language_typescript()))
    else:
        import tree_sitter_javascript as js

        parser = Parser(Language(js.language()))
    try:
        tree = parser.parse(source)
    except Exception:  # noqa: BLE001 - an unparsable file contributes no functions, never fatal
        return {}
    return _tree_sitter_nodes(tree.root_node, _JS_FUNCTION_TYPES)


def _go_nodes(source: bytes) -> dict[int, Any]:
    import tree_sitter_go as go
    from tree_sitter import Language, Parser

    try:
        tree = Parser(Language(go.language())).parse(source)
    except Exception:  # noqa: BLE001 - an unparsable file contributes no functions, never fatal
        return {}
    return _tree_sitter_nodes(tree.root_node, _GO_FUNCTION_TYPES)


def _parse_functions(root: Path, graph: CodeGraph) -> dict[str, ParsedFunction]:
    by_path: dict[str, list[Any]] = {}
    for s in graph.symbols.values():
        by_path.setdefault(s.path, []).append(s)

    functions: dict[str, ParsedFunction] = {}
    for rel_path, symbols in by_path.items():
        language = symbols[0].language
        try:
            source = (root / rel_path).read_bytes()
        except OSError:
            continue
        if language == "python":
            nodes = _python_nodes(source)
        elif language in ("javascript", "typescript"):
            nodes = _js_nodes(source, typescript=language == "typescript")
        elif language == "go":
            nodes = _go_nodes(source)
        else:
            continue
        for sym in symbols:
            node = nodes.get(sym.start_line)
            if node is not None:
                functions[sym.id] = ParsedFunction(sym.id, language, rel_path, node)
    return functions


def _catalogs() -> dict[str, Catalog]:
    return {
        "python": load_catalog("python"),
        "javascript": load_catalog("javascript"),
        "typescript": load_catalog("javascript"),  # same language, same catalog
        "go": load_catalog("go"),
    }


def analyze(root: Path) -> TaintResult:
    graph = codeintel.analyze(root)
    functions = _parse_functions(root, graph)
    catalogs = _catalogs()
    summaries = compute_summaries(graph, functions, catalogs)
    findings = find_taint_paths(graph, functions, summaries, catalogs)
    return TaintResult(graph=graph, summaries=summaries, findings=findings)


def analyze_or_none(root: Path) -> TaintResult | None:
    """Best effort: a failure here must never fail a scan, it only means no taint data."""
    try:
        return analyze(root)
    except Exception:  # noqa: BLE001
        log.warning("taint analysis failed", exc_info=True)
        return None


__all__ = ["TaintResult", "analyze", "analyze_or_none"]
