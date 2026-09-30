"""Gather context for one fix attempt (plan §21.2: "taint path, enclosing function, callers, related
tests"). Nothing here is stored ahead of time -- Week 37/38's call graph (`core.codeintel.CodeGraph`)
is built in memory per scan and never persisted (confirmed before writing this), so every fix attempt
re-runs `core.codeintel.analyze()` fresh over that attempt's own checkout. This costs the same
seconds a real scan's own code-intelligence step already costs; there is no cheaper "load it from the
DB" path available today.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.codeintel import analyze
from core.codeintel.models import CodeGraph, Symbol
from core.models import Finding, TaintPathStep


@dataclass(frozen=True)
class FixContext:
    graph: CodeGraph
    enclosing: Symbol | None  # the function/method containing the finding's line, if any
    callers: tuple[Symbol, ...]  # symbols that call `enclosing`, from the same graph
    taint_path: tuple[TaintPathStep, ...]


def enclosing_symbol(graph: CodeGraph, path: str, line: int) -> Symbol | None:
    """The innermost symbol in `path` whose line range contains `line` -- "innermost" because a
    nested function's own range is a subset of its enclosing one, and the fix belongs to whichever
    is tightest."""
    best: Symbol | None = None
    for s in graph.all_symbols:
        if s.path == path and s.start_line <= line <= s.end_line:
            if best is None or (s.end_line - s.start_line) < (best.end_line - best.start_line):
                best = s
    return best


def gather_context(checkout: Path, finding: Finding) -> FixContext:
    graph = analyze(checkout)
    enclosing = enclosing_symbol(graph, finding.location.path, finding.location.start_line)
    callers: tuple[Symbol, ...] = ()
    if enclosing is not None:
        caller_ids = graph.callers_of(enclosing.id)
        by_id = {s.id: s for s in graph.all_symbols}
        callers = tuple(by_id[cid] for cid in caller_ids if cid in by_id)
    return FixContext(graph, enclosing, callers, finding.taint_path)


def context_summary(ctx: FixContext) -> str:
    """A plain-text rendering for the model's prompt -- deliberately not JSON: the model reads this,
    it doesn't parse it."""
    lines: list[str] = []
    if ctx.enclosing:
        lines.append(
            f"Enclosing function: {ctx.enclosing.qualified_name} "
            f"({ctx.enclosing.path}:{ctx.enclosing.start_line}-{ctx.enclosing.end_line})"
        )
    else:
        lines.append("Enclosing function: not found (module-level code, or an unparsed file).")
    if ctx.callers:
        lines.append("Known callers:")
        lines.extend(f"  - {c.qualified_name} ({c.path}:{c.start_line})" for c in ctx.callers[:10])
    else:
        lines.append("Known callers: none found.")
    if ctx.taint_path:
        lines.append("Taint path (source to sink):")
        for step in ctx.taint_path:
            marker = " [SINK]" if step.is_sink else ""
            lines.append(f"  - {step.path}:{step.line}: {step.description}{marker}")
    else:
        lines.append("Taint path: none recorded for this finding.")
    return "\n".join(lines)
