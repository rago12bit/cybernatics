"""Turns already-persisted data into attack-path graph nodes (plan §21.6): `core.codeintel`
Entrypoints and the asset's open Issues (reconstructed from `FindingRow.data` via
`finding_from_dict`, the same helper `core.persistence.repo` already round-trips Findings through).
No new data is collected here -- this module only labels what scanners and `core.codeintel` already
found as graph nodes; `core.attackpath.rules` decides which nodes connect."""

from __future__ import annotations

from core.attackpath.model import NodeKind, PathNode
from core.codeintel.models import CodeGraph
from core.models import Category, Finding


def entrypoint_nodes(graph: CodeGraph) -> list[PathNode]:
    return [
        PathNode(
            id=f"ep_{ep.symbol_id}",
            kind=NodeKind.ENTRYPOINT,
            label=(f"{ep.method} {ep.path}".strip() or ep.symbol_id),
            detail=ep.framework,
        )
        for ep in graph.entrypoints
    ]


def issue_node(issue_id: str, finding: Finding) -> PathNode:
    """One node per Issue. SECRETS-category issues get their own NodeKind so rules can single them
    out (plan §21.6's "hardcoded cloud key" example); every other category is a plain ISSUE node."""
    kind = NodeKind.SECRET if finding.taxonomy.category is Category.SECRETS else NodeKind.ISSUE
    return PathNode(
        id=f"iss_{issue_id}",
        kind=kind,
        label=finding.title,
        issue_id=issue_id,
        detail=finding.location.snippet,
    )


def symbol_at(graph: CodeGraph, path: str, line: int) -> str | None:
    """The innermost symbol id whose file+line range contains `path:line`, or None when nothing in
    the graph encloses it (e.g. module-level code, or the file wasn't parsed) -- `core.attackpath.
    rules` uses this to place an Issue's location in the call graph before walking `callers_of` to
    look for a reachable entrypoint."""
    best: str | None = None
    best_span: int | None = None
    for sym in graph.symbols.values():
        if sym.path == path and sym.start_line <= line <= sym.end_line:
            span = sym.end_line - sym.start_line
            if best_span is None or span < best_span:
                best, best_span = sym.id, span
    return best
