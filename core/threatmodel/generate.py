"""Builds a ThreatModelDraft from an asset's code graph (plan §21.7). Deterministic and offline --
no model call, matching the plan's framing of this as a starting point, not an assessment.

Data-flow inference: forward reachability from each `core.codeintel` entrypoint over the RESOLVED
call graph (`CodeGraph.calls_from`), checking every call site reached (resolved or not, since a
sink is matched by callee name alone -- the same rule `core.taint.catalog`'s own docstring states)
against that symbol's language catalog. A `sql_injection`-category sink reachable from a route means
that route talks to a database; a `command_injection`-category sink means it shells out to the OS.
These are the exact same sink patterns the taint engine already uses for vulnerability detection,
reused here for a different purpose (which external systems exist), not reimplemented.
"""

from __future__ import annotations

from collections import deque

from core.codeintel.models import CodeGraph
from core.taint.catalog import load_catalog
from core.threatmodel.model import DfdElementKind, StrideRow, ThreatModelDraft

DB_CATEGORY = "sql_injection"
OS_CATEGORY = "command_injection"

_PROCESS_STRIDE = [
    ("Spoofing", "Can a request reach this endpoint without proving who the caller is?"),
    ("Tampering", "Can the request body or parameters be modified in transit or replayed?"),
    (
        "Repudiation",
        "Is this request logged with enough detail to attribute it to an actor later?",
    ),
    ("Information Disclosure", "Does the response reveal more than the caller should see?"),
    (
        "Denial of Service",
        "Can this endpoint be called at a rate or with inputs that exhaust resources?",
    ),
    (
        "Elevation of Privilege",
        "Can this endpoint be used to perform an action beyond the caller's role?",
    ),
]
_EXTERNAL_ENTITY_STRIDE = [
    ("Spoofing", "Can this actor's identity be impersonated by another party?"),
]
_DATA_STORE_STRIDE = [
    ("Tampering", "Can stored data be modified without going through an owning process?"),
    ("Information Disclosure", "Is data at rest here readable by more than intended?"),
    ("Denial of Service", "Can this store be exhausted or made unavailable?"),
]
_EXTERNAL_INTERACTOR_STRIDE = [
    ("Tampering", "Can the command or its arguments be influenced by external input?"),
    (
        "Elevation of Privilege",
        "Does this process run with more privilege than the calling code needs?",
    ),
]


def _quote(label: str) -> str:
    return '"' + label.replace('"', "&quot;").replace("\n", " ") + '"'


def _forward_reachable(graph: CodeGraph, start_id: str) -> set[str]:
    seen = {start_id}
    queue = deque([start_id])
    while queue:
        sym = queue.popleft()
        for edge in graph.calls_from(sym):
            if edge.callee_id is not None and edge.callee_id not in seen:
                seen.add(edge.callee_id)
                queue.append(edge.callee_id)
    return seen


def _sink_categories_reachable(graph: CodeGraph, start_id: str) -> set[str]:
    reachable = _forward_reachable(graph, start_id)
    by_id = {s.id: s for s in graph.all_symbols}
    categories: set[str] = set()
    for edge in graph.edges:
        if edge.caller_id not in reachable:
            continue
        caller = by_id.get(edge.caller_id)
        if caller is None:
            continue
        try:
            catalog = load_catalog(caller.language)
        except FileNotFoundError:
            continue
        sink = catalog.sink_for(edge.callee_name)
        if sink is not None:
            categories.add(sink.category)
    return categories


def generate_threat_model(graph: CodeGraph) -> ThreatModelDraft:
    lines = ["flowchart LR", "    user([User])"]
    stride: list[StrideRow] = [
        StrideRow("User", DfdElementKind.EXTERNAL_ENTITY, cat, prompt)
        for cat, prompt in _EXTERNAL_ENTITY_STRIDE
    ]

    needs_db = False
    needs_os = False
    for i, ep in enumerate(graph.entrypoints):
        node_id = f"ep{i}"
        label = f"{ep.method} {ep.path}".strip() or ep.symbol_id
        lines.append(f"    {node_id}({_quote(label)})")
        lines.append(f"    user --> {node_id}")
        stride.extend(
            StrideRow(label, DfdElementKind.PROCESS, cat, prompt) for cat, prompt in _PROCESS_STRIDE
        )
        categories = _sink_categories_reachable(graph, ep.symbol_id)
        if DB_CATEGORY in categories:
            needs_db = True
            lines.append(f"    {node_id} --> db")
        if OS_CATEGORY in categories:
            needs_os = True
            lines.append(f"    {node_id} --> os")

    if needs_db:
        lines.append("    db[(Database)]")
        stride.extend(
            StrideRow("Database", DfdElementKind.DATA_STORE, cat, prompt)
            for cat, prompt in _DATA_STORE_STRIDE
        )
    if needs_os:
        lines.append("    os{{OS process}}")
        stride.extend(
            StrideRow("OS process", DfdElementKind.EXTERNAL_INTERACTOR, cat, prompt)
            for cat, prompt in _EXTERNAL_INTERACTOR_STRIDE
        )

    return ThreatModelDraft(mermaid="\n".join(lines), stride=tuple(stride))
