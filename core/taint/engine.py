"""Call-graph worklist for taint analysis (plan §20.3): computes one `FunctionSummary` per function,
independent of any caller, then walks forward from every real HTTP entrypoint using those summaries
to find concrete `TaintFinding`s. See `python_flow.py`'s module docstring for the shared
intra-procedural algorithm this builds on, and its documented precision trade-offs.

Two passes, both built on the same per-language `analyze_function`:

  1. **Summaries** (`compute_summaries`). Every function with a known body is analysed once, seeded
     with its own parameters as *hypothetical* taint sources (`{param: {i}}`) plus any of the
     language's `global_sources`, which are always real, not hypothetical (Flask's `request`).
     A function's summary can depend on a callee's summary, so this runs as a worklist: whenever a
     function's summary changes, every one of its own callers (`CodeGraph.callers_of`) is re-queued,
     until nothing changes or a safety cap on passes is hit -- bounded so a call cycle (mutual or
     direct recursion) cannot loop forever, the same shape as the plan's own "propagated over the
     call graph with a worklist until a fixed point."
  2. **Findings** (`find_taint_paths`). From each `Entrypoint`, the same analyzer runs again on its
     own handler function, seeded this time with the literal `SOURCE` tag (plus, for a language whose
     catalog names a `param_source_positions` entry, that handler parameter too) -- and the resulting
     `sinks`, built using the now-complete summaries, already contain every reachable sink with a full
     hop chain (each re-exposure in pass 1 already prepended one hop; see `models.SinkHit`), needing
     only the entrypoint's own hop prepended once more here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from core.codeintel.models import CodeGraph, Entrypoint
from core.codeintel.resolve import build_name_index, resolve_one
from core.taint import go_flow, js_flow, python_flow
from core.taint.catalog import Catalog
from core.taint.models import SOURCE, FunctionSummary, SinkHit, TaintFinding, TaintHop, TaintSet

MAX_WORKLIST_PASSES = 50

_ANALYZERS: dict[str, Any] = {
    "python": python_flow,
    "javascript": js_flow,
    "typescript": js_flow,
    "go": go_flow,
}


@dataclass(frozen=True)
class ParsedFunction:
    """One function-like node, already parsed, ready for `analyze_function`."""

    symbol_id: str
    language: str
    path: str
    node: Any


def _resolver(
    path: str,
    by_file_and_name: dict[tuple[str, str], list[str]],
    by_name: dict[str, list[str]],
) -> Callable[[str], str | None]:
    return lambda name: resolve_one(path, name, by_file_and_name, by_name)


def _distinct_sinks(sinks: list[SinkHit]) -> tuple[SinkHit, ...]:
    """One hit per distinct sink (same tags reaching the same call), keeping the shortest chain.
    Keeping every chain made a summary grow with the number of call *paths* -- and, around a call
    cycle, by one more hop on every worklist pass, so it never settled: scanning this project's own
    code grew past 20 GB. find_taint_paths reports one finding per sink anyway."""
    best: dict[tuple[TaintSet, str, int, str, str], SinkHit] = {}
    for hit in sinks:
        key = (hit.params, hit.path, hit.line, hit.sink_name, hit.category)
        kept = best.get(key)
        if kept is None or _chain_order(hit) < _chain_order(kept):
            best[key] = hit
    return tuple(best.values())


def _chain_order(hit: SinkHit) -> tuple[int, tuple[tuple[str, str, int], ...]]:
    return len(hit.hops), tuple((h.symbol_id, h.path, h.line) for h in hit.hops)


def compute_summaries(
    graph: CodeGraph,
    functions: dict[str, ParsedFunction],
    catalogs: dict[str, Catalog],
) -> dict[str, FunctionSummary]:
    by_file_and_name, by_name = build_name_index(graph.all_symbols)
    summaries: dict[str, FunctionSummary] = {sid: FunctionSummary(sid) for sid in functions}

    def compute_one(symbol_id: str) -> FunctionSummary:
        fn = functions[symbol_id]
        mod = _ANALYZERS[fn.language]
        catalog = catalogs[fn.language]
        params = mod.param_names(fn.node)
        seed: dict[str, TaintSet] = {name: frozenset({SOURCE}) for name in catalog.global_sources}
        for i, p in enumerate(params):
            seed[p] = seed.get(p, frozenset()) | frozenset({i})
        returns, sinks = mod.analyze_function(
            fn.node,
            fn.path,
            seed,
            _resolver(fn.path, by_file_and_name, by_name),
            summaries,
            catalog,
        )
        return FunctionSummary(symbol_id, _distinct_sinks(sinks), returns, tuple(params))

    pending = set(functions)
    passes = 0
    while pending and passes < MAX_WORKLIST_PASSES:
        passes += 1
        next_pending: set[str] = set()
        for symbol_id in pending:
            new_summary = compute_one(symbol_id)
            if new_summary != summaries[symbol_id]:
                summaries[symbol_id] = new_summary
                next_pending |= {c for c in graph.callers_of(symbol_id) if c in functions}
        pending = next_pending

    return summaries


def _redirect_target(ep: Entrypoint, graph: CodeGraph, functions: dict[str, ParsedFunction]) -> str:
    """A route registered by naming an existing handler (`app.get('/x', obj.method)` in Express, a
    Django `urlpatterns` entry) makes `core.codeintel` mint a synthetic symbol that is nothing but a
    redirect to the real handler -- it has no body of its own to analyse. Follow its one call edge to
    find the function whose body actually needs seeding."""
    if ep.symbol_id in functions:
        return ep.symbol_id
    calls = graph.calls_from(ep.symbol_id)
    if len(calls) == 1 and calls[0].callee_id:
        return calls[0].callee_id
    return ep.symbol_id  # an unresolved redirect: no body either way, analysis below finds nothing


def find_taint_paths(
    graph: CodeGraph,
    functions: dict[str, ParsedFunction],
    summaries: dict[str, FunctionSummary],
    catalogs: dict[str, Catalog],
) -> list[TaintFinding]:
    by_file_and_name, by_name = build_name_index(graph.all_symbols)
    findings: list[TaintFinding] = []
    seen: set[tuple[str, int, str]] = set()  # de-dupe by (sink path, sink line, category): the same
    # sink reached from the same entrypoint by more than one internal path is one real issue, not two

    for ep in graph.entrypoints:
        target_id = _redirect_target(ep, graph, functions)
        fn = functions.get(target_id)
        if fn is None:
            continue  # no analyzable body was ever found for this entrypoint (or its redirect)
        mod = _ANALYZERS[fn.language]
        catalog = catalogs[fn.language]
        params = mod.param_names(fn.node)
        seed: dict[str, TaintSet] = {name: frozenset({SOURCE}) for name in catalog.global_sources}
        for i in catalog.param_source_positions:
            if i < len(params):
                seed[params[i]] = seed.get(params[i], frozenset()) | frozenset({SOURCE})
        _, sinks = mod.analyze_function(
            fn.node,
            fn.path,
            seed,
            _resolver(fn.path, by_file_and_name, by_name),
            summaries,
            catalog,
        )
        entry_symbol = graph.symbols.get(ep.symbol_id)
        entry_hop = TaintHop(
            ep.symbol_id,
            entry_symbol.path if entry_symbol else fn.path,
            entry_symbol.start_line if entry_symbol else 0,
            f"HTTP entrypoint: {ep.method} {ep.path} ({ep.framework})",
        )
        for hit in sinks:
            if SOURCE not in hit.params:
                continue  # a hit only exposed via a hypothetical parameter tag: not a real finding
            key = (hit.path, hit.line, hit.category)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                TaintFinding(
                    entrypoint_symbol_id=ep.symbol_id,
                    category=hit.category,
                    sink_path=hit.path,
                    sink_line=hit.line,
                    sink_name=hit.sink_name,
                    hops=(entry_hop, *hit.hops),
                )
            )

    return findings


__all__ = ["ParsedFunction", "compute_summaries", "find_taint_paths"]
