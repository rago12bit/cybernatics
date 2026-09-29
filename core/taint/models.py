"""Shared data model for taint analysis (plan §20.3): function summaries and concrete taint paths
from an HTTP entrypoint to a sink.

A tainted value's provenance is a *set* of tags, not a bare boolean, because one representation
has to answer two different questions:

  - "if parameter 2 of this function is ever tainted, does it reach a sink?" -- a `FunctionSummary`,
    computed once per function, independent of any caller (the plan's own wording: "function
    summaries ... propagated over the call graph"). This question only needs integer tags: "my own
    Nth parameter."
  - "starting from this real HTTP entrypoint, is a sink actually reached?" -- a `TaintFinding`,
    computed once per entrypoint by walking the call graph with every function's summary. This seeds
    the walk with the literal tag `SOURCE` instead of a parameter index: a concrete, already-real
    taint origin, not a hypothesis about what some future caller might pass in.

The same per-function analyzer (one per language, in `python_flow.py`/`js_flow.py`/`go_flow.py`)
answers both questions; only the initial tag set handed to it differs. See `engine.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

SOURCE = "source"
TaintTag = int | str  # int: this function's own Nth parameter; the literal SOURCE: real input
TaintSet = frozenset[TaintTag]


@dataclass(frozen=True)
class SinkHit:
    """One place where a tainted value reached a sink -- the sink's own location, which stays fixed
    even when this hit is *re-exposed* into a caller's own summary (see `engine.py`): a function
    that merely forwards a tainted argument into a helper which itself calls the real sink still
    reports the helper's line and path, not its own, since that is where the dangerous call actually
    executes.

    `hops` accumulates one `TaintHop` per re-exposure, each prepended as the hit rises through the
    call graph -- so by the time an entrypoint's own analysis produces a hit, `hops` already reads in
    call order (the entrypoint's own first outgoing call, then the next, ...), and only the sink's
    own final `path`/`line` remains to describe where the chain actually ends."""

    params: TaintSet  # which tags (own params, or SOURCE) made the sink's argument tainted
    path: str
    line: int
    sink_name: str
    category: str  # "sql_injection" | "command_injection" | "code_injection" | ...
    hops: tuple[TaintHop, ...] = ()


@dataclass(frozen=True)
class FunctionSummary:
    symbol_id: str
    sinks: tuple[SinkHit, ...] = ()
    returns: TaintSet = frozenset()  # which tags reach this function's own return value
    # By declaration-order index, matching each int tag's meaning ("this function's own Nth
    # parameter"). A caller re-exposing a sink (python_flow.py's own `_call_taint`) uses this to
    # find the argument expression a *keyword* call passed for tag N -- Python lets a positional
    # parameter be passed by name, and `call.args[N]` alone misses that entirely.
    param_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaintHop:
    symbol_id: str
    path: str
    line: int
    description: str


@dataclass(frozen=True)
class TaintFinding:
    entrypoint_symbol_id: str
    category: str
    sink_path: str
    sink_line: int
    sink_name: str
    hops: tuple[TaintHop, ...]  # source -> ... -> sink, in call order


def union_taint(sets: list[TaintSet]) -> TaintSet:
    result: TaintSet = frozenset()
    for s in sets:
        result = result | s
    return result


def merge_taint_states(results: list[dict[str, TaintSet]]) -> dict[str, TaintSet]:
    """Union each name's tags across every result, dropping any name left untainted everywhere.
    Shared by `python_flow`/`js_flow`/`go_flow`'s own `_visit_branches` (each language walks each
    branch of an `if`/`try`/loop independently from the same starting state, then merges the
    resulting states this way -- not visited sequentially into one shared map, which would let one
    branch's clean reassignment wrongly erase taint an earlier branch introduced). This piece of
    the shared algorithm is genuinely language-independent (unlike the branch-walking itself, which
    needs each language's own AST), so it lives once here rather than three times, identically,
    one per language module."""
    names: set[str] = set()
    for r in results:
        names |= set(r)
    merged = {name: union_taint([r.get(name, frozenset()) for r in results]) for name in names}
    return {k: v for k, v in merged.items() if v}
