"""Cross-file call resolution (plan §20.2): intra-procedural first, then inter-procedural
name-based resolution.

This is deliberately unsound, and says so rather than pretending otherwise: a call is resolved by
matching the plain name written at the call site against symbols by name, never by type. Dynamic
dispatch (`getattr(obj, name)()`), reflection, and two functions sharing a name where the call site
could mean either are all cases this cannot and does not resolve -- the edge is kept as unresolved
(`callee_id=None`) rather than guessed at, the same "unknown stays unknown" principle
`core/reachability/index.py` already uses for package reachability.
"""

from __future__ import annotations

from core.codeintel.models import CallEdge, CodeGraph, FileUnit, Symbol


def build_name_index(
    symbols: dict[str, Symbol],
) -> tuple[dict[tuple[str, str], list[str]], dict[str, list[str]]]:
    """The two indices `resolve_one` needs, built from an already-known symbol table -- exposed so
    `core.taint`'s own call sites (found by re-walking each file for data flow, not by reading
    `CodeGraph.edges`) can be resolved with the exact same semantics as this module's own edges,
    instead of a second, potentially-diverging implementation."""
    by_file_and_name: dict[tuple[str, str], list[str]] = {}
    by_name: dict[str, list[str]] = {}
    for s in symbols.values():
        by_file_and_name.setdefault((s.path, s.name), []).append(s.id)
        by_name.setdefault(s.name, []).append(s.id)
    return by_file_and_name, by_name


def resolve(units: list[FileUnit]) -> CodeGraph:
    symbols = {}
    entrypoints = []
    languages: set[str] = set()
    files_parsed = files_unparsed = 0

    for u in units:
        languages.add(u.language)
        if u.parsed:
            files_parsed += 1
        else:
            files_unparsed += 1
        for s in u.symbols:
            symbols[s.id] = s
        entrypoints.extend(u.entrypoints)

    by_file_and_name, by_name = build_name_index(symbols)
    edges = [
        CallEdge(
            caller_id, callee_name, line,
            resolve_one(u.path, callee_name, by_file_and_name, by_name),
        )  # fmt: skip
        for u in units
        for caller_id, callee_name, line in u.calls
    ]

    return CodeGraph(
        symbols=symbols,
        edges=edges,
        entrypoints=entrypoints,
        languages=frozenset(languages),
        files_parsed=files_parsed,
        files_unparsed=files_unparsed,
    )


def resolve_one(
    path: str,
    callee_name: str,
    by_file_and_name: dict[tuple[str, str], list[str]],
    by_name: dict[str, list[str]],
) -> str | None:
    same_file = by_file_and_name.get((path, callee_name))
    if same_file and len(same_file) == 1:
        return same_file[0]
    candidates = by_name.get(callee_name)
    if candidates and len(candidates) == 1:
        return candidates[0]
    return None  # zero matches (an external/stdlib call), or an ambiguous one -- both "unresolved"
