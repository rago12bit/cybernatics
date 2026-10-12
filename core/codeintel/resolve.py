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

import posixpath
from collections.abc import Iterable
from dataclasses import replace

from core.codeintel.models import (
    CallEdge,
    CodeGraph,
    Entrypoint,
    FileUnit,
    Mount,
    Symbol,
    join_route,
)

MAX_MOUNT_PATHS = 8  # one route mounted in more places than this keeps the first eight
_JS_EXTENSIONS = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")


def build_name_index(
    symbols: Iterable[Symbol],
) -> tuple[dict[tuple[str, str], list[str]], dict[str, list[str]]]:
    """The two indices `resolve_one` needs. Takes every symbol *as emitted* (`CodeGraph.all_symbols`
    or an equivalent list), not `CodeGraph.symbols` (keyed by id): a rare symbol_id collision would
    otherwise silently drop one of the two colliding definitions before this ever sees them, turning
    a genuinely ambiguous name into a confidently (and wrongly) resolved one. Exposed so
    `core.taint`'s own call sites (found by re-walking each file for data flow, not by reading
    `CodeGraph.edges`) can be resolved with the exact same semantics as this module's own edges,
    instead of a second, potentially-diverging implementation."""
    by_file_and_name: dict[tuple[str, str], list[str]] = {}
    by_name: dict[str, list[str]] = {}
    for s in symbols:
        by_file_and_name.setdefault((s.path, s.name), []).append(s.id)
        by_name.setdefault(s.name, []).append(s.id)
    return by_file_and_name, by_name


def resolve(units: list[FileUnit]) -> CodeGraph:
    symbols = {}
    all_symbols: list[Symbol] = []
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
            all_symbols.append(s)
    entrypoints = apply_mounts(units)

    by_file_and_name, by_name = build_name_index(all_symbols)
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
        all_symbols=tuple(all_symbols),
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


# --- mounts: the prefix a route gets from where its router is included ---------------------------


def _python_module(path: str) -> str:
    """src/shop/urls.py -> "src.shop.urls"; a package's __init__.py is the package."""
    stem = path[: -len(".py")]
    stem = stem[: -len("/__init__")] if stem.endswith("/__init__") else stem
    return stem.replace("/", ".")


def _closest(candidates: list[str], near: str) -> str | None:
    """The one candidate, or the one sharing the most leading directories with `near`."""
    if len(candidates) <= 1:
        return candidates[0] if candidates else None
    shared = {c: len(posixpath.commonpath([c, near]) or "") for c in candidates}
    best = [c for c in candidates if shared[c] == max(shared.values())]
    return best[0] if len(best) == 1 else None


def _locate(
    mount: Mount, language: str, files: set[str], py_modules: dict[str, list[str]]
) -> str | None:
    """The file a mount names. A Python module is matched by its dotted path's tail (the repository
    root need not be the import root: "shop.urls" is src/shop/urls.py); several matches go to the
    one nearest the mounting file, a tie to none. A JavaScript module is a file with any script
    extension, or a directory's index."""
    if not mount.module:
        return mount.file
    if language == "python":
        return _closest(sorted(py_modules.get(mount.module, [])), mount.file)
    for candidate in (mount.module, *(mount.module + e for e in _JS_EXTENSIONS),
                      *(f"{mount.module}/index{e}" for e in _JS_EXTENSIONS)):  # fmt: skip
        if candidate in files:
            return candidate
    return None


def apply_mounts(units: list[FileUnit]) -> list[Entrypoint]:
    """Every entrypoint, with the prefixes its router is mounted under: a route on `router` in
    users.py, which main.py includes under "/users", is "/users" + its own path. Prefixes chain
    (a router mounted on a router mounted on the app) and a router's own prefix comes after the
    mount's, as FastAPI and Express join them (Flask's `url_prefix` given at registration replaces
    the blueprint's own). A router mounted twice serves its routes at both paths. A mount whose
    target is not in the repository, or is ambiguous, adds nothing: the route keeps the path it
    was written with, as it did before mounts were read."""
    files = {u.path for u in units}
    language = {u.path: u.language for u in units}
    py_modules: dict[str, list[str]] = {}
    for f in files:
        if f.endswith(".py"):
            dotted = _python_module(f)
            for i in range(len(dotted.split("."))):
                py_modules.setdefault(".".join(dotted.split(".")[i:]), []).append(f)
    found: dict[str, set[str]] = {}
    for u in units:
        for name, value in u.constants.items():
            found.setdefault(name, set()).add(value)
    constant = {name: next(iter(v)) for name, v in found.items() if len(v) == 1}
    own = {(u.path, r): p for u in units for r, p in u.prefixes.items()}
    own.update({(u.path, r): constant[n] for u in units for r, n in u.prefix_names.items()
                if n in constant})  # fmt: skip
    into: dict[tuple[str, str], list[Mount]] = {}
    for u in units:
        for m in u.mounts:
            target = _locate(m, u.language, files, py_modules)
            if target is not None and language.get(target) == u.language:
                if m.prefix_name:  # a name with no single value adds nothing, as before
                    m = replace(m, prefix=constant.get(m.prefix_name, ""))
                into.setdefault((target, m.child), []).append(m)

    memo: dict[tuple[str, str], list[str]] = {}

    def prefixes(node: tuple[str, str], seen: frozenset[tuple[str, str]]) -> list[str]:
        if node in memo:
            return memo[node]
        base = own.get(node, "")
        mounts = [*into.get(node, []), *(into.get((node[0], "*"), []) if node[1] else [])]
        out: list[str] = []
        for m in mounts:
            parent = (m.file, m.parent)
            if parent in seen or parent == node:
                continue
            for p in prefixes(parent, seen | {node}):
                out.append(join_route(join_route(p, m.prefix), "" if m.replaces else base))
        result = list(dict.fromkeys(out))[:MAX_MOUNT_PATHS] or [base]
        if not seen:
            memo[node] = result
        return result

    entrypoints: list[Entrypoint] = []
    for u in units:
        for e in u.entrypoints:
            if not e.router or not e.path:
                entrypoints.append(e)
                continue
            for p in prefixes((u.path, e.router), frozenset()):
                entrypoints.append(replace(e, path=join_route(p, e.path)) if p else e)
    return entrypoints
