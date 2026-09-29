"""Shared data model for code intelligence (plan §20.2): symbols, calls, entrypoints.

A `Symbol` is one function or method definition. A `CallEdge` is one call site, resolved to a
specific `Symbol` when `resolve.py` could determine one, unresolved (`callee_id=None`) otherwise --
unresolved edges are kept, not dropped, since "we don't know" is a real, reportable answer (the same
principle `core/reachability/index.py` uses for package reachability).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property


def symbol_id(path: str, qualified_name: str, start_line: int) -> str:
    """Stable within one analysis. `start_line` disambiguates the rare case of two definitions
    with the same qualified name in the same file (e.g. a function redefined after an `if`)."""
    return f"{path}:{qualified_name}:{start_line}"


@dataclass(frozen=True)
class Symbol:
    id: str
    path: str  # relative to the analyzed root, forward slashes
    name: str  # "handler"
    qualified_name: str  # "app.routes.users.handler", or "handler" when no enclosing scope is known
    kind: str  # "function" | "method"
    start_line: int
    end_line: int
    language: str  # "python" | "javascript" | "typescript" | "go"


@dataclass(frozen=True)
class CallEdge:
    caller_id: str
    callee_name: str  # the name actually written at the call site -- always present
    line: int
    callee_id: str | None = None  # filled in by resolve.py; None means "not resolved"


@dataclass(frozen=True)
class Entrypoint:
    symbol_id: str
    framework: str  # "fastapi" | "flask" | "django" | "express" | "nextjs" | "net/http"
    method: str  # "GET", "POST", ... or "" when the framework doesn't restrict by verb
    path: str  # route path; "" when it couldn't be determined


@dataclass
class FileUnit:
    """One file's raw extraction, before cross-file call resolution."""

    path: str
    language: str
    symbols: list[Symbol] = field(default_factory=list)
    # (caller_id, callee_name, line)
    calls: list[tuple[str, str, int]] = field(default_factory=list)
    entrypoints: list[Entrypoint] = field(default_factory=list)
    parsed: bool = True


@dataclass
class CodeGraph:
    symbols: dict[str, Symbol] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)
    entrypoints: list[Entrypoint] = field(default_factory=list)
    languages: frozenset[str] = frozenset()
    files_parsed: int = 0
    files_unparsed: int = 0
    # Every symbol as originally emitted, in emission order -- unlike `symbols` (keyed by id, so a
    # rare id collision silently keeps only the last one written), this never drops an entry.
    # `resolve.build_name_index` is built from this, not from `symbols`, so a genuine collision
    # still shows up as two same-named candidates (correctly unresolved/ambiguous) rather than
    # quietly resolving to whichever symbol happened to survive the `symbols` dict.
    all_symbols: tuple[Symbol, ...] = ()

    @cached_property
    def _by_callee(self) -> dict[str, list[str]]:
        idx: dict[str, list[str]] = {}
        for e in self.edges:
            if e.callee_id is not None:
                idx.setdefault(e.callee_id, []).append(e.caller_id)
        return idx

    @cached_property
    def _by_caller(self) -> dict[str, list[CallEdge]]:
        idx: dict[str, list[CallEdge]] = {}
        for e in self.edges:
            idx.setdefault(e.caller_id, []).append(e)
        return idx

    def callers_of(self, symbol_id_: str) -> list[str]:
        """Symbol ids with a resolved edge into `symbol_id_` -- the one-hop query reachability
        (plan §20.3) walks outward from an entrypoint to build a path. `core.taint.engine`'s own
        worklist calls this once per changed summary per pass, so a linear scan over every edge in
        the repository (this used to be one) turns into O(passes x edges) instead of O(edges); the
        reverse index above is built once, lazily, and reused. Safe only because nothing mutates
        `edges` after `resolve()` builds a `CodeGraph` -- true today (grep confirms it), and this
        index would silently go stale if that ever changed."""
        return self._by_callee.get(symbol_id_, [])

    def calls_from(self, symbol_id_: str) -> list[CallEdge]:
        return self._by_caller.get(symbol_id_, [])
