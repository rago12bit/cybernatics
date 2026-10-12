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


def join_route(prefix: str, route: str) -> str:
    """A route under a mount's prefix, in each framework's own notation: "/api" + "/users/{id}",
    Django's "api/" + "users/<int:pk>/", or a regex include's "^api/" + "^users/(?P<pk>\\d+)/$" (the
    inner "^" goes: Django matches the included pattern against what the prefix left)."""
    if not prefix:
        return route
    head = prefix.rstrip("$").rstrip("/")
    tail = route.lstrip("^").lstrip("/")
    if head in ("", "^"):
        return head + ("/" if prefix.startswith("/") else "") + tail
    if tail:
        return f"{head}/{tail}"
    return head + ("/" if prefix.endswith("/") or route.endswith("/") else "")


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
    # Names of decorators (Python) or middleware arguments (Express) attached to this route,
    # other than the route-registration one itself -- e.g. ("login_required",) or ("requireAuth",)
    # (plan §21.4's Hypotheses lane: "the map of which auth decorators and middleware apply where").
    # Matched by name only, not resolved to a definition: a real, disclosed heuristic (the same kind
    # `_route_entrypoint`/`_express_entrypoint` already use for the route itself), not a guarantee
    # that a name here actually enforces authorization or that its absence means it doesn't.
    auth_markers: tuple[str, ...] = ()
    # What the route is registered on, by name: `router` for `@router.get(...)` or
    # `router.get(...)`, "urlpatterns" for Django; "" when nothing (Next.js, Go). A `Mount` of that
    # router adds its prefix to `path` (`resolve.apply_mounts`).
    router: str = ""


@dataclass(frozen=True)
class Mount:
    """`parent`, a router in `file`, serves the router `child` of `module` under `prefix`: Django's
    `path("api/", include("shop.urls"))`, FastAPI's `include_router(users.router, prefix="/u")`,
    Flask's `register_blueprint(bp, url_prefix="/u")`, Express's `app.use("/u", users)`.

    `module` is a dotted Python module ("shop.urls", already absolute for a relative import) or, for
    JavaScript, the imported file's path without extension ("routes/users"); "" means `file`
    itself. `child` "*" means every router in it (an Express module exports one, unnamed here)."""

    file: str
    parent: str
    prefix: str
    module: str
    child: str
    replaces: bool = False  # Flask: a url_prefix given when registering replaces the blueprint's
    prefix_name: str = ""  # the prefix is this constant's value (`prefix=settings.API_V1_STR`)


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
    mounts: list[Mount] = field(default_factory=list)
    # A router's own prefix, by its name: `APIRouter(prefix="/u")`, `Blueprint(url_prefix="/u")`;
    # or the constant it names, when it is not written out (`APIRouter(prefix=PREFIX)`).
    prefixes: dict[str, str] = field(default_factory=dict)
    prefix_names: dict[str, str] = field(default_factory=dict)
    # Module- and class-level string constants (`API_V1_STR: str = "/api/v1"`), which a prefix
    # written as a name resolves to when exactly one value is found by that name.
    constants: dict[str, str] = field(default_factory=dict)


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
