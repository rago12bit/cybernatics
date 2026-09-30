"""Deterministic candidate generation for the Hypotheses lane (plan §21.4).

Scope, v1 (ADR-0028): only "a route missing the authorization check its sibling routes have" -- the
one hypothesis type the plan states in fully concrete terms. IDOR (an object id taken from the
request and used without an ownership check) and mass assignment both need reasoning about object
identity and field binding this pass does not attempt; named as a deferred, disclosed cut in
ADR-0028, not silently dropped.

Finding a candidate needs no model: group a repository's HTTP entrypoints (`core.codeintel`, whose
`Entrypoint.auth_markers` this feature's own extractor additions -- Week 43's Python decorator and
Express middleware capture -- exist specifically to feed) by the file they're defined in, and flag
any route with no recognized auth marker in a file where at least one sibling route has one. This is
exactly the plan's "input: structured facts from code intelligence... not the whole repository" --
the model (`core.hypotheses.service`) only ever sees this short, structured summary plus the route's
own code, never the raw repository, and its job is downstream: decide whether THIS specific
asymmetry is worth a person's time, not to invent the pattern itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.codeintel.models import CodeGraph, Entrypoint

# A real, disclosed heuristic (the same "shape, not resolution" posture core.codeintel's own route
# matchers already use): a marker LOOKS like it might enforce authorization if its name contains one
# of these substrings, case-insensitively. False positives (a decorator named "cache_authenticated_
# response" that isn't really an auth check) and false negatives (an oddly-named in-house decorator)
# are both possible and expected -- narrowing them is the model's job, not this list's.
AUTH_KEYWORDS: tuple[str, ...] = (
    "auth", "login", "permission", "requires_role", "role_required", "protect", "authoriz",
    "authentic", "jwt", "session_required", "ensureauth", "requireauth", "isauthenticated",
)  # fmt: skip


def looks_like_auth_marker(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in AUTH_KEYWORDS)


def is_protected(ep: Entrypoint) -> bool:
    return any(looks_like_auth_marker(m) for m in ep.auth_markers)


@dataclass(frozen=True)
class Candidate:
    route: Entrypoint
    file: str
    line: int
    protected_siblings: tuple[Entrypoint, ...]  # evidence: siblings in the file that ARE marked


def missing_auth_candidates(graph: CodeGraph) -> list[Candidate]:
    """One candidate per unprotected route in a file that has at least one protected sibling.
    Sorted for a deterministic order (file, then line) -- nothing here is randomized, but a caller
    iterating a plain dict-derived order would otherwise see an incidental, non-reproducible one."""
    by_file: dict[str, list[Entrypoint]] = {}
    for ep in graph.entrypoints:
        sym = graph.symbols.get(ep.symbol_id)
        file = sym.path if sym is not None else ep.symbol_id.split(":", 1)[0]
        by_file.setdefault(file, []).append(ep)

    candidates: list[Candidate] = []
    for file, eps in by_file.items():
        protected = tuple(e for e in eps if is_protected(e))
        if not protected:
            continue
        for e in eps:
            if is_protected(e):
                continue
            sym = graph.symbols.get(e.symbol_id)
            line = sym.start_line if sym is not None else 0
            candidates.append(Candidate(e, file, line, protected))
    candidates.sort(key=lambda c: (c.file, c.line))
    return candidates
