"""SAST/DAST correlation: a live DAST finding on a route whose handler also has an existing SAST
finding with a related CWE is "confirmed at runtime" -- a static-analysis guess turns into something
a real HTTP request actually reached (Week 49 task 4, plan §22.4).

Matching is deliberately conservative on both axes: the route must resolve to a real handler
(`core.dast.routes`) at the same file the SAST finding is in, within a small line window of that
handler's `def` (the vulnerable code is normally inside or just below the function it decorates, not
somewhere else in a large file); and the CWEs must be related, via the same `core.correlation.
engine.cwe_family` grouping the ordinary cross-tool correlator already uses (so "CWE-89 SQL
injection" reported by DAST matches "CWE-89" reported by SAST, without requiring byte-identical CWE
lists). A finding with no CWE on either side, or a route with no matching handler at all, is never
force-matched to "the closest thing" -- an absent confirmation is correct; a wrong one is not.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.correlation.engine import cwe_family
from core.dast.routes import RouteHandler, route_matches
from core.models import Finding

# The vulnerable line is normally at or a little past the route handler's own `def` line (inside its
# body), occasionally a few lines before it (a module-level query built just above the handler that
# decorates it) -- generous enough to catch either without matching unrelated code far away in the
# same file.
LINE_WINDOW = 50


@dataclass(frozen=True)
class RuntimeConfirmation:
    dast_finding_id: str
    sast_finding_id: str
    route: str
    cwe: str


def correlate_dast_with_sast(
    dast_findings: list[Finding], sast_findings: list[Finding], handlers: list[RouteHandler]
) -> list[RuntimeConfirmation]:
    confirmations: list[RuntimeConfirmation] = []
    for dast in dast_findings:
        if not dast.location.route or not dast.taxonomy.cwe:
            continue
        dast_families = cwe_family(dast)
        matching_handlers = [h for h in handlers if route_matches(h.route, dast.location.route)]
        if not matching_handlers:
            continue
        for sast in sast_findings:
            if not sast.taxonomy.cwe:
                continue
            shared = dast_families & cwe_family(sast)
            if not shared:
                continue
            if _near_a_handler(sast, matching_handlers):
                confirmations.append(
                    RuntimeConfirmation(
                        dast_finding_id=dast.id,
                        sast_finding_id=sast.id,
                        route=dast.location.route,
                        cwe=next(iter(shared)),
                    )
                )
    return confirmations


def _near_a_handler(sast: Finding, handlers: list[RouteHandler]) -> bool:
    return any(
        h.path == sast.location.path and abs(h.line - sast.location.start_line) <= LINE_WINDOW
        for h in handlers
    )
