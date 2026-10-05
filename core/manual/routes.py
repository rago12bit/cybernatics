"""Routes for the manual finding form, and what automation already knows about them (plan §43.2:
"a manual finding on POST /orders then links to that handler's code and taint paths
automatically").

The routes are the project's latest scan's HTTP entrypoints (code intelligence, plan §20.2, stored
per scan since migration 0031), falling back to the older Python-only route map. Linking a manual
finding to automation is `core.dast.correlate` -- the same conservative match that marks a static
finding "confirmed at runtime": the route must resolve to a handler, a static finding must sit
near that handler, and the two CWEs must be related. A manual finding with no CWE, or on a route
with no such finding, links to nothing; a wrong link would be worse than none.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.dast.correlate import correlate_dast_with_sast
from core.dast.routes import RouteHandler, normalize_route_pattern
from core.models import Category, Finding, finding_from_dict
from core.persistence.models import FindingRow, IssueRow, Scan

SCANS_LOOKED_AT = 10


@dataclass(frozen=True)
class Route:
    method: str  # "" when the framework does not restrict the verb, or the scan did not record it
    route: str
    path: str  # the handler's file
    line: int  # its definition
    symbol: str = ""
    framework: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"method": self.method, "route": self.route, "path": self.path, "line": self.line,
                "symbol": self.symbol, "framework": self.framework}  # fmt: skip


@dataclass(frozen=True)
class RouteSource:
    scan_id: str | None
    routes: list[Route]


def latest_routes(s: Session, asset_id: str, org_id: str) -> RouteSource:
    """The newest completed scan of the project that recorded routes: its entrypoints when it has
    them, its route map otherwise. An imported report never has either."""
    scans = s.scalars(
        select(Scan)
        .where(
            Scan.asset_id == asset_id,
            Scan.org_id == org_id,
            Scan.status == "completed",
            (Scan.entrypoints.is_not(None)) | (Scan.route_map.is_not(None)),
        )
        .order_by(Scan.created_at.desc())
        .limit(SCANS_LOOKED_AT)
    )
    for scan in scans:
        if scan.entrypoints:
            return RouteSource(scan.id, [_route(e) for e in scan.entrypoints])
        if scan.route_map:
            return RouteSource(
                scan.id,
                [
                    Route("", str(r["route"]), str(r["path"]), int(r["line"]))
                    for r in scan.route_map
                ],
            )
    return RouteSource(None, [])


def _route(e: dict[str, object]) -> Route:
    return Route(
        method=str(e.get("method") or ""),
        route=str(e.get("route") or ""),
        path=str(e.get("path") or ""),
        line=int(str(e.get("line") or 0)),
        symbol=str(e.get("symbol") or ""),
        framework=str(e.get("framework") or ""),
    )


@dataclass(frozen=True)
class Related:
    issue_id: str
    source: str  # the tool that found it: "semgrep", "opengrep", "bandit"...
    finding: Finding


def related_automated_finding(
    s: Session, *, asset_id: str, scan_id: str | None, manual: Finding, handlers: list[Route]
) -> Related | None:
    """The static finding automation already has on this route's handler with a related CWE, if
    any -- preferring one with a concrete taint path, because that path is the evidence a manual
    finding gains from it."""
    if scan_id is None or not manual.location.route or not manual.taxonomy.cwe:
        return None
    rows = list(
        s.execute(
            select(FindingRow.data, FindingRow.issue_id)
            .join(IssueRow, IssueRow.id == FindingRow.issue_id)
            .where(FindingRow.scan_id == scan_id, IssueRow.asset_id == asset_id)
        )
    )
    static: list[tuple[Finding, str]] = []
    for data, issue_id in rows:
        f = finding_from_dict(data)
        if f.taxonomy.category is Category.SAST and issue_id:
            static.append((f, issue_id))
    if not static:
        return None
    route_handlers = [
        RouteHandler(normalize_route_pattern(h.route), h.path, h.line) for h in handlers
    ]
    probe = replace(manual, taxonomy=replace(manual.taxonomy, category=Category.DAST))
    matches = correlate_dast_with_sast([probe], [f for f, _ in static], route_handlers)
    if not matches:
        return None
    by_id = {f.id: (f, iid) for f, iid in static}
    candidates = [by_id[m.sast_finding_id] for m in matches if m.sast_finding_id in by_id]
    candidates.sort(key=lambda fi: (not fi[0].taint_path, fi[0].location.start_line))
    finding, issue_id = candidates[0]
    source = finding.evidence.reported_by[0] if finding.evidence.reported_by else "scanner"
    return Related(issue_id, source, finding)


def find_route(routes: list[Route], method: str, route: str) -> Route | None:
    """The handler a picked route resolves to: the same verb when the scan recorded one, else
    any verb."""
    exact = [r for r in routes if r.route == route and r.method.upper() == method.upper()]
    loose = [r for r in routes if r.route == route and not r.method]
    found = exact or loose
    return found[0] if found else None
