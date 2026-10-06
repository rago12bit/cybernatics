""" "Where do we use this?" (plan §46.1).

    search(s, org, purl="pkg:maven/org.apache.logging.log4j/log4j-core", constraint="<2.17.1")
    -> 14 projects in 6 business units, 3 internet-facing, 2 importing it from application code

The library is found by its key (one indexed lookup), its versions in current SBOMs are counted
(one indexed aggregate), each distinct version is checked against the condition once in Python --
with the ecosystem's own ordering, which SQL does not know -- and only then are the matching rows
read. A version the ecosystem cannot read is listed as "could not be compared", never quietly
counted in or out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.inventory.identity import from_purl
from core.persistence.models import Asset, ComponentRow, Library, Portfolio, PriorityPolicy
from core.versions import Constraint, VersionError, parse_constraint

MAX_USES = 2000


class SearchError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class Use:
    project_id: str
    project: str
    portfolio: str | None
    version: str
    relation: str
    paths: list[str]
    reachable: bool | None
    reachable_reason: str
    exposure: str  # internet | internal | unset (the project's priority context)
    source: str
    scan_id: str
    seen_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "paths": list(self.paths)}


@dataclass
class Result:
    library: dict[str, Any] | None
    constraint: str | None
    versions: list[dict[str, Any]] = field(default_factory=list)
    uses: list[Use] = field(default_factory=list)
    uncomparable: list[str] = field(default_factory=list)
    truncated: bool = False

    def summary(self) -> dict[str, int]:
        projects = {u.project_id for u in self.uses}
        exposure = {u.project_id: u.exposure for u in self.uses}
        return {
            "projects": len(projects),
            "portfolios": len({u.portfolio for u in self.uses if u.portfolio}),
            "internet_facing": sum(1 for e in exposure.values() if e == "internet"),
            "exposure_unset": sum(1 for e in exposure.values() if e == "unset"),
            "imported_by_app": len({u.project_id for u in self.uses if u.reachable is True}),
            "direct": len({u.project_id for u in self.uses if u.relation == "direct"}),
            "versions": len({u.version for u in self.uses}),
        }


def library_view(lib: Library) -> dict[str, Any]:
    return {"id": lib.id, "ecosystem": lib.ecosystem, "name": lib.name, "purl": lib.purl}


def exposures(s: Session, asset_ids: list[str]) -> dict[str, str]:
    """Each project's exposure as its newest priority policy states it; "unset" without one."""
    out: dict[str, str] = {}
    for i in range(0, len(asset_ids), 500):
        chunk = asset_ids[i : i + 500]
        rows = s.execute(
            select(PriorityPolicy.asset_id, PriorityPolicy.context)
            .where(PriorityPolicy.asset_id.in_(chunk))
            .order_by(PriorityPolicy.asset_id, PriorityPolicy.version.desc())
        ).all()
        for asset_id, context in rows:
            if asset_id in out:
                continue
            facing = (context or {}).get("internet_facing")
            exposure = "internet" if facing is True else "internal" if facing is False else None
            out[asset_id] = exposure or "unset"
    return {a: out.get(a, "unset") for a in asset_ids}


def find_library(s: Session, org_id: str, purl: str) -> tuple[Library | None, str]:
    ident = from_purl(purl)
    if ident is None:
        raise SearchError("purl", "Not a package URL. Example: pkg:npm/lodash or pkg:pypi/django")
    lib = s.scalars(
        select(Library).where(Library.org_id == org_id, Library.key == ident.key)
    ).first()
    return lib, ident.version


def search(
    s: Session,
    org_id: str,
    *,
    purl: str,
    constraint: str | None = None,
    project_id: str | None = None,
) -> Result:
    lib, purl_version = find_library(s, org_id, purl)
    cond: Constraint | None = None
    text = constraint if constraint else (f"={purl_version}" if purl_version else None)
    if text:
        try:
            cond = parse_constraint(text)
        except VersionError as exc:
            raise SearchError("version", str(exc)) from exc
    result = Result(
        library=library_view(lib) if lib else None, constraint=str(cond) if cond else None
    )
    if lib is None:
        return result

    where = [ComponentRow.library_id == lib.id, ComponentRow.current.is_(True)]
    if project_id:
        where.append(ComponentRow.asset_id == project_id)
    counts = s.execute(
        select(ComponentRow.version, func.count(func.distinct(ComponentRow.asset_id)))
        .where(*where)
        .group_by(ComponentRow.version)
    ).all()
    wanted: list[str] = []
    for version, n in counts:
        match: bool | None = True
        if cond is not None:
            try:
                match = cond.check(lib.ecosystem, version)
            except VersionError:
                match = None
                result.uncomparable.append(version or "(no version)")
        result.versions.append({"version": version, "projects": n, "matches": match})
        if match:
            wanted.append(version)
    # The vulnerabilities each version has in the organization's projects now (Week 68).
    from core.persistence.models import AdvisoryImpact

    vulns: dict[str, set[str]] = {}
    for version, vk in s.execute(
        select(AdvisoryImpact.version, AdvisoryImpact.vuln_key).where(
            AdvisoryImpact.library_id == lib.id, AdvisoryImpact.resolved_at.is_(None)
        )
    ):
        vulns.setdefault(version, set()).add(vk)
    for v in result.versions:
        v["advisories"] = sorted(vulns.get(v["version"], ()))
    result.versions.sort(key=lambda v: (-v["projects"], v["version"]))
    result.uncomparable.sort()
    if not wanted:
        return result

    rows = s.execute(
        select(ComponentRow, Asset.label, Portfolio.name)
        .join(Asset, Asset.id == ComponentRow.asset_id)
        .outerjoin(Portfolio, Portfolio.id == Asset.portfolio_id)
        .where(*where, ComponentRow.version.in_(wanted))
        .order_by(Asset.label, ComponentRow.version, ComponentRow.source)
        .limit(MAX_USES + 1)
    ).all()
    if len(rows) > MAX_USES:
        result.truncated, rows = True, rows[:MAX_USES]
    exposure = exposures(s, sorted({r[0].asset_id for r in rows}))
    result.uses = [
        Use(
            project_id=c.asset_id, project=label, portfolio=portfolio, version=c.version,
            relation=c.relation, paths=list(c.paths or []), reachable=c.reachable,
            reachable_reason=c.reachable_reason, exposure=exposure[c.asset_id], source=c.source,
            scan_id=c.scan_id, seen_at=c.seen_at,
        )
        for c, label, portfolio in rows
    ]  # fmt: skip
    return result


def libraries(
    s: Session, org_id: str, *, q: str = "", ecosystem: str | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Libraries in use, by name, most widely used first: what the search box offers as you type.
    One row per library, with how many projects and versions use it now (`Library.project_count`,
    kept by `core.inventory.store`), so this reads the libraries table and nothing else."""
    stmt = select(Library).where(Library.org_id == org_id, Library.project_count > 0)
    q = q.strip()
    if q.startswith("pkg:"):
        ident = from_purl(q)
        if ident is None:
            return []
        stmt = stmt.where(Library.key == ident.key)
    elif q:
        escaped = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        stmt = stmt.where(
            func.lower(Library.key).like(pattern, escape="\\")
            | func.lower(Library.name).like(pattern, escape="\\")
        )
    if ecosystem:
        stmt = stmt.where(Library.ecosystem == ecosystem)
    rows = s.scalars(stmt.order_by(Library.project_count.desc(), Library.name).limit(limit))
    return [
        {**library_view(lib), "projects": lib.project_count, "versions": lib.version_count}
        for lib in rows
    ]
