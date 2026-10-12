"""Reading advisories for one organization (plan §55.5, journey J7).

`listing` is the morning's list: every vulnerability affecting the organization now, newest first,
with how many projects, how many internet-facing and how many importing the library. `impact` is
one vulnerability's page: the projects, each with its version, the fix, whether its code imports
the library, its owner and exposure, and what has been done.

Reachability is reachability v1 -- whether application code imports the library -- and is worded
"not imported by application code", never "unreachable" (§55.5: the screen never claims code is
unreachable).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.collab.people import names
from core.inventory.search import exposures
from core.models import Severity
from core.persistence.models import (
    Advisory,
    AdvisoryImpact,
    AdvisoryState,
    Asset,
    ComponentRow,
    CveRecord,
    IssueGroup,
    IssueRow,
    KevEntry,
    Library,
    Portfolio,
)
from core.scoring.severity import from_cvss, normalize

ORDER = {s: i for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}


def representative(records: Sequence[Advisory]) -> Advisory:
    """The record whose words are shown: a reviewed GitHub advisory, else the one with the longest
    summary, else the lowest id."""
    return sorted(
        records,
        key=lambda r: (not r.id.startswith("GHSA-"), -len(r.summary or ""), r.id),
    )[0]


def severity_of(
    records: Sequence[Advisory], nvd: float | None = None
) -> tuple[Severity, float | None]:
    """Like osv-scanner: a malicious package is critical; otherwise the highest CVSS base score of
    the records (NVD's when they have none), else GitHub's own label."""
    if any(
        r.id.startswith("MAL-") or any(a.startswith("MAL-") for a in r.aliases) for r in records
    ):
        return Severity.CRITICAL, None
    scores = [r.cvss for r in records if r.cvss is not None]
    score = max(scores) if scores else nvd
    if score is not None:
        return from_cvss(score), score
    label = next((r.db_severity for r in records if r.db_severity), "")
    return normalize("osv-scanner", label), None


def _cves(records: Sequence[Advisory]) -> list[str]:
    return sorted({a for r in records for a in (r.id, *r.aliases) if a.startswith("CVE-")})


def _kev(s: Session, cves: list[str]) -> dict[str, Any] | None:
    if not cves:
        return None
    row = s.scalars(select(KevEntry).where(KevEntry.cve.in_(cves)).order_by(KevEntry.cve)).first()
    return (
        {"cve": row.cve, "date_added": row.date_added, "due_date": row.due_date,
         "name": row.name, "ransomware": row.ransomware}
        if row else None
    )  # fmt: skip


def _nvd(s: Session, cves: list[str]) -> CveRecord | None:
    if not cves:
        return None
    return s.scalars(
        select(CveRecord).where(CveRecord.id.in_(cves), CveRecord.cvss.is_not(None))
    ).first()


_LIST_COLUMNS = (
    Advisory.id, Advisory.vuln_key, Advisory.summary, Advisory.aliases, Advisory.cvss,
    Advisory.db_severity, Advisory.published, Advisory.withdrawn, Advisory.modified,
)  # fmt: skip


def _records(s: Session, vuln_keys: Sequence[str], *, light: bool = False) -> dict[str, list[Any]]:
    """The records of each vulnerability. `light` reads plain rows of the columns the list needs
    (not ORM objects, and not the long text), which is most of its cost at thousands of them."""
    out: dict[str, list[Any]] = defaultdict(list)
    for i in range(0, len(vuln_keys), 500):
        chunk = vuln_keys[i : i + 500]
        if light:
            for row in s.execute(select(*_LIST_COLUMNS).where(Advisory.vuln_key.in_(chunk))):
                out[row.vuln_key].append(row)
        else:
            for r in s.scalars(select(Advisory).where(Advisory.vuln_key.in_(chunk))):
                out[r.vuln_key].append(r)
    return out


def header(s: Session, vuln_key: str, records: Sequence[Advisory]) -> dict[str, Any]:
    rep = representative(records)
    cves = _cves(records)
    nvd = _nvd(s, cves)
    sev, score = severity_of(records, nvd.cvss if nvd else None)
    published = [r.published for r in records if r.published]
    return {
        "vuln_key": vuln_key,
        "ids": sorted(r.id for r in records),
        "aliases": sorted(
            {a for r in records for a in r.aliases} - {r.id for r in records} - {vuln_key}
        ),
        "cves": cves,
        "summary": rep.summary or (nvd.description[:300] if nvd else "") or vuln_key,
        "details": rep.details or (nvd.description if nvd else ""),
        "severity": sev.value,
        "cvss": score,
        "cvss_vector": next(
            (r.cvss_vector for r in records if r.cvss == score and r.cvss_vector), ""
        )
        or (nvd.cvss_vector if nvd and nvd.cvss == score else ""),
        "malicious": any(r.id.startswith("MAL-") for r in records),
        "kev": _kev(s, cves),
        "published": min(published) if published else None,
        "modified": max(r.modified for r in records),
        "references": sorted({u for r in records for u in r.references})[:30],
        "withdrawn": all(r.withdrawn is not None for r in records),
    }


def listing(
    s: Session,
    org_id: str,
    *,
    state: str | None = None,
    q: str = "",
    kev_only: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Sort keys for every vulnerability from a few bulk reads (no query per vulnerability), then
    the detailed counts for the page only -- an organization can be affected by thousands."""
    open_ = (
        select(
            AdvisoryImpact.vuln_key,
            func.count(func.distinct(AdvisoryImpact.asset_id)),
            func.min(AdvisoryImpact.first_seen_at),
        )
        .where(AdvisoryImpact.org_id == org_id, AdvisoryImpact.resolved_at.is_(None))
        .group_by(AdvisoryImpact.vuln_key)
    )
    counts = {vk: (n, first) for vk, n, first in s.execute(open_)}
    if not counts:
        return []
    states = {
        st.vuln_key: st
        for st in s.scalars(select(AdvisoryState).where(AdvisoryState.org_id == org_id))
    }
    keys = sorted(counts)
    if state:
        keys = [k for k in keys if (states[k].state if k in states else "new") == state]
    records = _records(s, keys, light=True)
    kev = set(s.scalars(select(KevEntry.cve)))
    unscored = [recs for recs in records.values() if not any(r.cvss for r in recs)]
    no_score = sorted({c for recs in unscored for c in _cves(recs)})
    nvd: dict[str, float] = {}
    for i in range(0, len(no_score), 500):
        nvd.update(
            (cid, score)
            for cid, score in s.execute(
                select(CveRecord.id, CveRecord.cvss).where(
                    CveRecord.id.in_(no_score[i : i + 500]), CveRecord.cvss.is_not(None)
                )
            )
            if score is not None
        )
    needle = q.strip().lower()
    named = _library_matches(s, org_id, needle) if needle else set()
    rows: list[dict[str, Any]] = []
    for vk in keys:
        recs = records.get(vk) or []
        if not recs:
            continue
        cves = _cves(recs)
        known = bool(kev.intersection(cves))
        if kev_only and not known:
            continue
        rep = representative(recs)
        if needle and vk not in named:
            words = [vk, rep.summary, *(r.id for r in recs), *(a for r in recs for a in r.aliases)]
            if needle not in " ".join(words).lower():
                continue
        scores = [nvd[c] for c in cves if c in nvd]
        sev, score = severity_of(recs, max(scores) if scores else None)
        st = states.get(vk)
        published = [r.published for r in recs if r.published]
        rows.append({
            "vuln_key": vk, "ids": sorted(r.id for r in recs), "summary": rep.summary or vk,
            "severity": sev.value, "cvss": score, "kev": known,
            "malicious": any(r.id.startswith("MAL-") for r in recs),
            "published": min(published) if published else None,
            "first_seen_at": st.first_seen_at if st else counts[vk][1],
            "state": st.state if st else "new", "projects": counts[vk][0],
        })  # fmt: skip
    # The newest day first; within a day, known-exploited, then the most severe, then the widest.
    rows.sort(
        key=lambda r: (
            _day(r["first_seen_at"]),
            r["kev"],
            -ORDER.get(r["severity"], 9),
            r["projects"],
        ),
        reverse=True,
    )
    page = rows[:limit]
    detail = _usage(s, org_id, [r["vuln_key"] for r in page])
    for r in page:
        d = detail[r["vuln_key"]]
        r.update(
            libraries=sorted(d["libraries"]), imported_by_app=len(d["imported"]),
            internet_facing=len(d["internet"]), uncertain=len(d["uncertain"]),
        )  # fmt: skip
    return page


def _library_matches(s: Session, org_id: str, needle: str) -> set[str]:
    """Vulnerabilities whose affected library's name contains `needle`."""
    escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return set(
        s.scalars(
            select(AdvisoryImpact.vuln_key)
            .join(Library, Library.id == AdvisoryImpact.library_id)
            .where(
                AdvisoryImpact.org_id == org_id,
                AdvisoryImpact.resolved_at.is_(None),
                func.lower(Library.name).like(f"%{escaped}%", escape="\\"),
            )
            .distinct()
        )
    )


def _day(when: datetime) -> str:
    return when.date().isoformat()


def _usage(s: Session, org_id: str, keys: Sequence[str]) -> dict[str, dict[str, set[str]]]:
    out: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"libraries": set(), "imported": set(), "internet": set(), "uncertain": set()}
    )
    if not keys:
        return out
    rows = s.execute(
        select(AdvisoryImpact, Library.name)
        .join(Library, Library.id == AdvisoryImpact.library_id)
        .where(
            AdvisoryImpact.org_id == org_id,
            AdvisoryImpact.resolved_at.is_(None),
            AdvisoryImpact.vuln_key.in_(list(keys)),
        )
    ).all()
    assets = sorted({i.asset_id for i, _n in rows})
    exposure = exposures(s, assets)
    imported: set[tuple[str, str, str]] = set()
    libs = sorted({i.library_id for i, _n in rows})
    for i in range(0, len(libs), 500):
        imported.update(
            (a, lib, v)
            for a, lib, v in s.execute(
                select(ComponentRow.asset_id, ComponentRow.library_id, ComponentRow.version).where(
                    ComponentRow.library_id.in_(libs[i : i + 500]),
                    ComponentRow.current.is_(True),
                    ComponentRow.reachable.is_(True),
                )
            )
        )
    for imp, name in rows:
        d = out[imp.vuln_key]
        d["libraries"].add(name)
        if (imp.asset_id, imp.library_id, imp.version) in imported:
            d["imported"].add(imp.asset_id)
        if exposure.get(imp.asset_id) == "internet":
            d["internet"].add(imp.asset_id)
        if not imp.certain:
            d["uncertain"].add(imp.asset_id)
    return out


def impact(s: Session, org_id: str, vuln_key: str) -> dict[str, Any] | None:
    records = _records(s, [vuln_key]).get(vuln_key)
    if not records:
        return None
    rows = s.execute(
        select(AdvisoryImpact, Library, Asset, Portfolio.name)
        .join(Library, Library.id == AdvisoryImpact.library_id)
        .join(Asset, Asset.id == AdvisoryImpact.asset_id)
        .outerjoin(Portfolio, Portfolio.id == Asset.portfolio_id)
        .where(AdvisoryImpact.org_id == org_id, AdvisoryImpact.vuln_key == vuln_key)
    ).all()
    if not rows:
        return None
    st = s.scalars(
        select(AdvisoryState).where(
            AdvisoryState.org_id == org_id, AdvisoryState.vuln_key == vuln_key
        )
    ).first()
    assets = sorted({a.id for _i, _l, a, _p in rows})
    exposure = exposures(s, assets)
    owners = names(s, org_id, {a.owner for _i, _l, a, _p in rows if a.owner})
    issues: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in s.scalars(
        select(IssueRow)
        .join(IssueGroup, IssueGroup.id == IssueRow.group_id)
        .where(IssueGroup.org_id == org_id, IssueGroup.name == vuln_key)
    ):
        issues[issue.asset_id].append(
            {"id": issue.id, "state": issue.state, "triage_status": issue.triage_status}
        )
    comps: dict[tuple[str, str, str], ComponentRow] = {}
    lib_ids = sorted({lib.id for _i, lib, _a, _p in rows})
    for i in range(0, len(lib_ids), 500):  # one read for every use, not one per use
        for c in s.scalars(
            select(ComponentRow).where(
                ComponentRow.library_id.in_(lib_ids[i : i + 500]),
                ComponentRow.asset_id.in_(assets),
                ComponentRow.current.is_(True),
            )
        ):
            comps.setdefault((c.asset_id, c.library_id, c.version), c)
    uses = []
    for imp, lib, asset, portfolio in rows:
        comp = comps.get((asset.id, lib.id, imp.version))
        uses.append({
            "project_id": asset.id, "project": asset.label, "portfolio": portfolio,
            "library": lib.name, "ecosystem": lib.ecosystem, "purl": lib.purl,
            "version": imp.version, "fixed_version": imp.fixed_version, "certain": imp.certain,
            "resolved_at": imp.resolved_at, "first_seen_at": imp.first_seen_at,
            "relation": comp.relation if comp else "unknown",
            "paths": list(comp.paths or []) if comp else [],
            "reachable": comp.reachable if comp else None,
            "reachable_reason": comp.reachable_reason if comp else "",
            "exposure": exposure.get(asset.id, "unset"),
            "owner": owners.get(asset.owner or "", asset.owner) if asset.owner else None,
            "issues": issues.get(asset.id, []),
        })  # fmt: skip
    open_uses = [u for u in uses if u["resolved_at"] is None]
    open_uses.sort(
        key=lambda u: (u["reachable"] is not True, u["exposure"] != "internet", u["project"])
    )
    fixed = [u for u in uses if u["resolved_at"] is not None]
    return {
        **header(s, vuln_key, records),
        "state": st.state if st else "new",
        "first_seen_at": st.first_seen_at if st else min(i.first_seen_at for i, *_ in rows),
        "uses": open_uses,
        "no_longer_affected": fixed,
        "summary_counts": {
            "projects": len({u["project_id"] for u in open_uses}),
            "portfolios": len({u["portfolio"] for u in open_uses if u["portfolio"]}),
            "imported_by_app": len({u["project_id"] for u in open_uses if u["reachable"] is True}),
            "internet_facing": len(
                {u["project_id"] for u in open_uses if u["exposure"] == "internet"}
            ),
            "uncertain": len({u["project_id"] for u in open_uses if not u["certain"]}),
            "with_fix": len({u["project_id"] for u in open_uses if u["fixed_version"]}),
            "with_issues": len({u["project_id"] for u in open_uses if u["issues"]}),
        },
    }
