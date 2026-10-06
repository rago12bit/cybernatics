"""What an advisory means for one organization (plan §46.2, §55.5).

`match` joins advisories to the organization's libraries by library key (one indexed join), reads
the current versions of those libraries, and decides each (advisory, version) pair once with OSV's
rules (`core.advisories.osv.affects`). The result is kept as impacts -- one per vulnerability,
library version and project -- so the morning a CVE lands, the impact view is a read, not a
search. Matching runs for what changed: the libraries of a newly recorded SBOM, or the advisories a
feed update changed (every record of the same vulnerability, so a sibling record is never lost).

A vulnerability an organization had never been affected by announces itself once
(`advisory.matched` on the outbox), which tells the team channels and the projects' owners.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, insert, select
from sqlalchemy.orm import Session

from core.advisories.osv import Affected, affects, fixed_in
from core.persistence import repo
from core.persistence.models import (
    Advisory,
    AdvisoryImpact,
    AdvisoryPackage,
    AdvisoryState,
    Asset,
    ComponentRow,
    Library,
)
from core.versions import VersionError, key

log = logging.getLogger(__name__)
_CHUNK = 500
FULL_MATCH_OVER = 5000  # more changed vulnerabilities than this: match everything at once


@dataclass
class Matched:
    opened: int = 0
    resolved: int = 0
    new_vulns: list[str] = field(default_factory=list)
    changed_assets: dict[str, set[str]] = field(default_factory=dict)  # vuln_key -> assets


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _chunks(items: Collection[str]) -> Iterator[list[str]]:
    seq = sorted(items)
    for i in range(0, len(seq), _CHUNK):
        yield seq[i : i + _CHUNK]


def _candidates(
    s: Session,
    org_id: str,
    library_ids: Collection[str] | None,
    vuln_keys: Collection[str] | None,
) -> list[Any]:
    base = (
        select(
            AdvisoryPackage.id,
            AdvisoryPackage.advisory_id,
            AdvisoryPackage.ecosystem,
            AdvisoryPackage.name,
            AdvisoryPackage.data,
            Library.id,
            Advisory.vuln_key,
        )
        .join(Library, and_(Library.key == AdvisoryPackage.lib_key, Library.org_id == org_id))
        .join(Advisory, Advisory.id == AdvisoryPackage.advisory_id)
        .where(Advisory.withdrawn.is_(None), Library.project_count > 0)
    )
    if library_ids is not None:
        by_lib = [base.where(Library.id.in_(c)) for c in _chunks(library_ids)]
        return [r for q in by_lib for r in s.execute(q)]
    if vuln_keys is not None:
        by_vuln = [base.where(Advisory.vuln_key.in_(c)) for c in _chunks(vuln_keys)]
        return [r for q in by_vuln for r in s.execute(q)]
    return list(s.execute(base))


def match(
    s: Session,
    org_id: str,
    *,
    library_ids: Collection[str] | None = None,
    vuln_keys: Collection[str] | None = None,
    asset_ids: Collection[str] | None = None,
    now: datetime | None = None,
    commit: bool = True,
) -> Matched:
    """Bring the organization's impacts up to date for `library_ids` (an SBOM was recorded), or
    `vuln_keys` (advisories changed), or everything when neither is given -- and, with
    `asset_ids`, only in those projects (a new SBOM changes nothing in any other project).
    Only rows whose answer changed are written."""
    now = now or _now()
    out = Matched()
    rows = _candidates(s, org_id, library_ids, vuln_keys)
    libs = {r[5] for r in rows}
    uses: dict[str, list[tuple[str, str]]] = defaultdict(list)  # library -> (asset, version)
    for c in _chunks(libs):
        q = select(ComponentRow.library_id, ComponentRow.asset_id, ComponentRow.version).where(
            ComponentRow.library_id.in_(c), ComponentRow.current.is_(True)
        )
        if asset_ids is not None:
            q = q.where(ComponentRow.asset_id.in_(sorted(asset_ids)))
        for lib_id, asset_id, version in s.execute(q.distinct()):
            uses[lib_id].append((asset_id, version))

    desired: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    # One verdict per (package entry, version): OSV lists a package once per range, so the entry,
    # not the advisory, is what a verdict belongs to.
    verdicts: dict[tuple[int, str], tuple[bool | None, str | None]] = {}
    for entry_id, advisory_id, eco, name, data, lib_id, vuln_key in rows:
        if lib_id not in uses:
            continue
        aff = Affected.from_dict(eco, name, data or {})
        for asset_id, version in uses[lib_id]:
            memo = (entry_id, version)
            if memo not in verdicts:
                hit = affects(aff, version) if version else None
                verdicts[memo] = (hit, fixed_in(aff, version) if hit else None)
            hit, fixed = verdicts[memo]
            if hit is False:
                continue
            d = desired.setdefault(
                (asset_id, lib_id, version, vuln_key),
                {"ids": set(), "fixed": None, "certain": False, "eco": eco},
            )
            # Several records (and several entries of one record) can say so: one is enough,
            # and the lowest fixed version among those that are sure is the upgrade.
            if hit is None and d["certain"]:
                continue
            if hit is True and not d["certain"]:
                d["ids"], d["certain"] = set(), True
            d["ids"].add(advisory_id)
            if fixed and (d["fixed"] is None or _lower(eco, fixed, d["fixed"])):
                d["fixed"] = fixed

    scope = select(AdvisoryImpact).where(AdvisoryImpact.org_id == org_id)
    if asset_ids is not None:
        scope = scope.where(AdvisoryImpact.asset_id.in_(sorted(asset_ids)))
    if library_ids is not None:
        chunks = [scope.where(AdvisoryImpact.library_id.in_(c)) for c in _chunks(library_ids)]
    elif vuln_keys is not None:
        chunks = [scope.where(AdvisoryImpact.vuln_key.in_(c)) for c in _chunks(vuln_keys)]
    else:
        chunks = [scope]
    existing: dict[tuple[str, str, str, str], AdvisoryImpact] = {}
    for scoped in chunks:
        for imp in s.scalars(scoped):
            existing[(imp.asset_id, imp.library_id, imp.version, imp.vuln_key)] = imp

    touched: dict[str, set[str]] = defaultdict(set)
    new_rows: list[dict[str, Any]] = []
    for k, d in desired.items():
        row = existing.get(k)
        ids = sorted(d["ids"])
        if row is None:
            new_rows.append({
                "id": str(uuid.uuid4()), "org_id": org_id, "asset_id": k[0], "library_id": k[1],
                "version": k[2], "vuln_key": k[3], "advisory_ids": ids,
                "fixed_version": d["fixed"], "certain": d["certain"], "first_seen_at": now,
                "last_seen_at": now, "resolved_at": None,
            })  # fmt: skip
            touched[k[3]].add(k[0])
            continue
        if row.resolved_at is not None:
            row.resolved_at = None
            out.opened += 1
            touched[k[3]].add(k[0])
        if (row.advisory_ids, row.fixed_version, row.certain) != (ids, d["fixed"], d["certain"]):
            row.advisory_ids, row.fixed_version, row.certain = ids, d["fixed"], d["certain"]
            row.last_seen_at = now
            touched[k[3]].add(k[0])
    for k, row in existing.items():
        if k not in desired and row.resolved_at is None:
            row.resolved_at = now
            out.resolved += 1
            touched[k[3]].add(k[0])
    for i in range(0, len(new_rows), _CHUNK):
        s.execute(insert(AdvisoryImpact), new_rows[i : i + _CHUNK])
    out.opened += len(new_rows)
    s.flush()
    out.changed_assets = {v: a for v, a in touched.items()}
    out.new_vulns = _announce(s, org_id, {k[3] for k in desired}, now)
    if commit:
        s.commit()
    return out


def _lower(eco: str, a: str, b: str) -> bool:
    try:
        return bool(key(eco, a) < key(eco, b))
    except VersionError:
        return a < b


def _announce(s: Session, org_id: str, vuln_keys: set[str], now: datetime) -> list[str]:
    """A state row for each vulnerability the organization is affected by for the first time, and
    one `advisory.matched` event each, naming how many projects and their owners."""
    if not vuln_keys:
        return []
    known: set[str] = set()
    for c in _chunks(vuln_keys):
        known.update(
            s.scalars(
                select(AdvisoryState.vuln_key).where(
                    AdvisoryState.org_id == org_id, AdvisoryState.vuln_key.in_(c)
                )
            )
        )
    fresh = sorted(vuln_keys - known)
    if not fresh:
        return []
    assets: dict[str, set[str]] = defaultdict(set)
    for c in _chunks(fresh):
        for vk, asset_id in s.execute(
            select(AdvisoryImpact.vuln_key, AdvisoryImpact.asset_id).where(
                AdvisoryImpact.org_id == org_id,
                AdvisoryImpact.vuln_key.in_(c),
                AdvisoryImpact.resolved_at.is_(None),
            )
        ):
            assets[vk].add(asset_id)
    everyone = sorted({a for v in assets.values() for a in v})
    owner_of: dict[str, str] = {}
    for c in _chunks(everyone):
        owner_of.update(
            (a, o) for a, o in s.execute(select(Asset.id, Asset.owner).where(Asset.id.in_(c))) if o
        )
    s.execute(
        insert(AdvisoryState),
        [{"id": str(uuid.uuid4()), "org_id": org_id, "vuln_key": vk, "state": "new",
          "first_seen_at": now, "updated_at": now, "updated_by": None} for vk in fresh],
    )  # fmt: skip
    for vk in fresh:
        mine = sorted(assets.get(vk, ()))
        repo.add_outbox_event(
            s, org_id=org_id, event_type="advisory.matched",
            payload={"vuln_key": vk, "projects": len(mine), "asset_ids": mine[:50],
                     "owners": sorted({owner_of[a] for a in mine if a in owner_of})},
        )  # fmt: skip
    s.flush()
    return fresh


def match_after_record(
    s: Session, org_id: str, library_ids: Collection[str], asset_ids: Collection[str]
) -> None:
    """After a project's SBOM was recorded (and committed): match the libraries whose use changed,
    in that project, and bring the Issues of adopted vulnerabilities up to date. In its own
    transaction and best effort -- a failure here is logged and never undoes the inventory."""
    if not library_ids:
        return
    try:
        result = match(s, org_id, library_ids=library_ids, asset_ids=asset_ids)
        if result.changed_assets:
            from core.advisories.issues import sync_changed

            sync_changed(s, org_id, result.changed_assets)
    except Exception:  # noqa: BLE001
        s.rollback()
        log.exception("advisories: matching after an SBOM failed")
