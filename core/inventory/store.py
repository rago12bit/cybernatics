"""Writing SBOMs into the inventory (plan §46.1).

`record` stores one SBOM's packages for one project from one scan or import, merging repeats (the
same library at the same version found in two lockfiles is one row listing both paths), and then
`refresh_current` marks the rows of that source's latest SBOM as the project's current inventory.
Doing that from the database, not from "the one just written", is what keeps it right when two
scans finish out of order or an import is reverted.

Only a full scan of a project's real state is recorded (the pipeline's own condition for writing
Issue history): a pull-request scan's SBOM describes code that may never merge.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, delete, exists, func, insert, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from core.inventory.identity import Ident, from_purl
from core.persistence.models import Asset, ComponentRow, Library, Scan

log = logging.getLogger(__name__)

MAX_COMPONENTS = 200_000  # per SBOM; more is not an application, and the rest are dropped, said so
MAX_PATHS = 20
SCAN_SOURCE = "scan"
RELATIONS = frozenset({"direct", "transitive", "root", "unknown"})
_CHUNK = 500


@dataclass(frozen=True)
class Recorded:
    components: int
    new_libraries: int
    skipped: int  # entries that were not a usable purl, or past MAX_COMPONENTS


def import_source(test_id: str) -> str:
    return f"test:{test_id}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


def _chunks(items: list[Any]) -> Iterable[list[Any]]:
    for i in range(0, len(items), _CHUNK):
        yield items[i : i + _CHUNK]


def _merge(
    packages: Iterable[Mapping[str, Any]],
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[str, Ident], int]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    libs: dict[str, Ident] = {}
    skipped = 0
    for p in packages:
        ident = from_purl(str(p.get("purl") or ""))
        if ident is None or len(rows) >= MAX_COMPONENTS:
            skipped += 1
            continue
        version = (ident.version or str(p.get("version") or ""))[:200]
        path = str(p.get("path") or "")[:500]
        relation = str(p.get("relation") or "unknown")
        reachable = p.get("reachable")
        row = rows.get((ident.key, version))
        if row is None:
            libs.setdefault(ident.key, ident)
            rows[(ident.key, version)] = {
                "purl": str(p.get("purl"))[:2000],
                "version": version,
                "relation": relation if relation in RELATIONS else "unknown",
                "paths": [path] if path else [],
                "license": str(p.get("license") or "")[:200],
                "reachable": reachable if isinstance(reachable, bool) else None,
                "reachable_reason": str(p.get("reachable_reason") or "")[:300],
            }
            continue
        if path and path not in row["paths"] and len(row["paths"]) < MAX_PATHS:
            row["paths"].append(path)
        if row["relation"] != "direct" and relation == "direct":  # direct anywhere is direct
            row["relation"] = "direct"
        if reachable is True or (row["reachable"] is None and reachable is False):
            row["reachable"] = reachable
            row["reachable_reason"] = str(p.get("reachable_reason") or "")[:300]
    return rows, libs, skipped


def _insert_ignore(s: Session) -> Any:
    return postgresql.insert if s.get_bind().dialect.name == "postgresql" else sqlite.insert


def _library_ids(s: Session, org_id: str, libs: dict[str, Ident]) -> tuple[dict[str, str], int]:
    keys = list(libs)
    ids: dict[str, str] = {}
    for chunk in _chunks(keys):
        ids.update(
            s.execute(
                select(Library.key, Library.id).where(
                    Library.org_id == org_id, Library.key.in_(chunk)
                )
            ).all()  # type: ignore[arg-type]
        )
    missing = [k for k in keys if k not in ids]
    now = _now()
    if missing:
        ins = _insert_ignore(s)
        for chunk in _chunks(missing):
            stmt = ins(Library).values(
                [
                    {
                        "id": _uuid(), "org_id": org_id, "ecosystem": libs[k].ecosystem,
                        "name": libs[k].name, "key": k, "purl": libs[k].purl,
                        "first_seen_at": now, "last_seen_at": now,
                    }
                    for k in chunk
                ]
            )  # fmt: skip
            # Another scan may add the same library at the same moment: keep whichever won.
            s.execute(stmt.on_conflict_do_nothing(index_elements=["org_id", "key"]))
        for chunk in _chunks(missing):
            ids.update(
                s.execute(
                    select(Library.key, Library.id).where(
                        Library.org_id == org_id, Library.key.in_(chunk)
                    )
                ).all()  # type: ignore[arg-type]
            )
    seen = [ids[k] for k in keys if k not in missing]
    for chunk in _chunks(seen):
        s.execute(update(Library).where(Library.id.in_(chunk)).values(last_seen_at=now))
    return ids, len(missing)


def record(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    scan_id: str,
    source: str,
    packages: Iterable[Mapping[str, Any]],
    commit: bool = True,
) -> Recorded:
    """Store one SBOM. Recording the same scan again replaces what it recorded before."""
    rows, libs, skipped = _merge(packages)
    ids, new = _library_ids(s, org_id, libs)
    s.execute(delete(ComponentRow).where(ComponentRow.scan_id == scan_id))
    now = _now()
    values = [
        {
            "id": _uuid(), "org_id": org_id, "library_id": ids[key], "asset_id": asset_id,
            "scan_id": scan_id, "source": source, "current": False, "seen_at": now, **row,
        }
        for (key, _version), row in rows.items()
    ]  # fmt: skip
    for chunk in _chunks(values):
        s.execute(insert(ComponentRow), chunk)
    refresh_current(s, asset_id, source)
    if skipped:
        log.info("inventory: %d SBOM entries skipped for scan %s", skipped, scan_id)
    if commit:
        s.commit()
    return Recorded(components=len(values), new_libraries=new, skipped=skipped)


def refresh_current(s: Session, asset_id: str, source: str) -> str | None:
    """Mark the latest SBOM of (project, source) as current and every other as history, and
    recount the libraries whose use changed. Returns the scan now current, or None when the source
    has no SBOM left (its import was reverted)."""
    latest = s.scalar(
        select(Scan.id)
        .where(
            exists().where(
                ComponentRow.scan_id == Scan.id,
                ComponentRow.asset_id == asset_id,
                ComponentRow.source == source,
            )
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )
    mine = and_(ComponentRow.asset_id == asset_id, ComponentRow.source == source)
    demote = and_(mine, ComponentRow.current.is_(True), ComponentRow.scan_id != (latest or ""))
    promote = and_(mine, ComponentRow.scan_id == (latest or ""), ComponentRow.current.is_(False))
    changed = set(s.scalars(select(ComponentRow.library_id).where(or_(demote, promote)).distinct()))
    s.execute(update(ComponentRow).where(demote).values(current=False))
    if latest is not None:
        s.execute(update(ComponentRow).where(promote).values(current=True))
    recount(s, changed)
    return latest


def recount(s: Session, library_ids: Iterable[str]) -> None:
    """Set each library's project and version counts from its current components."""
    projects = (
        select(func.count(func.distinct(ComponentRow.asset_id)))
        .where(ComponentRow.library_id == Library.id, ComponentRow.current.is_(True))
        .scalar_subquery()
    )
    versions = (
        select(func.count(func.distinct(ComponentRow.version)))
        .where(ComponentRow.library_id == Library.id, ComponentRow.current.is_(True))
        .scalar_subquery()
    )
    for chunk in _chunks(sorted(library_ids)):
        s.execute(
            update(Library)
            .where(Library.id.in_(chunk))
            .values(project_count=projects, version_count=versions)
            .execution_options(synchronize_session=False)
        )


def recount_org(s: Session, org_id: str) -> int:
    """Every library of an organization: what deleting a project (its components go with it)
    leaves stale until then. Hourly, with the backfill."""
    ids = list(s.scalars(select(Library.id).where(Library.org_id == org_id)))
    recount(s, ids)
    s.commit()
    return len(ids)


def forget_scan(s: Session, scan_id: str) -> None:
    """Before a scan is deleted (an import reverted): drop its rows and let the previous SBOM of
    the same source become current again."""
    pairs = s.execute(
        select(ComponentRow.asset_id, ComponentRow.source)
        .where(ComponentRow.scan_id == scan_id)
        .distinct()
    ).all()
    s.execute(delete(ComponentRow).where(ComponentRow.scan_id == scan_id))
    for asset_id, source in pairs:
        refresh_current(s, asset_id, source)


def backfill(s: Session, org_id: str, *, limit: int = 25, budget_seconds: float = 60.0) -> int:
    """Projects scanned with an SBOM before the inventory existed: record each one's latest full
    scan's SBOM. Files imported before then cannot be: their uploads were deleted once applied."""
    started = time.monotonic()
    has_rows = exists().where(ComponentRow.asset_id == Asset.id, ComponentRow.source == SCAN_SOURCE)
    has_sbom = exists().where(
        Scan.asset_id == Asset.id,
        Scan.status == "completed",
        Scan.ref.is_(None),
        Scan.sbom_summary.is_not(None),
    )
    candidates = list(
        s.scalars(
            select(Asset.id).where(Asset.org_id == org_id, ~has_rows, has_sbom).order_by(Asset.id)
        )
    )
    done = 0
    for asset_id in candidates:
        if done >= limit or time.monotonic() - started > budget_seconds:
            break
        scan = s.scalars(
            select(Scan)
            .where(
                Scan.asset_id == asset_id,
                Scan.status == "completed",
                Scan.ref.is_(None),
                Scan.sbom_summary.is_not(None),
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        ).first()
        packages = (scan.sbom_summary or {}).get("packages") if scan is not None else None
        if scan is None or not isinstance(packages, list) or not packages:
            continue
        record(
            s,
            org_id=org_id,
            asset_id=asset_id,
            scan_id=scan.id,
            source=SCAN_SOURCE,
            packages=[p for p in packages if isinstance(p, dict)],
        )
        done += 1
    return done
