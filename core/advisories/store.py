"""Keeping the advisory tables (plan §46.2): OSV records, CISA KEV, NVD's CVEs.

`upsert` takes parsed OSV records and writes only those that are new or whose `modified` moved,
replacing the packages they affect; it returns what changed, so matching re-runs only for those
(`core.advisories.impact.match`). Everything here is public data shared by every organization.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from core.advisories.osv import Advisory
from core.persistence.models import Advisory as AdvisoryRow
from core.persistence.models import AdvisoryPackage, CveRecord, FeedState, KevEntry

_CHUNK = 500


@dataclass
class Upserted:
    seen: int = 0
    changed: set[str] = field(default_factory=set)  # advisory ids written
    vuln_keys: set[str] = field(default_factory=set)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _chunks(items: Iterable[Any], n: int = _CHUNK) -> Iterator[list[Any]]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch


def upsert(s: Session, advisories: Iterable[Advisory], *, source: str) -> Upserted:
    """Write new and changed records, in batches; commits each batch."""
    out = Upserted()
    for batch in _chunks(advisories):
        out.seen += len(batch)
        q = select(AdvisoryRow.id, AdvisoryRow.modified).where(
            AdvisoryRow.id.in_([a.id for a in batch])
        )
        known: dict[str, datetime] = {aid: modified for aid, modified in s.execute(q)}
        fresh = [a for a in batch if a.id not in known or _aware(known[a.id]) != a.modified]
        if not fresh:
            continue
        ids = [a.id for a in fresh]
        s.execute(delete(AdvisoryPackage).where(AdvisoryPackage.advisory_id.in_(ids)))
        s.execute(delete(AdvisoryRow).where(AdvisoryRow.id.in_(ids)))
        now = _now()
        s.execute(
            insert(AdvisoryRow),
            [
                {
                    "id": a.id, "vuln_key": a.vuln_key, "modified": a.modified,
                    "published": a.published, "withdrawn": a.withdrawn,
                    "aliases": list(a.aliases), "summary": a.summary, "details": a.details,
                    "cvss": a.cvss, "cvss_vector": a.cvss_vector[:200],
                    "db_severity": a.db_severity, "cwe": list(a.cwe),
                    "references": list(a.references), "source": source, "fetched_at": now,
                }
                for a in fresh
            ],
        )  # fmt: skip
        packages = [
            {"advisory_id": a.id, "ecosystem": af.ecosystem, "name": af.name,
             "lib_key": af.library_key[:340], "data": af.to_dict()}
            for a in fresh for af in a.affected
        ]  # fmt: skip
        for chunk in _chunks(packages):
            s.execute(insert(AdvisoryPackage), chunk)
        s.commit()
        out.changed.update(ids)
        out.vuln_keys.update(a.vuln_key for a in fresh)
    return out


def load_kev(s: Session, raw: bytes) -> int:
    """Replace the KEV table with CISA's catalog. Raises ValueError for anything that is not it
    (a truncated or substituted download must not empty the table)."""
    doc = json.loads(raw)
    rows = {}
    for v in doc["vulnerabilities"]:
        cve = str(v.get("cveID", ""))
        if not cve.startswith("CVE-") or len(cve) > 32:
            continue
        rows[cve] = {
            "cve": cve, "date_added": str(v.get("dateAdded", ""))[:10],
            "due_date": str(v.get("dueDate", ""))[:10],
            "name": str(v.get("vulnerabilityName", ""))[:300],
            "ransomware": str(v.get("knownRansomwareCampaignUse", ""))[:16],
        }  # fmt: skip
    if len(rows) < 100:
        raise ValueError(f"only {len(rows)} KEV entries; not replacing the catalog")
    s.execute(delete(KevEntry))
    for chunk in _chunks(rows.values()):
        s.execute(insert(KevEntry), chunk)
    s.commit()
    return len(rows)


def upsert_cves(s: Session, records: list[dict[str, Any]]) -> int:
    """CVE records in NVD API 2.0's shape (`vulnerabilities[].cve`)."""
    n = 0
    for batch in _chunks(records):
        rows = {}
        for item in batch:
            cve = item.get("cve") or {}
            cid = str(cve.get("id", ""))
            if not cid.startswith("CVE-") or len(cid) > 32:
                continue
            score, vector = None, ""
            metrics = cve.get("metrics") or {}
            for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                for m in metrics.get(name) or []:
                    data = m.get("cvssData") or {}
                    if m.get("type") == "Primary" or score is None:
                        score, vector = data.get("baseScore"), str(data.get("vectorString", ""))
                if score is not None:
                    break
            desc = next(
                (
                    d.get("value", "")
                    for d in cve.get("descriptions") or []
                    if d.get("lang") == "en"
                ),
                "",
            )
            rows[cid] = {
                "id": cid, "published": _parse(cve.get("published")),
                "last_modified": _parse(cve.get("lastModified")),
                "cvss": float(score) if isinstance(score, (int, float)) else None,
                "cvss_vector": vector[:200], "description": str(desc)[:4000],
                "fetched_at": _now(),
            }  # fmt: skip
        if not rows:
            continue
        s.execute(delete(CveRecord).where(CveRecord.id.in_(list(rows))))
        s.execute(insert(CveRecord), list(rows.values()))
        s.commit()
        n += len(rows)
    return n


def _parse(v: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(v)[:19])
    except (TypeError, ValueError):
        return None
    return dt.replace(tzinfo=timezone.utc)


def feed(s: Session, source: str) -> FeedState:
    row = s.get(FeedState, source)
    if row is None:
        row = FeedState(source=source, cursor="", records=0)
        s.add(row)
        s.flush()
    return row


def record_run(
    s: Session, source: str, *, ok: bool, records: int = 0, cursor: str | None = None,
    error: str | None = None,
) -> None:  # fmt: skip
    row = feed(s, source)
    now = _now()
    row.last_run_at = now
    if ok:
        row.last_success_at, row.last_error = now, None
        row.records = records
        if cursor is not None:
            row.cursor = cursor[:200]
    else:
        row.last_error = (error or "failed")[:2000]
    s.commit()
