"""The audit-log extract in an evidence pack (plan §47): one organization's entries for a period,
with everything around them needed to check them (`core/evidence/verifier.py`).

The audit log is one chain for the whole deployment (ADR-0019). An extract covers every entry from
the first in the period to the later of the last in the period and the first Rekor checkpoint at or
after it, so the period is anchored when a checkpoint exists. Within it, the organization's own
version-2 entries in the period are shown in full (never a payload: the log holds only its digest);
every other entry is shown as its hashes only -- for a version-2 entry that still lets the hash be
recomputed, for a version-1 entry (before migration 0041, organization unknown) only its links.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.persistence.models import AuditCheckpoint, AuditEntry

MAX_ENTRIES = 200_000


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _row(e: AuditEntry, org_id: str, start: datetime, end: datetime) -> dict[str, Any]:
    version = e.version or 1
    ts = e.timestamp if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=timezone.utc)
    if version >= 2 and e.org_id == org_id and start <= ts < end:
        return {"seq": e.seq, "version": version, "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash, "body_digest": e.body_digest, "timestamp": _iso(ts),
                "org_id": e.org_id, "actor": e.actor, "action": e.action, "target": e.target,
                "payload_digest": e.payload_digest}  # fmt: skip
    out: dict[str, Any] = {"seq": e.seq, "version": version, "prev_hash": e.prev_hash,
                           "entry_hash": e.entry_hash, "withheld": True}  # fmt: skip
    if version >= 2:
        out["body_digest"] = e.body_digest
    return out


def extract(s: Session, org_id: str, start: datetime, end: datetime) -> dict[str, Any]:
    """`start` inclusive, `end` exclusive, both UTC."""
    first, last = s.execute(
        select(func.min(AuditEntry.seq), func.max(AuditEntry.seq)).where(
            AuditEntry.timestamp >= start, AuditEntry.timestamp < end
        )
    ).one()
    base: dict[str, Any] = {
        "org_id": org_id, "period": {"start": _iso(start), "end": _iso(end)},
        "entries": [], "checkpoints": [], "truncated": False,
    }  # fmt: skip
    if first is None:
        return base
    anchor = s.scalar(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.seq_end >= last)
        .order_by(AuditCheckpoint.seq_end)
        .limit(1)
    )
    upto = max(last, anchor.seq_end) if anchor is not None else last
    if upto - first + 1 > MAX_ENTRIES:
        upto, base["truncated"] = first + MAX_ENTRIES - 1, True
    rows = s.scalars(
        select(AuditEntry)
        .where(AuditEntry.seq >= first, AuditEntry.seq <= upto)
        .order_by(AuditEntry.seq)
    )
    base["entries"] = [_row(e, org_id, start, end) for e in rows]
    base["checkpoints"] = [
        {"seq_end": cp.seq_end, "chain_hash": cp.chain_hash,
         "rekor_log_index": cp.rekor_log_index, "created_at": _iso(cp.created_at),
         "bundle": cp.signature_bundle}  # fmt: skip
        for cp in s.scalars(
            select(AuditCheckpoint)
            .where(AuditCheckpoint.seq_end >= first, AuditCheckpoint.seq_end <= upto)
            .order_by(AuditCheckpoint.seq_end)
        )
    ]
    return base
