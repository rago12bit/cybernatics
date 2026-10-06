"""Tamper-evident audit log (Week 30 backfill, ADR-0019, plan §19.3): pure hash-chain logic, no DB
access here (mirrors `core/issues.py`'s split — see `core/persistence/repo.py` for storage,
`core/audit_rekor.py` for publishing a checkpoint of this chain to Sigstore's Rekor).

    entry_hash = SHA256(seq || prev_hash || timestamp || actor || action || target
                         || payload_digest)

Entries store a digest of the payload, never the payload itself: deleting the underlying record
later (a revoked token, a removed installation) must never break the chain, since the chain never
depended on that data still existing.

Version 2 (Week 69, plan §47) puts the entry's organization in the hash and splits it in two:

    body_digest = SHA256(canonical JSON of timestamp, org_id, actor, action, target, payload_digest)
    entry_hash  = SHA256("2" || seq || prev_hash || body_digest)

so an extract for one organization can show its own entries in full and every other entry as
(seq, prev_hash, body_digest, entry_hash) only -- revealing nothing about it, yet letting an auditor
recompute every link. Version 1 entries (everything before migration 0041) keep their hash; in an
extract they can only be shown in full or as an unverifiable link.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

GENESIS_HASH = "0" * 64


def payload_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_hash(
    *,
    seq: int,
    prev_hash: str,
    timestamp: datetime,
    actor: str,
    action: str,
    target: str,
    payload_digest: str,
) -> str:
    # SQLite (tests) hands back a naive datetime even for a `DateTime(timezone=True)` column;
    # `.astimezone()` on a naive value assumes the LOCAL zone, which would shift it and produce a
    # different hash than the one computed at write time from a genuinely UTC-aware value on
    # anything but a UTC host. Every timestamp this codebase writes is already UTC
    # (`core.persistence.models._now`), so a naive value is always meant as UTC, never local.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    ts = timestamp.astimezone(timezone.utc).isoformat()
    material = "|".join([str(seq), prev_hash, ts, actor, action, target, payload_digest])
    return hashlib.sha256(material.encode()).hexdigest()


def _utc_iso(timestamp: datetime) -> str:
    if timestamp.tzinfo is None:  # see compute_hash: a naive value from SQLite is UTC
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat()


def body_digest(
    *,
    timestamp: datetime | str,
    org_id: str | None,
    actor: str,
    action: str,
    target: str,
    payload_digest: str,
) -> str:
    """A version-2 entry's body. `timestamp` may be given already formatted (an extract's)."""
    ts = timestamp if isinstance(timestamp, str) else _utc_iso(timestamp)
    body = {"timestamp": ts, "org_id": org_id, "actor": actor, "action": action,
            "target": target, "payload_digest": payload_digest}  # fmt: skip
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_hash_v2(*, seq: int, prev_hash: str, body_digest: str) -> str:
    return hashlib.sha256(f"2|{seq}|{prev_hash}|{body_digest}".encode()).hexdigest()


class _EntryLike(Protocol):
    seq: int
    prev_hash: str
    entry_hash: str
    timestamp: datetime
    actor: str
    action: str
    target: str
    payload_digest: str


def recompute(e: _EntryLike) -> str:
    """The hash an entry's stored fields give, by its version (`version`, `org_id` and
    `body_digest` are read when present: an object without them is a version-1 entry)."""
    if (getattr(e, "version", None) or 1) >= 2:
        body = body_digest(
            timestamp=e.timestamp, org_id=getattr(e, "org_id", None), actor=e.actor,
            action=e.action, target=e.target, payload_digest=e.payload_digest,
        )  # fmt: skip
        stored = getattr(e, "body_digest", None)
        if stored is not None and stored != body:
            return ""  # the stored body digest disagrees with the fields: never a match
        return compute_hash_v2(seq=e.seq, prev_hash=e.prev_hash, body_digest=body)
    return compute_hash(
        seq=e.seq, prev_hash=e.prev_hash, timestamp=e.timestamp, actor=e.actor,
        action=e.action, target=e.target, payload_digest=e.payload_digest,
    )  # fmt: skip


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    broken_at_seq: int | None
    reason: str | None


def verify_chain(entries: list[_EntryLike]) -> VerifyResult:
    """`entries` must already be ordered by `seq` ascending. Recomputes every hash from the stored
    fields and checks it against what's stored, and checks each `prev_hash` against the previous
    entry's actual `entry_hash` -- not against the previous entry's *own* `prev_hash` field, which
    an attacker could edit to agree with a forged `entry_hash` on the same row."""
    prev = GENESIS_HASH
    for i, e in enumerate(entries):
        if e.prev_hash != prev:
            return VerifyResult(False, i, e.seq, f"prev_hash mismatch at seq {e.seq}")
        if recompute(e) != e.entry_hash:
            return VerifyResult(False, i, e.seq, f"entry_hash mismatch at seq {e.seq}")
        prev = e.entry_hash
    return VerifyResult(True, len(entries), None, None)
