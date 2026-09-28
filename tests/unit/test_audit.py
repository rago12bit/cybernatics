from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from core.audit import GENESIS_HASH, compute_hash, payload_digest, verify_chain


@dataclass
class _Entry:
    seq: int
    prev_hash: str
    entry_hash: str
    timestamp: datetime
    actor: str
    action: str
    target: str
    payload_digest: str


def _now() -> datetime:
    return datetime(2026, 9, 28, tzinfo=timezone.utc)


def _chain(n: int) -> list[_Entry]:
    entries: list[_Entry] = []
    prev = GENESIS_HASH
    for i in range(1, n + 1):
        pd = payload_digest({"i": i})
        h = compute_hash(
            seq=i, prev_hash=prev, timestamp=_now(), actor="test", action="t.did", target=str(i),
            payload_digest=pd,
        )  # fmt: skip
        entries.append(_Entry(i, prev, h, _now(), "test", "t.did", str(i), pd))
        prev = h
    return entries


def test_payload_digest_ignores_key_order_but_not_content() -> None:
    assert payload_digest({"a": 1, "b": 2}) == payload_digest({"b": 2, "a": 1})
    assert payload_digest({"a": 1}) != payload_digest({"a": 2})


def test_compute_hash_is_deterministic_and_sensitive_to_every_field() -> None:
    kwargs = dict(seq=1, prev_hash=GENESIS_HASH, timestamp=_now(), actor="a", action="b",
                  target="c", payload_digest="d" * 64)  # fmt: skip
    h = compute_hash(**kwargs)  # type: ignore[arg-type]
    assert compute_hash(**kwargs) == h  # type: ignore[arg-type]
    for field, other in [("seq", 2), ("actor", "z"), ("action", "z"), ("target", "z")]:
        mutated = {**kwargs, field: other}
        assert compute_hash(**mutated) != h  # type: ignore[arg-type]


def test_a_real_chain_verifies() -> None:
    result = verify_chain(_chain(20))
    assert result.ok and result.checked == 20 and result.broken_at_seq is None


def test_an_empty_chain_verifies_trivially() -> None:
    result = verify_chain([])
    assert result.ok and result.checked == 0


def test_editing_any_stored_field_breaks_verification_at_that_entry() -> None:
    entries = _chain(5)
    entries[2].action = "tampered"  # seq 3, but entry_hash still claims the old action
    result = verify_chain(entries)
    assert result.ok is False and result.broken_at_seq == 3


def test_deleting_an_entry_breaks_the_next_ones_prev_hash_link() -> None:
    entries = _chain(5)
    del entries[2]  # remove seq 3; seq 4's prev_hash now points at a hash not in the list
    result = verify_chain(entries)
    assert result.ok is False and result.broken_at_seq == entries[2].seq  # this is now old seq 4


def test_reordering_entries_is_also_caught() -> None:
    entries = _chain(4)
    entries[1], entries[2] = entries[2], entries[1]
    result = verify_chain(entries)
    assert result.ok is False


def test_forging_an_entry_hash_without_recomputing_it_is_still_caught() -> None:
    """An attacker who edits `action` and *also* edits `entry_hash` to something self-consistent
    with the tampered fields still can't make the NEXT entry's `prev_hash` agree, unless they also
    re-chain everything after -- which is exactly what a checkpoint published to Rekor prevents from
    going unnoticed."""
    entries = _chain(5)
    entries[2].action = "tampered"
    entries[2].entry_hash = compute_hash(
        seq=entries[2].seq, prev_hash=entries[2].prev_hash, timestamp=entries[2].timestamp,
        actor=entries[2].actor, action="tampered", target=entries[2].target,
        payload_digest=entries[2].payload_digest,
    )  # fmt: skip
    result = verify_chain(entries)
    assert result.ok is False  # seq 4's prev_hash no longer matches the forged seq 3's new hash
    assert result.broken_at_seq == entries[3].seq
