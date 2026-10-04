"""The dry run of a deduplication change (plan §42.3): "switching Nessus to `tool_id` would merge
212 issues into 97 and split none." Nothing changes until someone confirms.

Pure -- no database. The service (`core.dedup.service`) loads each Issue's most recent occurrences,
this module decides what the new strategy would make of them, and the same decision is what a
confirmation then applies, so the preview cannot differ from the result (the plan carries a digest
the confirmation must match).

What a change does, precisely. Each Issue of the source is judged by its *latest occurrences* (the
findings of the last scan that saw it): older history stays attached to the Issue it was recorded
against. Under the new strategy those occurrences get keys.

* All one key: the Issue keeps its identity and takes the new key.
* Several keys: the Issue is **split**. It keeps the key most of its occurrences have (ties: the
  smaller key) and every other key becomes an Issue of its own, a copy of this one at the time.
* Several Issues with one key: they are **merged**. The oldest survives; the others' occurrences
  move to it and they disappear.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from core.dedup.strategies import key_for
from core.models import Finding


@dataclass(frozen=True)
class Candidate:
    """An Issue of the source and its latest occurrences: (finding row id, the Finding)."""

    issue_id: str
    first_seen: datetime
    fingerprint: str  # the key it has now
    occurrences: tuple[tuple[int, Finding], ...]


@dataclass(frozen=True)
class KeyGroup:
    key: str
    survivor: str | None  # the existing Issue that takes this key; None: a new Issue is created
    merged: tuple[str, ...]  # Issues folded into the survivor (their occurrences move; they go)
    split_from: str | None  # for a new Issue: the Issue it is split off from
    rows: tuple[int, ...]  # the occurrences (finding row ids) that end up under this key


@dataclass(frozen=True)
class DedupPlan:
    groups: tuple[KeyGroup, ...]
    issues_before: int
    skipped_multi_source: int = 0
    conflicts: tuple[str, ...] = field(default_factory=tuple)  # keys another Issue already holds

    @property
    def issues_after(self) -> int:
        return len(self.groups)

    @property
    def merged_away(self) -> int:
        return sum(len(g.merged) for g in self.groups)

    @property
    def merge_groups(self) -> int:
        return sum(1 for g in self.groups if g.merged)

    @property
    def created_by_split(self) -> int:
        return sum(1 for g in self.groups if g.survivor is None)

    @property
    def issues_split(self) -> int:
        return len({g.split_from for g in self.groups if g.split_from})

    @property
    def digest(self) -> str:
        """Identifies exactly what applying this plan would do, so a confirmation can refuse a plan
        the project has moved away from since it was previewed."""
        raw = json.dumps(
            [
                [g.key, g.survivor, sorted(g.merged), g.split_from, sorted(g.rows)]
                for g in sorted(self.groups, key=lambda g: g.key)
            ]
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


def plan_change(
    candidates: list[Candidate],
    strategy: str,
    fields: tuple[str, ...] = (),
    *,
    skipped_multi_source: int = 0,
    held_elsewhere: frozenset[str] = frozenset(),
) -> DedupPlan:
    """What `strategy` would make of `candidates`. `held_elsewhere` is the keys that Issues outside
    the change already hold; a plan that would take one of them is reported as a conflict, not made.
    """
    parts: dict[str, dict[str, list[int]]] = {}
    for c in candidates:
        by_key: dict[str, list[int]] = defaultdict(list)
        for row, finding in c.occurrences:
            by_key[key_for(strategy, finding, fields)].append(row)
        parts[c.issue_id] = by_key

    # An Issue's home is the key most of its occurrences have (ties: the smaller key).
    home = {
        c.issue_id: min(parts[c.issue_id], key=lambda k: (-len(parts[c.issue_id][k]), k))
        for c in candidates
        if parts[c.issue_id]
    }
    by_id = {c.issue_id: c for c in candidates}
    homes: dict[str, list[str]] = defaultdict(list)
    for issue_id, key in home.items():
        homes[key].append(issue_id)
    others: dict[str, list[tuple[str, list[int]]]] = defaultdict(list)
    for issue_id, by_key in parts.items():
        for key, rows in by_key.items():
            if key != home.get(issue_id):
                others[key].append((issue_id, rows))

    groups: list[KeyGroup] = []
    conflicts: list[str] = []
    for key in sorted(set(homes) | set(others)):
        owners = sorted(homes.get(key, []), key=lambda i: (by_id[i].first_seen, i))
        rows = [r for i in owners for r in parts[i][key]]
        rows += [r for _, rs in others.get(key, []) for r in rs]
        survivor = owners[0] if owners else None
        merged = tuple(owners[1:])
        split_from = None
        if survivor is None:
            # Split off an Issue that has other keys too: the first (by id) of the contributors.
            split_from = min(i for i, _ in others[key])
        if key in held_elsewhere:
            conflicts.append(key)
            continue
        groups.append(KeyGroup(key, survivor, merged, split_from, tuple(sorted(rows))))
    return DedupPlan(tuple(groups), len(candidates), skipped_multi_source, tuple(conflicts))
