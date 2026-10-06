"""Previewing and applying a deduplication change against the database (plan §42.3, ADR-0042).

`preview_change` reads and writes nothing. `apply_change` recomputes the same plan inside one
transaction, refuses it if the project has moved since the preview (the digest), then merges and
splits Issues, records the next version of the setting with what it did, stages an outbox event, and
commits -- all or nothing. The audit-chain entry (`core.audit`) is appended once that has committed.

What is never lost: every occurrence keeps existing (they move between Issues, never disappear);
fix runs and ticket links of an Issue that is merged away move to the survivor; and a merge never
hides an open Issue behind a triaged one -- if the members of a merge disagree about triage, the
merged Issue is reopened for triage (and the change says how many).
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import inspect, select, update
from sqlalchemy.orm import Session

from core.dedup.change import Candidate, DedupPlan, KeyGroup, plan_change
from core.dedup.settings import current_settings, save_setting
from core.dedup.strategies import DEFAULT, source_of, validate
from core.issues import LIVE_STATES
from core.models import finding_from_dict
from core.persistence import repo
from core.persistence.models import (
    Asset,
    ExternalIssueLinkRow,
    FindingRow,
    HypothesisRow,
    IssueRow,
    Scan,
    VerifiedFixRun,
)

log = logging.getLogger(__name__)
_CHUNK = 400
_TRIAGE_COLUMNS = (
    "triage_status",
    "triage_reason",
    "triage_justification",
    "triage_expires_at",
    "triaged_at",
    "triaged_by",
)


class DedupError(Exception):
    """A change that cannot be made; the message says why."""


class StalePlan(DedupError):
    """The project changed since the preview; preview again."""


@dataclass(frozen=True)
class ChangePreview:
    source: str
    from_strategy: str
    from_version: int
    to_strategy: str
    to_version: int
    fields: tuple[str, ...]
    plan: DedupPlan
    examples: tuple[dict[str, Any], ...]
    triage_conflicts: int
    current_keys: dict[str, str]  # each Issue's key now, to tell a re-key from no change

    def to_dict(self) -> dict[str, Any]:
        p = self.plan
        return {
            "source": self.source,
            "from": {"strategy": self.from_strategy, "version": self.from_version},
            "to": {
                "strategy": self.to_strategy,
                "version": self.to_version,
                "fields": list(self.fields),
            },
            "summary": (
                f"Switching {self.source} to {self.to_strategy} would merge "
                f"{p.merged_away + p.merge_groups} issues into {p.merge_groups} and split "
                f"{p.issues_split if p.issues_split else 'none'}"
                + (f" into {p.created_by_split} new" if p.issues_split else "")
            ),
            "issues_before": p.issues_before,
            "issues_after": p.issues_after,
            "merge_groups": p.merge_groups,
            "issues_merged_away": p.merged_away,
            "issues_split": p.issues_split,
            "new_issues_from_split": p.created_by_split,
            "skipped_multi_source": p.skipped_multi_source,
            "triage_conflicts": self.triage_conflicts,
            "conflicts": list(p.conflicts),
            "examples": list(self.examples),
            "digest": p.digest,
            "changes_anything": self.changes_anything,
        }

    @property
    def changes_anything(self) -> bool:
        p = self.plan
        rekeys = any(g.survivor and g.key != self.current_keys.get(g.survivor) for g in p.groups)
        return bool(p.merged_away or p.created_by_split or rekeys)


@dataclass(frozen=True)
class AppliedChange:
    preview: ChangePreview
    version: int
    effect: dict[str, Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _chunks(items: list[Any], size: int = _CHUNK) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _load(
    s: Session, asset_id: str, source: str
) -> tuple[list[Candidate], int, frozenset[str], dict[str, IssueRow]]:
    """The source's Issues, each with its latest occurrences; how many multi-source Issues were left
    out; the keys other Issues hold; and the Issue rows by id."""
    issues = {i.id: i for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id))}
    ids = list(issues)
    # For each Issue, the scan that saw it last.
    seen: dict[str, list[tuple[str, datetime, int, list[str]]]] = defaultdict(list)
    for chunk in _chunks(ids):
        for row in s.execute(
            select(
                FindingRow.issue_id,
                FindingRow.scan_id,
                Scan.created_at,
                FindingRow.pk,
                FindingRow.tools,
            )
            .join(Scan, Scan.id == FindingRow.scan_id)
            .where(FindingRow.issue_id.in_(chunk))
        ):
            seen[row.issue_id].append((row.scan_id, row.created_at, row.pk, list(row.tools or [])))
    latest: dict[str, list[tuple[int, list[str]]]] = {}
    for issue_id, rows in seen.items():
        best = max(rows, key=lambda r: (r[1], r[0]))
        latest[issue_id] = [(r[2], r[3]) for r in rows if r[0] == best[0]]

    ours: list[str] = []
    multi = 0
    for issue_id, occ in latest.items():
        firsts = {t[0] if t else "unknown" for _, t in occ}
        if source not in firsts:
            continue
        if firsts != {source} or any(len(t) > 1 for _, t in occ):
            multi += 1  # another tool also reported it: not this source's alone to re-key
            continue
        ours.append(issue_id)

    data: dict[int, dict[str, Any]] = {}
    pks = [pk for i in ours for pk, _ in latest[i]]
    for chunk in _chunks(pks):
        data.update(
            {
                r.pk: r.data
                for r in s.execute(
                    select(FindingRow.pk, FindingRow.data).where(FindingRow.pk.in_(chunk))
                )
            }
        )
    candidates = [
        Candidate(
            i,
            issues[i].first_seen_at,
            issues[i].fingerprint,
            tuple((pk, finding_from_dict(data[pk])) for pk, _ in sorted(latest[i])),
        )
        for i in sorted(ours)
        if all(source_of(finding_from_dict(data[pk])) == source for pk, _ in latest[i])
    ]
    taken = {c.issue_id for c in candidates}
    held = frozenset(i.fingerprint for k, i in issues.items() if k not in taken)
    return candidates, multi, held, issues


def _own_project(s: Session, org_id: str, asset_id: str) -> None:
    """The project must exist and belong to `org_id` (row-level security already hides another
    org's; this makes the refusal explicit, and covers a database without it)."""
    asset = s.get(Asset, asset_id)
    if asset is None or asset.org_id != org_id:
        raise DedupError("project not found")


def preview_change(
    s: Session, *, org_id: str, asset_id: str, source: str, strategy: str,
    fields: tuple[str, ...] = (),
) -> ChangePreview:  # fmt: skip
    """What a change would do. Reads only."""
    fields = validate(strategy, fields)
    _own_project(s, org_id, asset_id)
    settings = current_settings(s, asset_id)
    now = settings.get(source)
    candidates, multi, held, issues = _load(s, asset_id, source)
    plan = plan_change(
        candidates, strategy, fields, skipped_multi_source=multi, held_elsewhere=held
    )
    by_id = {c.issue_id: c for c in candidates}
    examples = []
    for g in plan.groups:
        if g.merged or g.split_from:
            members = [i for i in (g.survivor, *g.merged) if i]
            examples.append(
                {
                    "kind": "merge" if g.merged else "split",
                    "issues": members or ([g.split_from] if g.split_from else []),
                    "issue_count": len(members) or 1,
                    "titles": list(
                        dict.fromkeys(
                            issues[i].title
                            for i in (members or [g.split_from or ""])
                            if i in issues
                        )
                    )[:5],
                    "occurrences": len(g.rows),
                }
            )
        if len(examples) >= 10:
            break
    conflicts = sum(
        1
        for g in plan.groups
        if _triage_disagrees([issues[i] for i in (g.survivor, *g.merged) if i])
    )
    preview = ChangePreview(
        source, now.strategy if now else DEFAULT, now.version if now else 0, strategy,
        (now.version if now else 0) + 1, fields, plan, tuple(examples), conflicts,
        {i: c.fingerprint for i, c in by_id.items()},
    )  # fmt: skip
    return preview


def _triage_disagrees(members: list[IssueRow]) -> bool:
    return len(members) > 1 and len({m.triage_status for m in members}) > 1


def apply_change(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    source: str,
    strategy: str,
    fields: tuple[str, ...] = (),
    expected_digest: str,
    created_by: str | None = None,
    note: str | None = None,
) -> AppliedChange:
    """Make the change the preview described, or raise (and change nothing)."""
    fields = validate(strategy, fields)
    _own_project(s, org_id, asset_id)
    # Serialise against anything else rewriting this project's Issues (ignored by SQLite).
    list(s.scalars(select(IssueRow.id).where(IssueRow.asset_id == asset_id).with_for_update()))
    preview = preview_change(
        s, org_id=org_id, asset_id=asset_id, source=source, strategy=strategy, fields=fields
    )
    plan = preview.plan
    if plan.digest != expected_digest:
        s.rollback()
        raise StalePlan("the project changed since the preview; preview the change again")
    if plan.conflicts:
        s.rollback()
        raise DedupError(
            f"{len(plan.conflicts)} key(s) are already held by other Issues; not applied"
        )

    candidates, _, _, issues = _load(s, asset_id, source)
    by_id = {c.issue_id: c for c in candidates}
    effect = {"merged_away": 0, "created_by_split": 0, "rekeyed": 0, "triage_reset": 0,
              "occurrences_moved": 0}  # fmt: skip
    for g in plan.groups:
        _apply_group(s, g, issues, by_id, effect)
    s.flush()

    row = save_setting(
        s, org_id=org_id, asset_id=asset_id, source=source, strategy=strategy, fields=fields,
        created_by=created_by, note=note, effect={**effect, "digest": plan.digest},
    )  # fmt: skip
    repo.add_outbox_event(
        s, org_id=org_id, event_type="dedup.changed",
        payload={"asset_id": asset_id, "source": source, "strategy": strategy,
                 "version": row.version, **effect},
    )  # fmt: skip
    s.commit()
    audit_payload = {"strategy": strategy, "fields": list(fields), "version": row.version}
    repo.append_audit_entry(
        s,
        actor=created_by or "system",
        action="dedup.changed",
        target=f"asset:{asset_id}:{source}",
        payload={**audit_payload, "note": note or "", **effect},
    )
    return AppliedChange(preview, row.version, effect)


def _repoint(s: Session, loser: str, survivor: str) -> None:
    """What referred to an Issue that is about to disappear now refers to the survivor."""
    s.execute(
        update(VerifiedFixRun).where(VerifiedFixRun.issue_id == loser).values(issue_id=survivor)
    )
    s.execute(
        update(HypothesisRow)
        .where(HypothesisRow.promoted_issue_id == loser)
        .values(promoted_issue_id=survivor)
    )
    have = {
        p
        for (p,) in s.execute(
            select(ExternalIssueLinkRow.provider).where(ExternalIssueLinkRow.issue_id == survivor)
        )
    }
    for link in s.scalars(
        select(ExternalIssueLinkRow).where(ExternalIssueLinkRow.issue_id == loser)
    ):
        if link.provider in have:
            s.delete(link)  # the survivor already has a ticket on that tracker
        else:
            link.issue_id = survivor


def _apply_group(
    s: Session,
    g: KeyGroup,
    issues: dict[str, IssueRow],
    by_id: dict[str, Candidate],
    effect: dict[str, int],
) -> None:
    rows = list(g.rows)
    if g.survivor is None:
        origin = issues[g.split_from or ""]
        survivor = _clone(origin, g.key)
        s.add(survivor)
        s.flush()
        effect["created_by_split"] += 1
    else:
        survivor = issues[g.survivor]
        members = [survivor, *(issues[m] for m in g.merged)]
        _merge_state(survivor, members, effect)
        for loser in members[1:]:
            _repoint(s, loser.id, survivor.id)
        for loser in members[1:]:
            s.execute(
                update(FindingRow)
                .where(FindingRow.issue_id == loser.id)
                .values(issue_id=survivor.id)
            )
            s.delete(loser)
            effect["merged_away"] += 1
        s.flush()
        if survivor.fingerprint != g.key:
            effect["rekeyed"] += 1
        survivor.fingerprint, survivor.fallback_fingerprint = g.key, None
    for chunk in _chunks(rows):
        res = s.execute(
            update(FindingRow).where(FindingRow.pk.in_(chunk)).values(issue_id=survivor.id)
        )
        effect["occurrences_moved"] += getattr(res, "rowcount", 0) or 0
    s.flush()


def _clone(origin: IssueRow, key: str) -> IssueRow:
    """A new Issue that is `origin` as it is now, under `key` -- what a split produces."""
    skip = {"id", "fingerprint", "fallback_fingerprint"}
    values = {c.key: getattr(origin, c.key) for c in inspect(IssueRow).columns if c.key not in skip}
    return IssueRow(id=str(uuid.uuid4()), fingerprint=key, fallback_fingerprint=None, **values)


def _merge_state(survivor: IssueRow, members: list[IssueRow], effect: dict[str, int]) -> None:
    if len(members) == 1:
        return
    survivor.first_seen_at = min(m.first_seen_at for m in members)
    survivor.last_seen_at = max(m.last_seen_at for m in members)
    if survivor.state not in LIVE_STATES:
        live = next((m for m in members if m.state in LIVE_STATES), None)
        if live is not None:  # one member is still present, so the merged Issue is
            survivor.state, survivor.fixed_at = live.state, None
    if _triage_disagrees(members):
        # Never let a merge hide an open Issue behind a decision made about another one.
        for col in _TRIAGE_COLUMNS:
            setattr(survivor, col, "open" if col == "triage_status" else None)
        effect["triage_reset"] += 1
