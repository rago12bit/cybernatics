"""One-time backfill: create Assets and Issues for scans that ran before ADR-0012 (Week 28).

The schema migration (migrations/versions/0004_issues_assets.py) only creates the new tables and
columns; it leaves existing scans' `asset_id` and existing findings' `issue_id`/`issue_state` as
NULL, because turning stored JSON back into a lifecycle history is application logic, not schema,
and doesn't belong baked into an Alembic migration that has to keep working as that logic evolves.
Run this once after upgrading to pick them up:

    python -m scripts.backfill-issues            # report what it would do
    python -m scripts.backfill-issues --apply    # actually write

Findings are replayed through the exact same `core.issues.sync` used by every live scan, one asset
at a time, oldest scan first, so the result is what would have happened if Issue tracking had
existed from day one. Scans are only replayed if they finished as "completed" — the same rule
`core/pipeline.py` applies live, since a partial or failed scan can't tell "not seen" from "not
looked for".
"""

from __future__ import annotations

import argparse
import sys
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.assets import asset_key
from core.config import Settings
from core.issues import ExistingIssue, fallback_key
from core.issues import sync as sync_issues
from core.models import finding_from_dict
from core.persistence.db import make_engine
from core.persistence.models import Asset, FindingRow, IssueRow, Scan


@dataclass
class _Tracked:
    """In-memory lifecycle state for one issue, kept regardless of --apply so a dry run reports
    what *would* happen across an asset's whole scan history, not just its first scan. Only turned
    into a real `IssueRow` (and written) when --apply is passed; see `_persist`."""

    id: str
    category: str
    fingerprint: str
    fallback_fingerprint: str | None
    state: str
    severity: str
    path: str
    title: str
    first_seen_at: datetime
    last_seen_at: datetime
    fixed_at: datetime | None = None


def _persist(
    s: Session, asset_id: str, tracked: dict[str, _Tracked], orm_by_id: dict[str, IssueRow]
) -> None:
    """Write the current in-memory state to the session. `orm_by_id` remembers which issues have
    already been added this run, so a later scan updates the same ORM object rather than adding a
    second row for an id already pending in this transaction."""
    for issue_id, t in tracked.items():
        row = orm_by_id.get(issue_id)
        if row is None:
            row = IssueRow(
                id=t.id, asset_id=asset_id, fingerprint=t.fingerprint,
                fallback_fingerprint=t.fallback_fingerprint, state=t.state, category=t.category,
                severity=t.severity, path=t.path, title=t.title, first_seen_at=t.first_seen_at,
                last_seen_at=t.last_seen_at, fixed_at=t.fixed_at,
            )  # fmt: skip
            s.add(row)
            orm_by_id[issue_id] = row
        else:
            row.fingerprint = t.fingerprint
            row.fallback_fingerprint = t.fallback_fingerprint
            row.state = t.state
            row.severity, row.path, row.title = t.severity, t.path, t.title
            row.last_seen_at = t.last_seen_at
            row.fixed_at = t.fixed_at


def backfill(s: Session, *, apply: bool) -> None:
    scans = list(
        s.scalars(
            select(Scan)
            .where(Scan.asset_id.is_(None), Scan.status == "completed")
            .order_by(Scan.created_at)
        )
    )
    if not scans:
        print("nothing to backfill: every completed scan already has an asset")
        return

    by_asset: dict[tuple[str, str], list[Scan]] = defaultdict(list)
    for sc in scans:
        by_asset[(sc.source_type, asset_key(sc.source_type, sc.source_label))].append(sc)

    total_assets = total_issues = total_occurrences = 0
    for (source_type, key), asset_scans in by_asset.items():
        label = asset_scans[-1].source_label  # most recent label, matching create_scan's behaviour
        asset = s.scalars(
            select(Asset).where(Asset.source_type == source_type, Asset.key == key)
        ).one_or_none()
        if asset is None:
            asset = Asset(source_type=source_type, key=key, label=label)
            if apply:
                s.add(asset)
                s.flush()  # need asset.id before it's referenced below
            total_assets += 1
        # Tracked in memory across this asset's whole scan history regardless of --apply, so a dry
        # run's per-scan report reflects state carried from earlier scans of the SAME asset, not
        # just what's already committed to the database.
        tracked: dict[str, _Tracked] = {}
        if apply and asset.id:
            for r in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset.id)):
                tracked[r.id] = _Tracked(
                    r.id,
                    r.category,
                    r.fingerprint,
                    r.fallback_fingerprint,
                    r.state,
                    r.severity,
                    r.path,
                    r.title,
                    r.first_seen_at,
                    r.last_seen_at,
                    r.fixed_at,
                )
        orm_by_id: dict[str, IssueRow] = {}

        for sc in asset_scans:
            rows = list(s.scalars(select(FindingRow).where(FindingRow.scan_id == sc.id)))
            findings = [finding_from_dict(r.data) for r in rows]
            existing = [
                ExistingIssue(t.id, t.category, t.fingerprint, t.fallback_fingerprint, t.state)  # type: ignore[arg-type]  # noqa: E501
                for t in tracked.values()
            ]
            result = sync_issues(findings, existing, new_issue_id=lambda: str(uuid.uuid4()))
            total_occurrences += len(result.updates)
            total_issues += result.new_count
            print(
                f"  {sc.created_at:%Y-%m-%d} {sc.id[:8]} ({label}): "
                f"{result.new_count} new, {result.reintroduced_count} reintroduced, "
                f"{result.fixed_count} fixed"
            )
            for f, u in zip(findings, result.updates, strict=True):
                t = tracked.get(u.issue_id)
                if t is None:
                    t = _Tracked(
                        u.issue_id, f.taxonomy.category.value, u.fingerprint, fallback_key(f),
                        u.state, f.scoring.normalized_severity.value, f.location.path, f.title,
                        sc.created_at, sc.created_at,
                    )  # fmt: skip
                    tracked[u.issue_id] = t
                else:
                    t.fingerprint, t.state = u.fingerprint, u.state
                    t.severity = f.scoring.normalized_severity.value
                    t.path, t.title = f.location.path, f.title
                    t.last_seen_at, t.fixed_at = sc.created_at, None
                    t.fallback_fingerprint = fallback_key(f)
            for issue_id in result.fixed_issue_ids:
                tracked[issue_id].state = "fixed"
                tracked[issue_id].fixed_at = sc.finished_at or sc.created_at

            if not apply:
                continue
            sc.asset_id = asset.id
            # Flush the issue rows before pointing any finding at them: FindingRow and IssueRow
            # have no ORM `relationship()` between them (only a raw FK column), so the unit of work
            # has no dependency to sort by and won't otherwise order the INSERT before the UPDATE.
            _persist(s, asset.id, tracked, orm_by_id)
            s.flush()
            row_by_finding = {r.finding_id: r for r in rows}
            for f, u in zip(findings, result.updates, strict=True):
                row = row_by_finding.get(f.id)
                if row is not None:
                    row.issue_id, row.issue_state = u.issue_id, u.state
            s.flush()
        if apply:
            s.commit()

    verb = "Backfilled" if apply else "Would backfill"
    print(
        f"{verb}: {total_assets} assets, {total_issues} issues, "
        f"{total_occurrences} occurrences, across {len(scans)} scans."
    )
    if not apply:
        print("Re-run with --apply to write this.")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = ap.parse_args()
    engine = make_engine(Settings.from_env().database_url)
    with Session(engine) as s:
        backfill(s, apply=args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
