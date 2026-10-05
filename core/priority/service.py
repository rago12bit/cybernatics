"""Priority policies, each Issue's priority, recomputation and the preview (plan §44.3, Week 63).

Each Issue stores its priority (score, band, and the factors with their weights) so the issues table
can sort and filter by it in SQL and an SLA can key on its band. It is written:

- at ingest -- every scan, import, DAST campaign and manual finding (`repo.add_findings`), from the
  occurrence just stored and the project's newest policy;
- when an Issue is confirmed at runtime or gets a triage-assistant verdict (both are factors);
- by a recomputation of the whole project after a policy is saved, in the background.

With no saved policy, priority is the v2 risk score exactly as stored on the occurrence (version 0),
so nothing a project sees changes until someone saves weights.

The lock: a policy version records its own recomputation (pending, running, done, failed,
superseded). While the newest version's is pending or running, saving another is refused --
unless it has made no progress for `STALE_AFTER` (a worker that died), in which case the save
takes over and the abandoned job stops at its next batch. Two saves that both pass the check still
cannot both land: (asset, version) is unique, so the second insert fails and is refused too.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import FindingRow, IssueRow, PriorityPolicy, Scan
from core.priority.engine import (
    STARTER,
    Context,
    Signals,
    band_of,
    parse_context,
    parse_weights,
    score,
)
from core.sla.policy import OPEN_STATES

log = logging.getLogger(__name__)

STALE_AFTER = timedelta(minutes=10)
BATCH = 500
PREVIEW_TOP = 50
RUNNING = ("pending", "running")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class PolicyLocked(Exception):
    """A recomputation is still running for this project's newest policy."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- policies -------------------------------------------------------------------------------------


def current(s: Session, asset_id: str) -> PriorityPolicy | None:
    return s.scalars(
        select(PriorityPolicy)
        .where(PriorityPolicy.asset_id == asset_id)
        .order_by(PriorityPolicy.version.desc())
        .limit(1)
    ).first()


def history(s: Session, asset_id: str, limit: int = 50) -> list[PriorityPolicy]:
    return list(
        s.scalars(
            select(PriorityPolicy)
            .where(PriorityPolicy.asset_id == asset_id)
            .order_by(PriorityPolicy.version.desc())
            .limit(limit)
        )
    )


@dataclass(frozen=True)
class Rules:
    """What ranks a project's Issues: a saved policy's weights and context, or none (v2)."""

    version: int
    weights: dict[str, float] | None  # None: no policy; priority is the stored v2 score
    context: Context

    @classmethod
    def of(cls, row: PriorityPolicy | None) -> Rules:
        if row is None:
            return cls(0, None, Context())
        return cls(row.version, parse_weights(row.weights), parse_context(row.context))


def rules_for(s: Session, asset_id: str) -> Rules:
    return Rules.of(current(s, asset_id))


def locked(row: PriorityPolicy | None, now: datetime | None = None) -> bool:
    if row is None or row.status not in RUNNING:
        return False
    last = _aware(row.heartbeat_at or row.started_at or row.created_at)
    return bool(last is not None and last > (now or _now()) - STALE_AFTER)


def save(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    weights: Any,
    context: Any,
    note: str | None = None,
    actor: str,
    now: datetime | None = None,
) -> PriorityPolicy:
    """A new version, pending its recomputation (the caller queues it). Audit-logged."""
    now = now or _now()
    parsed_w, parsed_c = parse_weights(weights), parse_context(context)
    prev = current(s, asset_id)
    if locked(prev, now):
        raise PolicyLocked("the previous change is still being applied to every issue")
    if prev is not None and prev.status in RUNNING:  # stale: its worker died; take over
        prev.status, prev.finished_at = "failed", now
        prev.error = f"abandoned: no progress for {int(STALE_AFTER.total_seconds() // 60)} minutes"
    row = PriorityPolicy(
        org_id=org_id,
        asset_id=asset_id,
        version=(prev.version + 1) if prev else 1,
        weights=parsed_w,
        context=parsed_c.to_dict(),
        note=" ".join(note.split())[:500] if note else None,
        created_by=actor,
        created_at=now,
        status="pending",
    )
    s.add(row)
    try:
        s.flush()
    except IntegrityError as exc:  # another save took this version number first
        s.rollback()
        raise PolicyLocked("someone else changed the priority policy at the same moment") from exc
    repo.add_outbox_event(
        s,
        org_id=org_id,
        event_type="priority.policy_changed",
        payload={"asset_id": asset_id, "version": row.version},
    )
    repo.append_audit_entry(  # commits, with the policy row
        s,
        actor=actor,
        action="priority.policy.changed",
        target=f"asset:{asset_id}",
        payload={
            "org_id": org_id,
            "version": row.version,
            "weights": row.weights,
            "context": row.context,
        },
    )
    return row


# --- one Issue's priority -------------------------------------------------------------------------


def signals(data: dict[str, Any], issue: IssueRow) -> Signals:
    return Signals.from_finding(
        data,
        runtime=issue.confirmed_at_runtime_at is not None,
        verdict=issue.assistant_verdict,
        verdict_confidence=issue.assistant_verdict_confidence,
    )


def evaluate(rules: Rules, data: dict[str, Any], issue: IssueRow) -> dict[str, Any]:
    """{score, band, factors, version} for one Issue from its latest occurrence."""
    if rules.weights is None:
        sc = data.get("scoring") or {}
        v2 = sc.get("risk_score")
        return {
            "score": v2,
            "band": band_of(v2),
            "factors": [{"text": t} for t in sc.get("risk_factors") or ()],
            "version": 0,
        }
    p = score(signals(data, issue), rules.weights, rules.context)
    return {**p.to_dict(), "version": rules.version}


def apply(issue: IssueRow, result: dict[str, Any]) -> bool:
    """Store a result on the Issue; True when its band changed."""
    moved = bool(issue.priority_band != result["band"])
    issue.priority_score = result["score"]
    issue.priority_band = result["band"]
    issue.priority_factors = result["factors"]
    issue.priority_version = result["version"]
    return moved


def view(issue: IssueRow | None) -> dict[str, Any] | None:
    if issue is None or issue.priority_version is None:
        return None
    return {
        "score": issue.priority_score,
        "band": issue.priority_band,
        "version": issue.priority_version,
        "factors": issue.priority_factors or [],
    }


def latest_occurrences(s: Session, issue_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Each Issue's most recent stored Finding (a native scan or an import, whichever is newer)."""
    ids = list(issue_ids)
    out: dict[str, dict[str, Any]] = {}
    if not ids:
        return out
    rows = s.execute(
        select(FindingRow.issue_id, FindingRow.data)
        .join(Scan, Scan.id == FindingRow.scan_id)
        .where(FindingRow.issue_id.in_(ids))
        .order_by(Scan.created_at.desc(), FindingRow.pk.desc())
    )
    for issue_id, data in rows:
        if issue_id is not None and issue_id not in out:
            out[issue_id] = data
    return out


def refresh_ingested(s: Session, asset_id: str, pairs: list[tuple[str, dict[str, Any]]]) -> None:
    """At ingest, before the caller commits: rank each Issue from the occurrence just stored."""
    if not pairs:
        return
    rules = rules_for(s, asset_id)
    latest = dict(pairs)  # one Issue reported twice in one batch: the last occurrence wins
    for issue in s.scalars(select(IssueRow).where(IssueRow.id.in_(list(latest)))):
        apply(issue, evaluate(rules, latest[issue.id], issue))


def rescore(s: Session, issue: IssueRow) -> None:
    """After something about the Issue itself changed (runtime confirmation, assistant verdict).
    The caller commits."""
    data = latest_occurrences(s, [issue.id]).get(issue.id)
    if data is not None:
        apply(issue, evaluate(rules_for(s, issue.asset_id), data, issue))


# --- recomputation --------------------------------------------------------------------------------


def recompute(s: Session, policy_id: str, *, batch: int = BATCH) -> PriorityPolicy | None:
    """Re-rank every Issue of the policy's project, a batch per commit, recording progress on the
    policy row (which is also the lock). Stops if the policy is no longer the newest (a stale lock
    was taken over). Idempotent: a redelivered job for a finished policy does nothing."""
    row = s.get(PriorityPolicy, policy_id)
    if row is None or row.status not in RUNNING:
        return row
    newest = current(s, row.asset_id)
    if newest is not None and newest.id != row.id:
        row.status, row.finished_at = "superseded", _now()
        s.commit()
        return row
    rules = Rules.of(row)
    row.status, row.processed, row.changed = "running", 0, 0
    row.started_at = row.heartbeat_at = _now()
    row.total = len(list(s.scalars(select(IssueRow.id).where(IssueRow.asset_id == row.asset_id))))
    s.commit()
    try:
        after = ""
        while True:
            issues = list(
                s.scalars(
                    select(IssueRow)
                    .where(IssueRow.asset_id == row.asset_id, IssueRow.id > after)
                    .order_by(IssueRow.id)
                    .limit(batch)
                )
            )
            if not issues:
                break
            s.refresh(row)
            if row.status != "running":  # taken over after going stale
                return row
            data = latest_occurrences(s, [i.id for i in issues])
            for issue in issues:
                d = data.get(issue.id)
                if d is not None and apply(issue, evaluate(rules, d, issue)):
                    row.changed += 1
            row.processed += len(issues)
            row.heartbeat_at = _now()
            s.commit()
            after = issues[-1].id
        row.status, row.finished_at = "done", _now()
        repo.add_outbox_event(
            s,
            org_id=row.org_id,
            event_type="priority.recomputed",
            payload={
                "asset_id": row.asset_id,
                "version": row.version,
                "issues": row.processed,
                "band_changed": row.changed,
            },
        )
        s.commit()
    except Exception as exc:
        s.rollback()
        failed = s.get(PriorityPolicy, policy_id)
        assert failed is not None
        row = failed
        row.status, row.finished_at = "failed", _now()
        row.error = f"{type(exc).__name__}: {exc}"[:500]
        s.commit()
        log.exception("priority recomputation %s failed", policy_id)
    return row


# --- preview --------------------------------------------------------------------------------------


@dataclass
class _Ranked:
    issue: IssueRow
    v2: int
    score: int
    band: str | None


def _rank(items: list[_Ranked]) -> list[_Ranked]:
    return sorted(
        items,
        key=lambda r: (
            -(r.score if r.score is not None else -1),
            -r.v2,
            -SEVERITY_RANK.get(r.issue.severity, 0),
            r.issue.title,
            r.issue.id,
        ),
    )


def preview(
    s: Session, asset_id: str, weights: Any, context: Any, *, top: int = PREVIEW_TOP
) -> dict[str, Any]:
    """How the project's open queue would reorder under proposed weights, before saving:
    the new top `top` with each one's rank and score before and after, the ones that would drop
    out of it, and how many open Issues would land in each band."""
    proposed = Rules(-1, parse_weights(weights), parse_context(context))
    now_rules = rules_for(s, asset_id)
    issues = list(
        s.scalars(
            select(IssueRow).where(
                IssueRow.asset_id == asset_id,
                IssueRow.state.in_(OPEN_STATES),
                repo._active_triage_clause(_now()),
            )
        )
    )
    data = latest_occurrences(s, [i.id for i in issues])
    before: list[_Ranked] = []
    after: list[_Ranked] = []
    for issue in issues:
        d = data.get(issue.id)
        if d is None:
            continue
        v2 = (d.get("scoring") or {}).get("risk_score")
        v2 = v2 if v2 is not None else -1
        b, a = evaluate(now_rules, d, issue), evaluate(proposed, d, issue)
        before.append(_Ranked(issue, v2, b["score"], b["band"]))
        after.append(_Ranked(issue, v2, a["score"], a["band"]))
    before, after = _rank(before), _rank(after)
    rank_before = {r.issue.id: (i + 1, r) for i, r in enumerate(before)}

    def row(rank: int | None, r: _Ranked, was: tuple[int, _Ranked] | None) -> dict[str, Any]:
        return {
            "issue_id": r.issue.id,
            "title": r.issue.title,
            "severity": r.issue.severity,
            "path": r.issue.path,
            "before": {"rank": was[0], "score": was[1].score, "band": was[1].band} if was else None,
            "after": {"rank": rank, "score": r.score, "band": r.band} if rank else None,
        }

    top_after = after[:top]
    in_top = {r.issue.id for r in top_after}
    rows = [row(i + 1, r, rank_before.get(r.issue.id)) for i, r in enumerate(top_after)]
    after_by_id = {r.issue.id: (i + 1, r) for i, r in enumerate(after)}
    dropped = []
    for i, r in enumerate(before[:top]):
        if r.issue.id in in_top:
            continue
        rank, now_at = after_by_id[r.issue.id]
        moved_to = {"rank": rank, "score": now_at.score, "band": now_at.band}
        dropped.append({**row(None, r, (i + 1, r)), "after": moved_to})

    def bands(items: list[_Ranked]) -> dict[str, int]:
        out = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for r in items:
            if r.band in out:
                out[r.band] += 1
        return out

    return {
        "open_issues": len(after),
        "current_version": now_rules.version,
        "moved": sum(
            1 for x in rows if x["before"] is None or x["before"]["rank"] != x["after"]["rank"]
        ),
        "top": rows,
        "dropped": dropped,
        "bands_before": bands(before),
        "bands_after": bands(after),
    }


def starter() -> dict[str, float]:
    return dict(STARTER)
