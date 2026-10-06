"""Running rules (plan §45): from the outbox, from the sweep, by an Admin's confirmation, and as a
dry run.

**From the outbox.** The dispatcher (`core.dispatch`) hands each batch of new events to
`on_events`. For each enabled rule whose trigger the batch contains, the rule's subjects (the
Issues, or the project, the event is about) are built into `input` documents and its condition is
evaluated once for the whole batch. Matches are grouped by cause -- the scan or import that caused
them, or else the event type, project and minute -- and each group is one run.

**Safety (threat T26).**
- *Bulk confirmation.* When a cause would have a rule act on more Issues than its threshold (25 by
  default), nothing is applied: the run is held until an Admin confirms or dismisses it. Later
  matches from the same cause join the held run.
- *Depth limit.* An event a rule caused carries the chain's depth. A rule set off at depth
  `MAX_DEPTH` does not run; a `depth_limited` run records that it would have.
- *Once per subject per cause.* A subject already in a run for the same cause is skipped, so a
  redelivered batch never acts twice.
- A rule never fires on events from before it was created.

**From the sweep.** `sweep` fires the two triggers no event carries: a project with no completed
scan or import for N days (once per quiet stretch), and schedules (once per slot, after the rule
was created; every open Issue in scope is checked).

**Dry run.** `dry_run` replays the last seven days of the trigger's events, or checks the current
state for the sweep's triggers, against the rule's condition -- without acting -- and says how many
Issues it would have matched, how many runs that is, and how many would have needed confirmation.
It reads each Issue as it is now, not as it was when the event happened, and says so.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import Asset, AutomationRule, IssueRow, OutboxEvent, RuleRun, Scan
from core.rules import actions as rule_actions
from core.rules import rego
from core.rules.catalog import MAX_DEPTH, TRIGGERS
from core.rules.inputs import Builder, event_doc
from core.sla.policy import OPEN_STATES

log = logging.getLogger(__name__)
BATCH = 500
DRY_RUN_DAYS = 7
DRY_RUN_MAX_EVENTS = 5000
APPLIED = ("applied", "confirmed")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Event:
    """An outbox event as plain data, so commits during a batch never reload it."""

    id: int
    type: str
    payload: dict[str, Any]
    created_at: datetime

    @staticmethod
    def of(e: OutboxEvent) -> Event:
        return Event(e.id, e.event_type, dict(e.payload or {}), _aware(e.created_at))

    @property
    def depth(self) -> int:
        rule = self.payload.get("rule")
        return int(rule.get("depth", 0)) if isinstance(rule, dict) else 0

    @property
    def cause(self) -> str:
        p = self.payload
        if p.get("import_id"):
            return f"import:{p['import_id']}"
        if p.get("scan_id"):
            return f"scan:{p['scan_id']}"
        if p.get("acceptance_id"):
            return f"acceptance:{p['acceptance_id']}:{self.type}"
        return f"{self.type}:{p.get('asset_id', '')}:{self.created_at:%Y-%m-%dT%H:%M}"


@dataclass
class Candidate:
    subject_id: str
    cause: str
    depth: int
    event: Event | None
    item: dict[str, Any] = field(default_factory=dict)
    describe: str = ""
    project: str = ""
    reason: str = ""

    @property
    def key(self) -> str:
        return f"{self.event.id if self.event is not None else '-'}:{self.subject_id}"


@dataclass
class Outcome:
    runs: list[RuleRun] = field(default_factory=list)
    held: int = 0
    applied: int = 0
    depth_limited: int = 0
    failed: int = 0


# --- rules in scope ------------------------------------------------------------------------------


def _enabled(s: Session, org_id: str, triggers: Iterable[str]) -> list[AutomationRule]:
    wanted = list(set(triggers))
    if not wanted:
        return []
    return list(
        s.scalars(
            select(AutomationRule)
            .where(
                AutomationRule.org_id == org_id,
                AutomationRule.enabled.is_(True),
                AutomationRule.deleted_at.is_(None),
                AutomationRule.trigger.in_(wanted),
            )
            .order_by(AutomationRule.created_at)
        )
    )


def _triggers_for(event_types: Iterable[str]) -> set[str]:
    types = set(event_types)
    return {k for k, t in TRIGGERS.items() if types & set(t.events)}


# --- building candidates --------------------------------------------------------------------------


def _describe_issue(doc: dict[str, Any], project: str) -> str:
    band = f", {doc['priority_band']}" if doc.get("priority_band") else ""
    return f"{doc.get('severity', '')}{band} {str(doc.get('title', ''))[:140]} ({project})".strip()


def _issue_candidates(
    b: Builder, pairs: Sequence[tuple[str, str, int, Event | None]], trigger_label: str
) -> list[Candidate]:
    """`pairs` are (issue id, cause, depth, event)."""
    docs = b.issues(p[0] for p in pairs)
    out = []
    for issue_id, cause, depth, ev in pairs:
        if issue_id not in docs:
            continue
        row, doc = docs[issue_id]
        asset = b.s.get(Asset, row.asset_id)
        assert asset is not None
        project = b.project(asset)
        item: dict[str, Any] = {"issue": doc, "project": project}
        if ev is not None:
            item["event"] = event_doc(ev.type, ev.payload, ev.created_at)
        out.append(Candidate(issue_id, cause, depth, ev, item,
                             _describe_issue(doc, asset.label), asset.label,
                             f"{trigger_label.lower()} in {asset.label}"))  # fmt: skip
    return out


def _project_candidate(
    b: Builder, asset: Asset, cause: str, depth: int, ev: Event | None, **extra: Any
) -> Candidate:
    project = dict(b.project(asset))
    item: dict[str, Any] = {"project": project}
    reason = asset.label
    if "days_since_scan" in extra:
        project["days_since_scan"] = extra["days_since_scan"]
        reason = f"{asset.label} has had no scan for {extra['days_since_scan']} days"
    if ev is not None:
        item["event"] = event_doc(ev.type, ev.payload, ev.created_at)
        counts = ev.payload.get("counts")
        item["scan"] = {"id": ev.payload.get("scan_id"), "status": ev.payload.get("status"),
                        "source": ev.payload.get("source"),
                        "counts": counts if isinstance(counts, dict) else {}}  # fmt: skip
        what = "import" if ev.payload.get("source") == "import" else "scan"
        new = item["scan"]["counts"].get("new")
        reason = f"a {what} of {asset.label} completed" + (f": {new} new" if new else "")
    return Candidate(asset.id, cause, depth, ev, item, asset.label, asset.label, reason)


def _candidates_for_events(
    b: Builder, rule: AutomationRule, events: Sequence[Event]
) -> tuple[list[Candidate], list[tuple[str, int, int]]]:
    """Candidates for one rule, and the (cause, depth, event id) the depth limit stopped."""
    trig = TRIGGERS[rule.trigger]
    created = _aware(rule.created_at)
    pairs: list[tuple[str, str, int, Event | None]] = []
    projects: list[tuple[str, str, int, Event]] = []
    stopped: list[tuple[str, int, int]] = []
    for ev in events:
        if ev.type not in trig.events or ev.created_at < created:
            continue
        if rule.asset_id is not None and ev.payload.get("asset_id") != rule.asset_id:
            continue
        if ev.depth >= MAX_DEPTH:
            stopped.append((ev.cause, ev.depth, ev.id))
            continue
        if trig.subject == "issue":
            ids = ev.payload.get("issue_ids") or (
                [ev.payload["issue_id"]] if ev.payload.get("issue_id") else []
            )
            pairs.extend((str(i), ev.cause, ev.depth, ev) for i in ids)
        elif ev.payload.get("asset_id"):
            projects.append((str(ev.payload["asset_id"]), ev.cause, ev.depth, ev))
    out = _issue_candidates(b, pairs, trig.label) if pairs else []
    for asset_id, cause, depth, ev in projects:
        asset = repo.get_asset(b.s, asset_id, org_id=b.org_id)
        if asset is not None:
            out.append(_project_candidate(b, asset, cause, depth, ev))
    return out, stopped


def _match(rule: AutomationRule, cands: list[Candidate]) -> list[Candidate]:
    hits: set[int] = set()
    for start in range(0, len(cands), BATCH):
        chunk = cands[start : start + BATCH]
        hits |= {start + i for i in rego.matches(rule.condition, [c.item for c in chunk])}
    return [c for i, c in enumerate(cands) if i in hits]


# --- firing ---------------------------------------------------------------------------------------


def _runs_for(s: Session, rule_id: str, cause: str) -> list[RuleRun]:
    return list(s.scalars(select(RuleRun).where(RuleRun.rule_id == rule_id,
                                                RuleRun.cause == cause)))  # fmt: skip


def _audit_run(s: Session, rule: AutomationRule, run: RuleRun, actor: str | None = None) -> None:
    summary: dict[str, int] = defaultdict(int)
    for r in run.results or []:
        summary[f"{r.get('action')}.{r.get('outcome')}"] += 1
    repo.append_audit_entry(  # commits
        s, actor=actor or f"rule:{rule.id}", action=f"rule.run.{run.status}",
        target=f"rule:{rule.id}",
        payload={"org_id": rule.org_id, "run_id": run.id, "version": run.rule_version,
                 "cause": run.cause, "subjects": run.subject_ids, "depth": run.depth,
                 "outcomes": dict(summary), "error": run.error},
    )  # fmt: skip


def apply_actions(
    s: Session, org_id: str, rule: AutomationRule, cands: Sequence[Candidate], depth: int
) -> list[dict[str, Any]]:
    subject = TRIGGERS[rule.trigger].subject
    cands = list({c.subject_id: c for c in cands}.values())  # one subject, acted on once
    reason = cands[0].reason if cands else ""
    if len({c.reason for c in cands}) > 1 and subject == "issue":
        reason = f"{len(cands)} issues: {TRIGGERS[rule.trigger].label.lower()}"
    ctx = rule_actions.Context(s, org_id, rule, depth, reason=reason)
    results: list[dict[str, Any]] = []
    if subject == "issue":
        for c in cands:
            issue = s.get(IssueRow, c.subject_id)
            if issue is None:
                continue
            for spec in rule.actions:
                if spec["type"] != "notify":
                    results.append(rule_actions.apply_to_issue(ctx, spec, issue))
    for spec in rule.actions:
        if spec["type"] == "notify":
            project = cands[0].project if cands else ""
            results.append(rule_actions.notify(ctx, spec, [(c.subject_id, c.describe)
                                                           for c in cands], project))  # fmt: skip
    return results


def _fire(
    s: Session,
    org_id: str,
    rule: AutomationRule,
    cause: str,
    cands: list[Candidate],
    out: Outcome,
) -> None:
    existing = _runs_for(s, rule.id, cause)
    seen = {k for r in existing for k in (r.event_keys or [])}
    fresh: list[Candidate] = []
    for c in cands:
        if c.key not in seen:
            seen.add(c.key)
            fresh.append(c)
    if not fresh:
        return
    keys = [c.key for c in fresh]
    subjects = list(dict.fromkeys(c.subject_id for c in fresh))
    depth = max(c.depth for c in fresh)
    event_id = next((c.event.id for c in fresh if c.event is not None), None)
    held = next((r for r in existing if r.status == "held"), None)
    if held is not None:
        held.subject_ids = list(dict.fromkeys([*held.subject_ids, *subjects]))
        held.event_keys = [*held.event_keys, *keys]
        s.commit()
        return
    subject = TRIGGERS[rule.trigger].subject
    already = len({sid for r in existing if r.status in APPLIED for sid in (r.subject_ids or [])})
    base = dict(org_id=org_id, rule_id=rule.id, rule_version=rule.version, trigger=rule.trigger,
                cause=cause, event_id=event_id, depth=depth, subject_ids=subjects,
                event_keys=keys)  # fmt: skip
    if subject == "issue" and already + len(subjects) > rule.confirm_over:
        run = RuleRun(status="held", results=[], **base)
        s.add(run)
        s.flush()
        repo.add_outbox_event(
            s, org_id=org_id, event_type="rule.held",
            payload={"rule_id": rule.id, "run_id": run.id, "name": rule.name,
                     "count": len(subjects) + already, "asset_id": rule.asset_id},
        )  # fmt: skip
        s.flush()
        _audit_run(s, rule, run)
        out.runs.append(run)
        out.held += 1
        return
    # Committed before acting: an action that fails rolls back only its own work, never the
    # record that the run happened.
    run = RuleRun(status="running", results=[], **base)
    s.add(run)
    s.commit()
    run_id = run.id
    results = apply_actions(s, org_id, rule, fresh, depth)
    run = s.get(RuleRun, run_id) or run
    run.results, run.status = results, "applied"
    if results and all(r["outcome"] == "failed" for r in results):
        run.status, run.error = "failed", results[0].get("detail")
    rule_row = s.get(AutomationRule, rule.id) or rule
    rule_row.last_fired_at = _now()
    s.flush()
    _audit_run(s, rule_row, run)
    out.runs.append(run)
    if run.status == "failed":
        out.failed += 1
    else:
        out.applied += 1


def _record(
    s: Session, org_id: str, rule: AutomationRule, cause: str, status: str, error: str,
    depth: int = 0, event_id: int | None = None,
) -> RuleRun | None:  # fmt: skip
    """A run that did nothing (depth-limited, or a condition that would not evaluate) -- once per
    cause, so a stream of events does not become a stream of identical rows."""
    if any(r.status == status for r in _runs_for(s, rule.id, cause)):
        return None
    run = RuleRun(org_id=org_id, rule_id=rule.id, rule_version=rule.version, trigger=rule.trigger,
                  cause=cause, event_id=event_id, depth=depth, status=status, subject_ids=[],
                  event_keys=[], results=[], error=error[:2000])  # fmt: skip
    s.add(run)
    s.flush()
    _audit_run(s, rule, run)
    return run


def _run_rule(
    s: Session, org_id: str, rule: AutomationRule, cands: list[Candidate], out: Outcome
) -> None:
    if not cands:
        return
    try:
        matched = _match(rule, cands)
    except rego.ConditionError as exc:
        if _record(s, org_id, rule, cands[0].cause, "failed", f"condition: {exc}"):
            out.failed += 1
        return
    by_cause: dict[str, list[Candidate]] = defaultdict(list)
    for c in matched:
        by_cause[c.cause].append(c)
    for cause, group in by_cause.items():
        try:
            _fire(s, org_id, rule, cause, group, out)
        except Exception as exc:  # noqa: BLE001 - one rule failing must not stop the others
            s.rollback()
            log.warning("rule %s failed for %s", rule.id, cause, exc_info=True)
            if _record(s, org_id, rule, cause, "failed", f"{type(exc).__name__}: {exc}"):
                out.failed += 1


def on_events(s: Session, org_id: str, events: Sequence[Event]) -> Outcome:
    """The dispatcher's subscriber: every enabled rule a batch of events can fire."""
    out = Outcome()
    rules = _enabled(s, org_id, _triggers_for(e.type for e in events))
    if not rules:
        return out
    b = Builder(s, org_id)
    for rule in rules:
        cands, stopped = _candidates_for_events(b, rule, events)
        for cause, depth, event_id in stopped:
            if _record(s, org_id, rule, cause, "depth_limited",
                       f"set off by a chain of {depth} rules; the limit is {MAX_DEPTH}",
                       depth=depth, event_id=event_id):  # fmt: skip
                out.depth_limited += 1
        _run_rule(s, org_id, rule, cands, out)
    return out


# --- the sweep: quiet projects and schedules ----------------------------------------------------


def _assets_in_scope(s: Session, org_id: str, rule: AutomationRule) -> list[Asset]:
    q = select(Asset).where(Asset.org_id == org_id)
    if rule.asset_id is not None:
        q = q.where(Asset.id == rule.asset_id)
    return list(s.scalars(q.order_by(Asset.created_at)))


def last_activity(s: Session, asset_ids: list[str]) -> dict[str, datetime]:
    """Each project's latest completed scan or import."""
    if not asset_ids:
        return {}
    rows = s.execute(
        select(Scan.asset_id, func.max(Scan.created_at))
        .where(Scan.asset_id.in_(asset_ids), Scan.status == "completed")
        .group_by(Scan.asset_id)
    )
    return {a: _aware(t) for a, t in rows if a is not None and t is not None}


def _quiet_candidates(b: Builder, rule: AutomationRule, now: datetime) -> list[Candidate]:
    days = int(rule.trigger_params.get("days", 7))
    assets = _assets_in_scope(b.s, b.org_id, rule)
    last = last_activity(b.s, [a.id for a in assets])
    out = []
    for asset in assets:
        since = last.get(asset.id) or _aware(asset.created_at)
        quiet = (now - since).days
        if quiet < days:
            continue
        cause = f"quiet:{asset.id}:{since.isoformat()}"
        out.append(_project_candidate(b, asset, cause, 0, None, days_since_scan=quiet))
    return out


def schedule_slot(params: dict[str, Any], now: datetime) -> datetime:
    """The most recent moment the schedule was due, at or before `now` (UTC)."""
    every = params.get("every", "day")
    if every == "hour":
        return now.replace(minute=0, second=0, microsecond=0)
    slot = now.replace(hour=int(params.get("hour", 9)), minute=0, second=0, microsecond=0)
    if every == "day":
        return slot if slot <= now else slot - timedelta(days=1)
    slot -= timedelta(days=(slot.weekday() - int(params.get("weekday", 0))) % 7)
    return slot if slot <= now else slot - timedelta(days=7)


def _open_issue_ids(s: Session, org_id: str, rule: AutomationRule) -> list[str]:
    q = (
        select(IssueRow.id)
        .join(Asset, Asset.id == IssueRow.asset_id)
        .where(Asset.org_id == org_id, IssueRow.state.in_(OPEN_STATES))
    )
    if rule.asset_id is not None:
        q = q.where(IssueRow.asset_id == rule.asset_id)
    return list(s.scalars(q.order_by(IssueRow.first_seen_at)))


def _schedule_candidates(b: Builder, rule: AutomationRule, cause: str) -> list[Candidate]:
    ids = _open_issue_ids(b.s, b.org_id, rule)
    out: list[Candidate] = []
    for start in range(0, len(ids), BATCH):
        chunk = ids[start : start + BATCH]
        out += _issue_candidates(b, [(i, cause, 0, None) for i in chunk], "the schedule")
    for c in out:
        c.reason = f"{rule.name} (scheduled)"
    return out


def sweep(s: Session, org_id: str, now: datetime | None = None) -> Outcome:
    now = now or _now()
    out = Outcome()
    b = Builder(s, org_id, now)
    for rule in _enabled(s, org_id, ("project.quiet", "schedule")):
        if rule.trigger == "project.quiet":
            _run_rule(s, org_id, rule, _quiet_candidates(b, rule, now), out)
            continue
        slot = schedule_slot(rule.trigger_params, now)
        last = _aware(rule.last_fired_at) if rule.last_fired_at else None
        if slot < _aware(rule.created_at) or (last is not None and last >= slot):
            continue
        rule.last_fired_at = slot
        s.commit()
        _run_rule(s, org_id, rule, _schedule_candidates(b, rule, f"schedule:{slot:%Y-%m-%dT%H:%M}"),
                  out)  # fmt: skip
    return out


# --- an Admin's decision on a held run ------------------------------------------------------------


class RunError(ValueError):
    pass


def confirm(s: Session, org_id: str, run: RuleRun, *, actor: str) -> RuleRun:
    """Apply a held run, as it was held: the same Issues, the rule's current actions."""
    if run.status != "held":
        raise RunError("Only a held run can be confirmed.")
    rule = s.get(AutomationRule, run.rule_id)
    if rule is None or rule.deleted_at is not None:
        raise RunError("The rule was deleted.")
    b = Builder(s, org_id)
    cands = _issue_candidates(b, [(i, run.cause, run.depth, None) for i in run.subject_ids],
                              TRIGGERS[rule.trigger].label)  # fmt: skip
    run_id = run.id
    results = apply_actions(s, org_id, rule, cands, run.depth)
    run = s.get(RuleRun, run_id) or run
    run.results = results
    run.status, run.decided_by, run.decided_at = "confirmed", actor, _now()
    rule.last_fired_at = run.decided_at
    s.flush()
    _audit_run(s, rule, run, actor=actor)
    return run


def dismiss(s: Session, org_id: str, run: RuleRun, *, actor: str) -> RuleRun:
    if run.status != "held":
        raise RunError("Only a held run can be dismissed.")
    rule = s.get(AutomationRule, run.rule_id)
    assert rule is not None
    run.status, run.decided_by, run.decided_at = "dismissed", actor, _now()
    s.flush()
    _audit_run(s, rule, run, actor=actor)
    return run


# --- dry run --------------------------------------------------------------------------------------


@dataclass
class DryRun:
    subject: str
    matched: int
    runs: int
    would_hold: int
    checked: int
    window_days: int
    sample: list[dict[str, Any]]
    note: str


def dry_run(
    s: Session, org_id: str, rule: AutomationRule, *, now: datetime | None = None
) -> DryRun:
    """`rule` may be unsaved (an AutomationRule built from a draft, never added to the session)."""
    now = now or _now()
    b = Builder(s, org_id, now)
    trig = TRIGGERS[rule.trigger]
    note = "Checked against each issue as it is now, not as it was when the event happened."
    checked = 0
    if rule.trigger == "project.quiet":
        cands = _quiet_candidates(b, rule, now)
        checked = len(_assets_in_scope(s, org_id, rule))
        note = "Checked against every project in scope as it is now."
    elif rule.trigger == "schedule":
        cands = _schedule_candidates(b, rule, "dry-run")
        checked = len(cands)
        note = "Checked against every open issue in scope as it is now, as the next run would."
    else:
        q = (
            select(OutboxEvent)
            .where(
                OutboxEvent.org_id == org_id,
                OutboxEvent.event_type.in_(trig.events),
                OutboxEvent.created_at >= now - timedelta(days=DRY_RUN_DAYS),
            )
            .order_by(OutboxEvent.id.desc())
            .limit(DRY_RUN_MAX_EVENTS)
        )
        if rule.asset_id is not None:
            q = q.where(OutboxEvent.payload["asset_id"].as_string() == rule.asset_id)
        events = [Event.of(e) for e in s.scalars(q)][::-1]
        checked = len(events)
        probe = AutomationRule(**{c: getattr(rule, c) for c in (
            "id", "org_id", "asset_id", "name", "trigger", "trigger_params", "condition",
            "actions", "confirm_over", "version")})  # fmt: skip
        probe.created_at = now - timedelta(days=DRY_RUN_DAYS + 1)
        cands, _ = _candidates_for_events(b, probe, events)
    matched = _match(rule, cands)
    by_cause: dict[str, set[str]] = defaultdict(set)
    for c in matched:
        by_cause[c.cause].add(c.subject_id)
    subjects = list(dict.fromkeys(c.subject_id for c in matched))
    hold = sum(1 for ids in by_cause.values() if trig.subject == "issue"
               and len(ids) > rule.confirm_over)  # fmt: skip
    sample = []
    shown: set[str] = set()
    for c in matched:
        if c.subject_id in shown:
            continue
        shown.add(c.subject_id)
        entry: dict[str, Any] = {"id": c.subject_id, "text": c.describe, "project": c.project}
        if trig.subject == "issue":
            issue = c.item.get("issue", {})
            entry.update(title=issue.get("title"), severity=issue.get("severity"),
                         priority_band=issue.get("priority_band"),
                         asset_id=c.item.get("project", {}).get("id"))  # fmt: skip
        sample.append(entry)
        if len(sample) >= 10:
            break
    return DryRun(trig.subject, len(subjects), len(by_cause), hold, checked,
                  DRY_RUN_DAYS, sample, note)  # fmt: skip


def runs_touching(s: Session, org_id: str, issue_id: str) -> list[RuleRun]:
    """Runs that acted on an Issue (for its page). JSON containment differs between databases,
    so this reads the organization's recent runs and filters."""
    rows = s.scalars(
        select(RuleRun)
        .where(RuleRun.org_id == org_id, or_(RuleRun.status == "applied",
                                             RuleRun.status == "confirmed"))  # fmt: skip
        .order_by(RuleRun.created_at.desc()).limit(500)
    )
    return [r for r in rows if issue_id in (r.subject_ids or [])]


__all__ = ["DryRun", "Event", "RunError", "confirm", "dismiss", "dry_run", "on_events", "sweep"]
