"""Bulk changes across the org's Issues, with a preview first and Undo after (plan §56, principle 9:
"show the effect before the action ... a preview is what makes them safe to take").

A selection is a query (core.search.language), optionally narrowed to Issues picked by id. Every
action is first previewed: how many are selected, how many it would change, how many already are as
asked, and how many it leaves alone and why, by project and severity. Applying names the count the
person saw (`expected_count`); if the list changed since, nothing happens and the new count is
returned, so nobody changes 1,300 Issues believing it was 1,204.

Reversible actions -- assign or unassign, mark not a risk, reopen, add or remove a tag -- are
applied in one transaction with one audit entry per changed Issue (the same actions a single change
writes, so each Issue's history shows it) and one for the batch. Each changed Issue's previous
values are kept, and for UNDO_SECONDS the change can be undone: an Issue someone changed since is
left as it now is, and said so. The screen offers Undo for 10 seconds; the server allows a few
more for a slow network.

Risk acceptance is not a bulk action here. It needs a second person (principle 10) and is made per
project, so its preview groups the selection by project and the screen opens each project's
request form with those Issues; applying it is refused.

Left alone, with the reason: Issues under a risk acceptance (decided in that flow), fixed Issues
(for assign and not-a-risk), and dependency Issues with a VEX justification (reopen: reopening
withdraws their VEX statement, which Undo could not put back, so that is done one at a time).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.acceptance.service import MAX_ISSUES as MAX_PER_ACCEPTANCE
from core.collab import tags as tagging
from core.collab.assign import AssignError, resolve
from core.persistence import repo
from core.persistence.models import Asset, IssueBatch, IssueRow, Tag
from core.search import issues as search
from core.search.language import QueryError, format_query, parse

MAX_BULK = 10_000
MAX_IDS = 1_000
UNDO_SECONDS = 10
GRACE_SECONDS = 5
REVERSIBLE = ("assign", "not_a_risk", "reopen", "tag", "untag")
ACTIONS = (*REVERSIBLE, "accept")
TRIAGE_FIELDS = ("triage_status", "triage_reason", "triage_expires_at", "triaged_at",
                 "triaged_by", "triage_justification")  # fmt: skip

UNDER_ACCEPTANCE = "under a risk acceptance: decide it there"
FIXED = "already fixed"
VEX_BACKED = "a dependency Issue with a VEX justification: reopen it on its own page"
TOO_MANY_TAGS = f"already has {tagging.MAX_TAGS} tags"
NOT_OPEN = "not open"


class BulkError(ValueError):
    def __init__(self, field: str, message: str, status: int = 422, **extra: Any) -> None:
        super().__init__(message)
        self.field, self.message, self.status, self.extra = field, message, status, extra

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "message": self.message, **self.extra}


@dataclass
class Plan:
    """What an action would do to each selected Issue."""

    action: str
    params: dict[str, Any]
    query: str
    selected: list[IssueRow]
    change: list[IssueRow]
    unchanged: list[IssueRow]
    skipped: dict[str, list[IssueRow]]
    describe: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _iso(dt: datetime | None) -> str | None:
    dt = _utc(dt)
    return dt.isoformat() if dt else None


def _dt(raw: Any) -> datetime | None:
    return datetime.fromisoformat(raw) if isinstance(raw, str) else None


def _n(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


# --- what is selected ------------------------------------------------------------------------


def selection(
    s: Session, org_id: str, q_text: Any, ids: Any, ctx: search.Context
) -> tuple[str, list[IssueRow]]:
    """The Issues a selection names: everything matching the query, or only the given ids among
    them (an id that does not match, or is another organization's, is simply not selected)."""
    if not isinstance(q_text, str) or len(q_text) > 2000:
        raise BulkError("q", "A query of at most 2,000 characters.")
    try:
        q = parse(q_text)
    except QueryError as exc:
        raise BulkError("q", exc.message, start=exc.start, end=exc.end) from exc
    conds, _ = search.conditions(s, org_id, q, ctx)
    stmt = select(IssueRow).where(*conds)
    if ids is not None:
        if not isinstance(ids, list) or not all(isinstance(i, str) and len(i) <= 36 for i in ids):
            raise BulkError("ids", "Issue ids, please.")
        if not ids:
            raise BulkError("ids", "Select at least one Issue.")
        if len(ids) > MAX_IDS:
            raise BulkError(
                "ids", f"At most {MAX_IDS:,} picked one by one; select all matching instead."
            )
        stmt = stmt.where(IssueRow.id.in_(set(ids)))
    rows = list(s.scalars(stmt.order_by(IssueRow.id).limit(MAX_BULK + 1)))
    if len(rows) > MAX_BULK:
        raise BulkError(
            "q", f"At most {MAX_BULK:,} Issues at once. Narrow the filters and do it in parts.", 413
        )
    return format_query(q), rows


# --- what an action would do -----------------------------------------------------------------


def _accepted(i: IssueRow) -> bool:
    return i.triage_status == "accepted"


def _own_tags(s: Session, issues: list[IssueRow]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {i.id: set() for i in issues}
    ids = list(out)
    for k in range(0, len(ids), 1000):
        for target, name in s.execute(select(Tag.target_id, Tag.name).where(
                Tag.target_type == "issue", Tag.target_id.in_(ids[k:k + 1000]))):  # fmt: skip
            out[target].add(name)
    return out


def plan(
    s: Session, org_id: str, action: Any, params: Any, q_text: Any, ids: Any, ctx: search.Context
) -> Plan:
    if action not in ACTIONS:
        raise BulkError("action", f"One of: {', '.join(ACTIONS)}.")
    if not isinstance(params, dict):
        params = {}
    query, rows = selection(s, org_id, q_text, ids, ctx)
    change: list[IssueRow] = []
    unchanged: list[IssueRow] = []
    skipped: dict[str, list[IssueRow]] = {}

    def skip(reason: str, i: IssueRow) -> None:
        skipped.setdefault(reason, []).append(i)

    clean: dict[str, Any] = {}
    if action == "assign":
        to = params.get("to")
        if to in (None, ""):
            target, who = None, "nobody"
        else:
            if not isinstance(to, str):
                raise BulkError("to", "Name a person by their @handle.")
            try:
                person = resolve(s, org_id, to)
            except AssignError as exc:
                raise BulkError("to", str(exc)) from exc
            target, who = person.actor, person.name
        clean = {"to": target}
        describe = f"Assign to {who}" if target else "Unassign"
        for i in rows:
            if i.state == "fixed":
                skip(FIXED, i)
            elif i.assignee == target:
                unchanged.append(i)
            else:
                change.append(i)
    elif action == "not_a_risk":
        reason = params.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise BulkError("reason", "Say why these are not a risk; each Issue keeps the reason.")
        if len(reason) > 2000:
            raise BulkError("reason", "At most 2,000 characters.")
        clean = {"reason": reason.strip()}
        describe = "Mark not a risk"
        for i in rows:
            if _accepted(i):
                skip(UNDER_ACCEPTANCE, i)
            elif i.state == "fixed":
                skip(FIXED, i)
            elif i.triage_status == "not_a_risk":
                unchanged.append(i)
            else:
                change.append(i)
    elif action == "reopen":
        describe = "Reopen"
        for i in rows:
            if _accepted(i):
                skip(UNDER_ACCEPTANCE, i)
            elif i.triage_status != "not_a_risk":
                unchanged.append(i)
            elif i.triage_justification and i.category in ("sca", "container"):
                skip(VEX_BACKED, i)
            else:
                change.append(i)
    elif action in ("tag", "untag"):
        try:
            tag = tagging.normalize(str(params.get("tag") or ""))
        except tagging.TagError as exc:
            raise BulkError("tag", str(exc)) from exc
        clean = {"tag": tag}
        describe = f"Add the tag “{tag}”" if action == "tag" else f"Remove the tag “{tag}”"
        own = _own_tags(s, rows)
        for i in rows:
            has = tag in own[i.id]
            if action == "tag" and has or action == "untag" and not has:
                unchanged.append(i)
            elif action == "tag" and len(own[i.id]) >= tagging.MAX_TAGS:
                skip(TOO_MANY_TAGS, i)
            else:
                change.append(i)
    else:  # accept: its own flow, previewed here
        describe = "Request a risk acceptance"
        now = ctx.now
        for i in rows:
            until = _utc(i.triage_expires_at)
            if _accepted(i) and until is not None and until > now:
                skip(UNDER_ACCEPTANCE, i)
            elif search.status_of_row(i, now) != "open":
                skip(NOT_OPEN, i)
            else:
                change.append(i)  # including one whose acceptance ran out: back in the queue
    return Plan(action, clean, query, rows, change, unchanged, skipped, describe)


def _labels(s: Session, org_id: str, issues: list[IssueRow]) -> dict[str, str]:
    asset_ids = sorted({i.asset_id for i in issues})
    out: dict[str, str] = {}
    for k in range(0, len(asset_ids), 1000):
        found = s.execute(select(Asset.id, Asset.label).where(
            Asset.org_id == org_id, Asset.id.in_(asset_ids[k:k + 1000])))  # fmt: skip
        out.update((a, label) for a, label in found)
    return out


def _skipped(p: Plan) -> list[dict[str, Any]]:
    return [{"reason": r, "count": len(v)} for r, v in p.skipped.items()]


def sentence(p: Plan, *, done: bool = False) -> str:
    """The preview, or the result, in one sentence (principle 9: counts, before anything)."""
    n = len(p.change)
    if p.action == "accept":
        projects = len({i.asset_id for i in p.change})
        head = (f"{_n(n, 'Issue')} in {_n(projects, 'project')} can be put forward for risk "
                "acceptance: one request per project, which a second person approves.")  # fmt: skip
    elif done:
        head = f"{p.describe}: {_n(n, 'Issue')} changed."
    else:
        head = f"{p.describe}: {_n(n, 'Issue')} will change."
    rest = []
    if p.unchanged and p.action != "accept":
        verb = "is" if len(p.unchanged) == 1 else "are"
        rest.append(f"{_n(len(p.unchanged), 'Issue')} already {verb} as asked")
    for r, v in p.skipped.items():
        rest.append(f"{len(v):,} left alone ({r})")
    return head + (" " + "; ".join(rest) + "." if rest else "")


def preview(s: Session, org_id: str, p: Plan) -> dict[str, Any]:
    labels = _labels(s, org_id, p.change)
    by_project = Counter(labels.get(i.asset_id, "?") for i in p.change)
    out: dict[str, Any] = {
        "action": p.action,
        "selected": len(p.selected),
        "will_change": len(p.change),
        "unchanged": len(p.unchanged),
        "skipped": _skipped(p),
        "by_project": [{"project": k, "count": v} for k, v in by_project.most_common(10)],
        "by_severity": dict(Counter(i.severity.lower() for i in p.change)),
        "expected_count": len(p.selected),
        "reversible": p.action in REVERSIBLE,
        "sentence": sentence(p),
    }
    if p.action == "accept":
        groups: dict[str, list[str]] = {}
        for i in p.change:
            groups.setdefault(i.asset_id, []).append(i.id)
        out["flow"] = {"kind": "risk_acceptance", "projects": [
            {"project_id": a, "project": labels.get(a, "?"), "count": len(v),
             "issue_ids": v[:MAX_PER_ACCEPTANCE], "truncated": len(v) > MAX_PER_ACCEPTANCE}
            for a, v in sorted(groups.items(), key=lambda kv: (-len(kv[1]), labels.get(kv[0], "")))
        ]}  # fmt: skip
    return out


# --- applying, and undoing -------------------------------------------------------------------


def _triage_values(i: IssueRow) -> dict[str, Any]:
    return {f: _iso(getattr(i, f)) if f.endswith("_at") else getattr(i, f) for f in TRIAGE_FIELDS}


def _set_triage(i: IssueRow, values: dict[str, Any]) -> None:
    for f in TRIAGE_FIELDS:
        setattr(i, f, _dt(values.get(f)) if f.endswith("_at") else values.get(f))


def _tag_creators(s: Session, ids: list[str], tag: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for k in range(0, len(ids), 1000):
        chunk = ids[k : k + 1000]
        found = s.execute(select(Tag.target_id, Tag.created_by).where(
            Tag.target_type == "issue", Tag.name == tag, Tag.target_id.in_(chunk)))  # fmt: skip
        out.update((target, by) for target, by in found)
    return out


def _drop_tags(s: Session, ids: list[str], tag: str) -> None:
    """One statement per thousand Issues, not one per Issue (a batch may hold 10,000)."""
    for k in range(0, len(ids), 1000):
        s.execute(delete(Tag).where(and_(Tag.target_type == "issue", Tag.name == tag,
                                         Tag.target_id.in_(ids[k:k + 1000]))))  # fmt: skip


def _apply_one(
    s: Session, org_id: str, p: Plan, i: IssueRow, actor: str, now: datetime, batch: str,
    creators: dict[str, str | None],
) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    """Change one Issue; return its previous values and its audit entry."""
    if p.action == "assign":
        target = p.params["to"]
        prev: dict[str, Any] = {"assignee": i.assignee, "assigned_at": _iso(i.assigned_at)}
        i.assignee, i.assigned_at = target, now if target else None
        kind = "issue.assigned" if target else "issue.unassigned"
        repo.add_outbox_event(s, org_id=org_id, event_type=kind, payload={
            "issue_id": i.id, "asset_id": i.asset_id, "assignee": target,
            "previous": prev["assignee"], "by": actor, "batch_id": batch})  # fmt: skip
        payload = {"asset_id": i.asset_id, "assignee": target, "previous": prev["assignee"],
                   "batch_id": batch}  # fmt: skip
        return prev, {"action": kind, "payload": payload}
    if p.action in ("not_a_risk", "reopen"):
        prev = _triage_values(i)
        if p.action == "not_a_risk":
            i.triage_status, i.triage_reason = "not_a_risk", p.params["reason"]
        else:
            i.triage_status, i.triage_reason = "open", None
        i.triage_expires_at, i.triage_justification = None, None
        i.triaged_at, i.triaged_by = now, actor
        return prev, {"action": f"issue.triage.{p.action}",
                      "payload": {"action": p.action, "reason": p.params.get("reason"),
                                  "expires_at": None, "batch_id": batch}}  # fmt: skip
    tag = p.params["tag"]
    if p.action == "tag":
        s.add(Tag(org_id=org_id, target_type="issue", target_id=i.id, name=tag, created_by=actor))
        added, removed = [tag], []
        prev = {"tag": None}
    else:
        prev = {"tag": {"created_by": creators.get(i.id, actor)}}  # removed after, all at once
        added, removed = [], [tag]
    return prev, {
        "action": "tags.changed",
        "payload": {
            "org_id": org_id,
            "type": "issue",
            "added": added,
            "removed": removed,
            "batch_id": batch,
        },
    }


def _retrying(s: Session, fn: Any) -> Any:
    """Run a change that stages audit entries and commit it; if another append took the same
    sequence numbers meanwhile, roll back and run it again from the start."""
    for attempt in range(5):
        try:
            out = fn()
            s.commit()
            return out
        except IntegrityError:
            s.rollback()
            if attempt == 4:
                raise
    raise AssertionError("unreachable")


def apply(
    s: Session, org_id: str, actor: str, action: Any, params: Any, q_text: Any, ids: Any,
    expected: Any, ctx: search.Context,
) -> dict[str, Any]:  # fmt: skip
    if action == "accept":
        raise BulkError(
            "action",
            "Risk acceptance is not a bulk change: it needs a second person. Request it per "
            "project from the preview.",
            409,
        )

    def run() -> dict[str, Any]:
        p = plan(s, org_id, action, params, q_text, ids, ctx)
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise BulkError("expected_count", "Say how many Issues the preview showed.")
        if len(p.selected) != expected:
            raise BulkError(
                "expected_count",
                f"The list changed since the preview: {_n(len(p.selected), 'Issue')} match now, "
                f"not {expected:,}. Nothing was changed; look at the preview again.",
                409,
                selected=len(p.selected),
            )
        now = _now()
        batch = IssueBatch(org_id=org_id, actor=actor, action=p.action, params=p.params,
                           query=p.query, selected=len(p.selected), changed=len(p.change),
                           previous={}, created_at=now,
                           undo_until=now + timedelta(seconds=UNDO_SECONDS))  # fmt: skip
        s.add(batch)
        s.flush()
        previous: dict[str, Any] = {}
        entries = []
        changed = [i.id for i in p.change]
        creators = _tag_creators(s, changed, p.params["tag"]) if p.action == "untag" else {}
        for i in p.change:
            prev, entry = _apply_one(s, org_id, p, i, actor, now, batch.id, creators)
            previous[i.id] = prev
            entries.append({"actor": actor, "target": i.id, **entry})
        if p.action == "untag":
            _drop_tags(s, changed, p.params["tag"])
        batch.previous = previous
        entries.append({"actor": actor, "action": "issues.bulk.applied",
                        "target": f"issue_batch:{batch.id}",
                        "payload": {"org_id": org_id, "action": p.action, "params": p.params,
                                    "query": p.query, "selected": len(p.selected),
                                    "changed": len(p.change), "skipped": _skipped(p)}})  # fmt: skip
        s.flush()
        repo.stage_audit_entries(s, entries, org_id=org_id)
        return {"batch_id": batch.id, "action": p.action, "changed": len(p.change),
                "unchanged": len(p.unchanged), "skipped": _skipped(p),
                "undo_until": _iso(batch.undo_until),
                "sentence": sentence(p, done=True)}  # fmt: skip

    try:
        return _retrying(s, run)  # type: ignore[no-any-return]
    except BulkError:
        s.rollback()
        raise


def _still_as_left(s: Session, b: IssueBatch, i: IssueRow, own: set[str]) -> bool:
    """Whether the Issue is still as the batch left it (nobody changed it since)."""
    if b.action == "assign":
        return i.assignee == b.params.get("to") and _utc(i.assigned_at) == (
            _utc(b.created_at) if b.params.get("to") else None
        )
    if b.action in ("not_a_risk", "reopen"):
        want = "not_a_risk" if b.action == "not_a_risk" else "open"
        return (i.triage_status == want and i.triaged_by == b.actor
                and _utc(i.triaged_at) == _utc(b.created_at))  # fmt: skip
    tag = b.params["tag"]
    return (tag in own) if b.action == "tag" else (tag not in own)


def undo(s: Session, org_id: str, actor: str, batch_id: str) -> dict[str, Any]:
    b = s.get(IssueBatch, batch_id) if len(batch_id) <= 36 else None
    if b is None or b.org_id != org_id:
        raise BulkError("id", "No such bulk change.", 404)
    if b.actor != actor:
        raise BulkError("id", "Only the person who made a bulk change can undo it.", 403)
    if b.undone_at is not None:
        raise BulkError("id", "This bulk change was already undone.", 409)
    if _now() > _utc(b.undo_until) + timedelta(seconds=GRACE_SECONDS):  # type: ignore[operator]
        raise BulkError(
            "id", "Too late to undo: change the Issues back with another bulk change.", 409
        )

    def run() -> dict[str, Any]:
        issues = list(s.scalars(select(IssueRow).where(IssueRow.id.in_(list(b.previous)))))
        own = _own_tags(s, issues) if b.action in ("tag", "untag") else {}
        restored = kept = 0
        entries = []
        untag: list[str] = []
        now = _now()
        for i in issues:
            if not _still_as_left(s, b, i, own.get(i.id, set())):
                kept += 1
                continue
            prev = b.previous[i.id]
            if b.action == "assign":
                i.assignee, i.assigned_at = prev["assignee"], _dt(prev["assigned_at"])
                repo.add_outbox_event(
                    s, org_id=org_id,
                    event_type="issue.assigned" if i.assignee else "issue.unassigned",
                    payload={"issue_id": i.id, "asset_id": i.asset_id, "assignee": i.assignee,
                             "previous": b.params.get("to"), "by": actor, "undo_of": b.id},
                )  # fmt: skip
            elif b.action in ("not_a_risk", "reopen"):
                _set_triage(i, prev)
            elif b.action == "tag":
                untag.append(i.id)
            else:
                s.add(Tag(org_id=org_id, target_type="issue", target_id=i.id,
                          name=b.params["tag"], created_by=prev["tag"]["created_by"]))  # fmt: skip
            restored += 1
            entries.append({"actor": actor, "action": "issue.bulk.undone", "target": i.id,
                            "payload": {"batch_id": b.id, "action": b.action}})  # fmt: skip
        _drop_tags(s, untag, b.params.get("tag", ""))
        b.undone_at, b.undone_by = now, actor
        entries.append({"actor": actor, "action": "issues.bulk.undone",
                        "target": f"issue_batch:{b.id}",
                        "payload": {"org_id": org_id, "restored": restored,
                                    "kept": kept}})  # fmt: skip
        s.flush()
        repo.stage_audit_entries(s, entries, org_id=org_id)
        one = kept == 1
        kept_text = (
            f" {_n(kept, 'Issue')} changed since by someone else and "
            f"{'was' if one else 'were'} left as {'it is' if one else 'they are'}."
            if kept
            else ""
        )
        back = "it was" if restored == 1 else "they were"
        return {
            "restored": restored,
            "kept": kept,
            "sentence": f"Undone: {_n(restored, 'Issue')} back as {back}." + kept_text,
        }

    return _retrying(s, run)  # type: ignore[no-any-return]
