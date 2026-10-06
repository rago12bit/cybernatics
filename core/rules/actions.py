"""What a rule does when it matches (plan §45). Each action reports, per subject, whether it
changed something, changed nothing (already so), was skipped (with why) or failed (with why).

A rule acts as `rule:<id>`: the audit log and the Issue's history name it. Every change announces
an outbox event carrying the rule and its depth in a chain, so a rule another rule set off knows how
deep it is (`MAX_DEPTH`). An action that changes nothing announces nothing, so a rule cannot keep
re-firing itself on its own no-op.

`notify` runs once per run with every matched subject, so a scan that matches forty Issues is one
message listing them, not forty messages.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.collab import tags as tag_service
from core.collab.assign import AssignError, assign
from core.persistence import repo
from core.persistence.models import Asset, AutomationRule, IssueRow, RuleRun
from core.rules.catalog import DEFAULT_FIX_PER_DAY

log = logging.getLogger(__name__)


@dataclass
class Context:
    s: Session
    org_id: str
    rule: AutomationRule
    depth: int  # the depth of the event that set this run off; what it announces is one deeper
    reason: str = ""  # for notify: what happened ("12 new issues from the scan of ...")
    fixes_this_run: int = 0

    @property
    def actor(self) -> str:
        return f"rule:{self.rule.id}"

    def event_extra(self) -> dict[str, Any]:
        return {"rule": {"id": self.rule.id, "name": self.rule.name, "depth": self.depth + 1}}


def _result(action: str, subject: str, outcome: str, detail: str = "") -> dict[str, Any]:
    out = {"action": action, "subject": subject, "outcome": outcome}
    if detail:
        out["detail"] = detail[:500]
    return out


def apply_to_issue(ctx: Context, spec: dict[str, Any], issue: IssueRow) -> dict[str, Any]:
    kind = spec["type"]
    try:
        if kind == "assign":
            changed = assign(ctx.s, issue, spec["to"], actor=ctx.actor,
                             event_extra=ctx.event_extra())  # fmt: skip
            return _result(kind, issue.id, "changed" if changed else "unchanged",
                           f"@{str(spec['to']).lstrip('@')}")  # fmt: skip
        if kind == "set_priority":
            from core.priority.service import set_override

            changed = set_override(ctx.s, issue, spec["band"], actor=ctx.actor, org_id=ctx.org_id,
                                   event_extra=ctx.event_extra())  # fmt: skip
            return _result(kind, issue.id, "changed" if changed else "unchanged", spec["band"])
        if kind == "tag":
            before = tag_service.own(ctx.s, "issue", issue.id)
            wanted = before + [t for t in spec["tags"] if t not in before]
            if wanted == before:
                return _result(kind, issue.id, "unchanged", ", ".join(spec["tags"]))
            tag_service.replace(ctx.s, org_id=ctx.org_id, target_type="issue", target_id=issue.id,
                                names=wanted, actor=ctx.actor)  # fmt: skip
            repo.add_outbox_event(
                ctx.s, org_id=ctx.org_id, event_type="issue.tagged",
                payload={"issue_id": issue.id, "asset_id": issue.asset_id,
                         "added": [t for t in spec["tags"] if t not in before],
                         "by": ctx.actor, **ctx.event_extra()},
            )  # fmt: skip
            ctx.s.commit()
            return _result(kind, issue.id, "changed", ", ".join(spec["tags"]))
        if kind == "request_retest":
            from core.retest.service import RetestError, act

            if issue.retest_status == "requested":
                return _result(kind, issue.id, "unchanged", "already requested")
            try:
                act(ctx.s, issue, "request", actor=ctx.actor, note=spec.get("note") or None,
                    event_extra=ctx.event_extra())  # fmt: skip
            except RetestError as exc:
                return _result(kind, issue.id, "skipped", str(exc))
            return _result(kind, issue.id, "changed")
        if kind == "request_fix":
            return _request_fix(ctx, spec, issue)
        if kind == "group":
            from core.tickets.groups import get_or_create, set_group

            group = get_or_create(ctx.s, ctx.org_id, issue.asset_id, spec["name"], actor=ctx.actor)
            changed = set_group(ctx.s, ctx.org_id, issue, group, actor=ctx.actor)
            return _result(kind, issue.id, "changed" if changed else "unchanged", spec["name"])
        if kind == "ticket":
            from core.tickets.sync import TicketError, file

            try:
                links = file(ctx.s, ctx.org_id, issue, actor=ctx.actor)
            except TicketError as exc:
                return _result(kind, issue.id, "skipped", str(exc))
            return _result(kind, issue.id, "changed", links[0].external_id if links else "")
    except AssignError as exc:
        ctx.s.rollback()
        return _result(kind, issue.id, "failed", str(exc))
    except Exception as exc:  # noqa: BLE001 - one action failing must not stop the others
        ctx.s.rollback()
        log.warning("rule %s action %s failed on %s", ctx.rule.id, kind, issue.id, exc_info=True)
        return _result(kind, issue.id, "failed", f"{type(exc).__name__}: {exc}")
    return _result(kind, issue.id, "skipped", "not an action for an issue")


def _fixes_today(ctx: Context) -> int:
    since = datetime.now(timezone.utc) - timedelta(days=1)
    n = 0
    for results in ctx.s.scalars(
        select(RuleRun.results).where(RuleRun.rule_id == ctx.rule.id, RuleRun.created_at >= since)
    ):
        n += sum(1 for r in results or [] if r.get("action") == "request_fix"
                 and r.get("outcome") == "changed")  # fmt: skip
    return n


def _request_fix(ctx: Context, spec: dict[str, Any], issue: IssueRow) -> dict[str, Any]:
    """Plan §45: "fix requests count against the AI budget." Refused when the organization's
    monthly token budget is spent, or the rule already requested `max_per_day` fixes in the last
    day, or a fix for this Issue is already running."""
    from core.fixagent import store as fixagent_store
    from core.fixagent.start import FixStartError, start
    from core.llm import budget

    cap = int(spec.get("max_per_day") or DEFAULT_FIX_PER_DAY)
    if _fixes_today(ctx) + ctx.fixes_this_run >= cap:
        return _result("request_fix", issue.id, "skipped",
                       f"this rule already requested {cap} fixes in the last day")  # fmt: skip
    try:
        budget.check_org(ctx.s, ctx.org_id)
    except budget.BudgetExceeded as exc:
        return _result("request_fix", issue.id, "skipped", f"AI budget: {exc}")
    latest = fixagent_store.latest_run_for_issue(ctx.s, issue.id, org_id=ctx.org_id)
    terminal = ("approved", "rejected", "opened_pr", "failed", "inconclusive")
    if latest is not None and latest.status not in terminal:
        return _result("request_fix", issue.id, "unchanged", "a fix is already in progress")
    asset = ctx.s.get(Asset, issue.asset_id)
    assert asset is not None
    try:
        started = asyncio.run(start(ctx.s, ctx.org_id, asset, issue.id))
    except FixStartError as exc:
        return _result("request_fix", issue.id, "failed", str(exc))
    ctx.fixes_this_run += 1
    repo.append_audit_entry(  # commits
        ctx.s, actor=ctx.actor, action="issue.fix.requested", target=issue.id,
        payload={"asset_id": issue.asset_id, "run_id": started.run_id},
    )  # fmt: skip
    return _result("request_fix", issue.id, "changed", f"run {started.run_id}")


def notify(
    ctx: Context, spec: dict[str, Any], subjects: list[tuple[str, str]], project: str
) -> dict[str, Any]:
    """One message for the whole run. `subjects` are (id, one-line description)."""
    from core.rules.notify import send_rule_message

    lines = [f"{ctx.rule.name}: {ctx.reason or project}"]
    if spec.get("message"):
        lines.append(str(spec["message"]))
    for _, text in subjects[:10]:
        lines.append(f"• {text}")
    if len(subjects) > 10:
        lines.append(f"…and {len(subjects) - 10} more")
    subject = ",".join(sid for sid, _ in subjects[:50])
    told = 0
    if spec.get("people"):
        from core.collab.assign import AssignError, resolve
        from core.notify.service import notify_people

        actors = []
        for handle in spec["people"]:
            try:
                actors.append(resolve(ctx.s, ctx.org_id, handle).actor)
            except AssignError:
                continue
        first = subjects[0][0] if subjects else None
        issue = ctx.s.get(IssueRow, first) if first else None
        link = f"/app/projects/{issue.asset_id}/issues/{issue.id}" if issue else "/app/automation"
        told = notify_people(ctx.s, ctx.org_id, actors, lines[0][:300], "\n".join(lines[1:]),
                             link, actor=ctx.actor)  # fmt: skip
    try:
        sent = send_rule_message(ctx.s, ctx.org_id, "\n".join(lines))
    except Exception as exc:  # noqa: BLE001
        log.warning("rule %s notify failed", ctx.rule.id, exc_info=True)
        return _result("notify", subject, "failed", f"{type(exc).__name__}: {exc}")
    if told:
        sent = [*sent, f"{told} {'person' if told == 1 else 'people'}"]
    if not sent:
        return _result(
            "notify", subject, "skipped", "no team channel is configured and nobody is named"
        )
    return _result("notify", subject, "changed", f"sent to {', '.join(sent)}")
