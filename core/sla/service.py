"""SLA policies, each Issue's SLA, and the sweep that announces crossings (plan §44.1, Week 61).

The deadline is never stored: it is computed from the policy in force, the Issue's severity and its
clock, so changing a policy or a severity moves every deadline at once and nothing can drift. What
is stored per Issue is only the last state announced (`sla_notified`), so the sweep announces each
crossing into "due soon" or "breached" once -- as an outbox event (for rules, plan §45) and as one
message per project to the organization's Slack, Discord and outbound webhook.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import ColumnElement, and_, false, func, or_, select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import Asset, IssueRow, SlaPolicy
from core.sla.policy import (
    BASES,
    OPEN_SLA,
    OPEN_STATES,
    STARTER_POLICY,
    Policy,
    PolicyError,
    Status,
    evaluate,
    from_row,
    parse_bands,
)

log = logging.getLogger(__name__)
ANNOUNCED = ("due_soon", "breached")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- policies -------------------------------------------------------------------------------------


def current(s: Session, asset_id: str) -> SlaPolicy | None:
    return s.scalars(
        select(SlaPolicy)
        .where(SlaPolicy.asset_id == asset_id)
        .order_by(SlaPolicy.version.desc())
        .limit(1)
    ).first()


def policies_for(s: Session, asset_ids: list[str]) -> dict[str, Policy]:
    """Each project's policy in force, in one query (projects without one get the starter)."""
    out = {a: STARTER_POLICY for a in asset_ids}
    if not asset_ids:
        return out
    latest = (
        select(SlaPolicy.asset_id, func.max(SlaPolicy.version).label("v"))
        .where(SlaPolicy.asset_id.in_(asset_ids))
        .group_by(SlaPolicy.asset_id)
        .subquery()
    )
    rows = s.scalars(
        select(SlaPolicy).join(
            latest, and_(SlaPolicy.asset_id == latest.c.asset_id, SlaPolicy.version == latest.c.v)
        )
    )
    for row in rows:
        out[row.asset_id] = from_row(row.enabled, row.basis, row.bands)
    return out


def policy_for(s: Session, asset_id: str) -> Policy:
    row = current(s, asset_id)
    return from_row(row.enabled, row.basis, row.bands) if row is not None else STARTER_POLICY


def history(s: Session, asset_id: str, limit: int = 50) -> list[SlaPolicy]:
    return list(
        s.scalars(
            select(SlaPolicy)
            .where(SlaPolicy.asset_id == asset_id)
            .order_by(SlaPolicy.version.desc())
            .limit(limit)
        )
    )


def save(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    enabled: bool,
    bands: Any,
    basis: str = "severity",
    note: str | None = None,
    actor: str,
) -> SlaPolicy:
    """A new version of the project's policy, audit-logged. Saving does not announce anything by
    itself; the next sweep does, once per Issue that the new policy puts due soon or breached."""
    if basis not in BASES:
        raise PolicyError("basis", "the basis is severity or priority")
    parsed = parse_bands(bands, basis)
    if enabled and not any(b.days for b in parsed.values()):
        what = "priority band" if basis == "priority" else "severity"
        raise PolicyError("bands", f"an SLA needs a deadline for at least one {what}")
    prev = current(s, asset_id)
    row = SlaPolicy(
        org_id=org_id,
        asset_id=asset_id,
        version=(prev.version + 1) if prev else 1,
        enabled=enabled,
        basis=basis,
        bands=Policy(enabled, basis, parsed).to_dict()["bands"],
        note=" ".join(note.split())[:500] if note else None,
        created_by=actor,
    )
    s.add(row)
    s.flush()
    repo.append_audit_entry(  # commits, with the policy row
        s,
        actor=actor,
        action="sla.policy.changed",
        target=f"asset:{asset_id}",
        payload={
            "org_id": org_id,
            "version": row.version,
            "enabled": enabled,
            "basis": basis,
            "bands": row.bands,
        },
    )
    return row


# --- each Issue's SLA -----------------------------------------------------------------------------


def status_of(policy: Policy, issue: IssueRow, now: datetime | None = None) -> Status:
    return evaluate(
        policy,
        severity=issue.severity,
        priority_band=issue.priority_override or issue.priority_band,
        state=issue.state,
        first_seen_at=issue.first_seen_at,
        sla_started_at=issue.sla_started_at,
        fixed_at=issue.fixed_at,
        triage_status=issue.triage_status,
        triage_expires_at=issue.triage_expires_at,
        now=now or _now(),
    )


def _active(now: datetime) -> ColumnElement[bool]:
    return or_(
        IssueRow.triage_status == "open",
        and_(
            IssueRow.triage_status == "accepted",
            IssueRow.triage_expires_at.is_not(None),
            IssueRow.triage_expires_at <= now,
        ),
    )


def clause(policy: Policy, states: list[str], now: datetime) -> ColumnElement[bool]:
    """SQL for "the Issue's SLA state is one of `states`" (open states only), so the issues table
    can filter by SLA without loading every Issue."""
    wanted = [x for x in states if x in OPEN_SLA]
    if not policy.enabled or not wanted:
        return false()
    start = func.coalesce(IssueRow.sla_started_at, IssueRow.first_seen_at)
    key = (
        func.coalesce(IssueRow.priority_override, IssueRow.priority_band)
        if policy.basis == "priority"
        else IssueRow.severity
    )
    per_band = []
    for name, band in policy.bands.items():
        if band.days is None:
            continue
        due_by = now - timedelta(days=band.days)  # started at or before this: breached
        warn_by = now - timedelta(days=band.days - band.warn)  # ...or this: due soon
        parts = []
        if "breached" in wanted:
            parts.append(start <= due_by)
        if "due_soon" in wanted:
            parts.append(and_(start > due_by, start <= warn_by))
        if "on_track" in wanted:
            parts.append(start > warn_by)
        per_band.append(and_(key == name, or_(*parts)))
    if not per_band:
        return false()
    return and_(IssueRow.state.in_(OPEN_STATES), _active(now), or_(*per_band))


def summary(s: Session, asset_id: str, now: datetime | None = None) -> dict[str, int]:
    """How many of the project's Issues are in each SLA state (open ones, plus fixed met/missed)."""
    now = now or _now()
    policy = policy_for(s, asset_id)
    counts = dict.fromkeys(("on_track", "due_soon", "breached", "exempt", "met", "missed"), 0)
    if not policy.enabled:
        return counts
    for issue in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id)):
        st = status_of(policy, issue, now).state
        if st in counts:
            counts[st] += 1
    return counts


def annotate(
    s: Session, asset_id: str, items: list[dict[str, Any]], now: datetime | None = None
) -> None:
    """Add `issue.sla` ({state, due_at, started_at, days}) to finding dicts that carry an Issue."""
    ids = [d["issue"]["id"] for d in items if d.get("issue")]
    if not ids:
        return
    policy = policy_for(s, asset_id)
    rows = {i.id: i for i in s.scalars(select(IssueRow).where(IssueRow.id.in_(ids)))}
    for d in items:
        issue = d.get("issue")
        row = rows.get(issue["id"]) if issue else None
        if issue is not None:
            issue["sla"] = (status_of(policy, row, now) if row else Status("none")).to_dict()


# --- the sweep ------------------------------------------------------------------------------------


@dataclass
class Crossing:
    issue_id: str
    title: str
    severity: str
    state: str
    due_at: datetime


@dataclass
class SweepResult:
    crossings: dict[str, list[Crossing]] = field(default_factory=dict)  # by asset id
    cleared: int = 0

    @property
    def announced(self) -> int:
        return sum(len(v) for v in self.crossings.values())


Notifier = Callable[[Session, str, str, list[Crossing]], None]


def sweep(
    s: Session, org_id: str, *, now: datetime | None = None, notify: Notifier | None = None
) -> SweepResult:
    """Announce every Issue of the org that crossed into due soon or breached since the last sweep,
    once each; forget the announcement when an Issue leaves those states (fixed, triaged away,
    deadline moved), so a later crossing is announced again."""
    now = now or _now()
    notify = notify if notify is not None else notify_integrations
    out = SweepResult()
    assets = list(s.scalars(select(Asset).where(Asset.org_id == org_id)))
    for asset in assets:
        policy = policy_for(s, asset.id)
        found: list[Crossing] = []
        issues = s.scalars(
            select(IssueRow).where(
                IssueRow.asset_id == asset.id,
                or_(IssueRow.state.in_(OPEN_STATES), IssueRow.sla_notified.is_not(None)),
            )
        )
        for issue in issues:
            st = status_of(policy, issue, now)
            new = st.state if st.state in ANNOUNCED else None
            if new == issue.sla_notified:
                continue
            issue.sla_notified, issue.sla_notified_at = new, now
            if new is None:
                out.cleared += 1
                continue
            assert st.due_at is not None
            c = Crossing(issue.id, issue.title, issue.severity, new, st.due_at)
            found.append(c)
            repo.add_outbox_event(
                s,
                org_id=org_id,
                event_type=f"sla.{new}",
                payload={
                    "issue_id": issue.id,
                    "asset_id": asset.id,
                    "severity": issue.severity,
                    "title": issue.title[:300],
                    "due_at": st.due_at.isoformat(),
                },
            )
        s.commit()
        if found:
            out.crossings[asset.id] = found
            try:
                notify(s, org_id, asset.label, found)
            except Exception:  # noqa: BLE001 - a dying notification must not stop the sweep
                log.warning("SLA notification failed for asset %s", asset.id, exc_info=True)
    return out


# --- notifications --------------------------------------------------------------------------------


def message(project: str, crossings: list[Crossing], now: datetime | None = None) -> str:
    """One line for the project, then the most urgent few."""
    now = now or _now()
    breached = [c for c in crossings if c.state == "breached"]
    soon = [c for c in crossings if c.state == "due_soon"]
    parts = []
    if breached:
        parts.append(f"{len(breached)} breached")
    if soon:
        parts.append(f"{len(soon)} due soon")
    lines = [f"⏰ Bulwark SLA for *{project}*: {', '.join(parts)}."]
    for c in sorted(crossings, key=lambda c: c.due_at)[:5]:
        when = _relative(c.due_at, now)
        lines.append(f"• {c.severity.title()}: {c.title[:120]} -- {when}")
    if len(crossings) > 5:
        lines.append(f"…and {len(crossings) - 5} more.")
    return "\n".join(lines)


def _relative(due: datetime, now: datetime) -> str:
    days = (due - now).total_seconds() / 86400
    if days < 0:
        n = max(int(-days), 1) if -days >= 1 else 0
        return f"overdue by {n} day{'s' if n != 1 else ''}" if n else "overdue since today"
    n = int(days)
    return f"due in {n} day{'s' if n != 1 else ''}" if n else "due today"


def notify_integrations(s: Session, org_id: str, project: str, crossings: list[Crossing]) -> None:
    """Send to every channel the organization configured; one channel failing does not stop the
    others (the same rule as scan notifications, `core.integrations.dispatch`)."""
    from core.integrations import discord, slack
    from core.integrations.webhooks import deliver_signed
    from core.notify import team

    settings = repo.get_integration_settings(s, org_id)
    if settings is None:
        return
    text = message(project, crossings)
    if not team.gate(s, org_id, "sla", text):  # Week 66: the team's choice -- digest, or off
        return
    team.send_teams(s, org_id, text.replace("*", ""))
    if settings.slack_webhook_url:
        try:
            slack.send(settings.slack_webhook_url, {"text": text})
        except Exception:  # noqa: BLE001
            log.warning("slack SLA notification failed", exc_info=True)
    if settings.discord_webhook_url:
        try:
            discord.send(settings.discord_webhook_url, {"content": text.replace("*", "**")})
        except Exception:  # noqa: BLE001
            log.warning("discord SLA notification failed", exc_info=True)
    if settings.outbound_webhook_url and settings.outbound_webhook_secret:
        try:
            deliver_signed(
                settings.outbound_webhook_url,
                {
                    "type": "sla.changed",
                    "project": project,
                    "issues": [
                        {"id": c.issue_id, "title": c.title[:300], "severity": c.severity,
                         "state": c.state, "due_at": c.due_at.isoformat()}
                        for c in crossings
                    ],
                },  # fmt: skip
                settings.outbound_webhook_secret,
            )
        except Exception:  # noqa: BLE001
            log.warning("outbound SLA webhook failed", exc_info=True)
