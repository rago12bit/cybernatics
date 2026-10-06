"""Risk acceptance: request, four-eyes approval, expiry (plan §44.2, Week 62, ADR-0046).

The rules the server enforces, whatever any screen does:
- A request names one or more open Issues of one project, a decision (accept, mitigate, transfer,
  avoid), a justification and compensating controls (both required), and an expiry no later than
  the policy maximum (90 days by default, `BULWARK_RISK_ACCEPTANCE_MAX_DAYS`).
- The Issues stay open until someone *else* approves: the approver's actor must differ from the
  requester's and be a personal API token -- the shared deployment token is anyone, so it can
  approve nothing. A designated approver, if one was named, is the only one who can.
- An Issue is covered by at most one live acceptance (requested or approved) at a time.
- Approval marks each Issue `accepted` until the expiry; on expiry (the job, or "expire now") they
  reopen, and with `restart_sla` their SLA clock restarts from that moment.
- "Reinstate" undoes an "expire now" within the approved dates only; anything longer is an
  extension, which is a new request that needs its own approval.
- Every state change is a hash-chained audit entry, and an outbox event.

Without user accounts, "someone else" means a different API token: one person holding two tokens
can approve their own request. The ADR records that limit; SSO and SCIM (Week 75) close it.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import (
    ApiToken,
    Asset,
    IssueRow,
    RiskAcceptance,
    RiskAcceptanceIssue,
)

log = logging.getLogger(__name__)

DECISIONS = ("accept", "mitigate", "transfer", "avoid")
LIVE = ("requested", "approved")
OPEN_STATES = ("new", "open", "reintroduced")
SHARED = "shared-token"
MAX_ISSUES = 500
_URL = re.compile(r"^https?://[^\s<>\"']{1,2000}$")


class AcceptanceError(ValueError):
    """A request the rules refuse; `field` names what to fix, `status` the HTTP answer."""

    def __init__(self, message: str, *, field: str | None = None, status: int = 422) -> None:
        super().__init__(message)
        self.field = field
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _text(value: str | None, name: str, label: str, limit: int = 4000) -> str:
    out = " ".join((value or "").split()) if name != "justification" else (value or "").strip()
    if not out:
        raise AcceptanceError(f"{label} is required", field=name)
    return out[:limit]


def issues_of(s: Session, acceptance_id: str) -> list[IssueRow]:
    return list(
        s.scalars(
            select(IssueRow)
            .join(RiskAcceptanceIssue, RiskAcceptanceIssue.issue_id == IssueRow.id)
            .where(RiskAcceptanceIssue.acceptance_id == acceptance_id)
            .order_by(IssueRow.title)
        )
    )


def issue_ids_of(s: Session, acceptance_id: str) -> list[str]:
    return list(
        s.scalars(
            select(RiskAcceptanceIssue.issue_id).where(
                RiskAcceptanceIssue.acceptance_id == acceptance_id
            )
        )
    )


def get(s: Session, acceptance_id: str, org_id: str) -> RiskAcceptance | None:
    return s.scalars(
        select(RiskAcceptance).where(
            RiskAcceptance.id == acceptance_id, RiskAcceptance.org_id == org_id
        )
    ).first()


def list_for(
    s: Session,
    org_id: str,
    *,
    asset_id: str | None = None,
    states: list[str] | None = None,
    issue_id: str | None = None,
    limit: int = 200,
) -> list[RiskAcceptance]:
    q = select(RiskAcceptance).where(RiskAcceptance.org_id == org_id)
    if asset_id:
        q = q.where(RiskAcceptance.asset_id == asset_id)
    if states:
        q = q.where(RiskAcceptance.state.in_(states))
    if issue_id:
        q = q.join(RiskAcceptanceIssue, RiskAcceptanceIssue.acceptance_id == RiskAcceptance.id)
        q = q.where(RiskAcceptanceIssue.issue_id == issue_id)
    return list(s.scalars(q.order_by(RiskAcceptance.requested_at.desc()).limit(limit)))


def approvers(s: Session, org_id: str, *, excluding: str) -> list[dict[str, str]]:
    """Who could approve: the org's live personal tokens that may write, other than the asker."""
    now = _now()
    out = []
    for t in s.scalars(
        select(ApiToken).where(ApiToken.org_id == org_id, ApiToken.revoked_at.is_(None))
    ):
        actor = f"token:{t.display_prefix}"
        if actor == excluding or "scans:write" not in (t.scopes or []):
            continue
        if t.expires_at is not None and _utc(t.expires_at) <= now:
            continue
        out.append({"actor": actor, "name": t.name})
    return sorted(out, key=lambda a: a["name"].lower())


def _audit(s: Session, actor: str, ra: RiskAcceptance, action: str, **extra: Any) -> None:
    ids = issue_ids_of(s, ra.id)
    repo.add_outbox_event(
        s,
        org_id=ra.org_id,
        event_type=f"risk_acceptance.{action}",
        payload={"acceptance_id": ra.id, "asset_id": ra.asset_id, "issue_ids": ids, **extra},
    )
    repo.append_audit_entry(  # commits, with every change staged before it
        s,
        actor=actor,
        action=f"risk_acceptance.{action}",
        target=f"risk_acceptance:{ra.id}",
        payload={
            "org_id": ra.org_id,
            "asset_id": ra.asset_id,
            "issue_ids": ids,
            "state": ra.state,
            "decision": ra.decision,
            "expires_at": _utc(ra.expires_at).isoformat(),
            **extra,
        },
    )


# --- request --------------------------------------------------------------------------------------


def request(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    issue_ids: list[str],
    decision: str,
    justification: str | None,
    controls: str | None,
    proof_links: list[str] | None,
    expires_at: datetime | None,
    restart_sla: bool,
    approver: str | None,
    actor: str,
    max_days: int,
    extends: RiskAcceptance | None = None,
    now: datetime | None = None,
) -> RiskAcceptance:
    now = now or _now()
    if decision not in DECISIONS:
        raise AcceptanceError(f"decision is one of {', '.join(DECISIONS)}", field="decision")
    why = _text(justification, "justification", "A justification")
    ctl = _text(controls, "controls", "Compensating controls")
    links = [str(u).strip() for u in proof_links or [] if str(u).strip()]
    bad = [u for u in links if not _URL.match(u)]
    if bad:
        raise AcceptanceError(f"not a link: {bad[0][:80]}", field="proof_links")
    if len(links) > 20:
        raise AcceptanceError("at most 20 links", field="proof_links")
    if expires_at is None:
        raise AcceptanceError("an expiry date is required", field="expires_at")
    expires = _utc(expires_at)
    if expires <= now:
        raise AcceptanceError("the expiry must be in the future", field="expires_at")
    if expires > now + timedelta(days=max_days, hours=1):
        raise AcceptanceError(
            f"the policy allows at most {max_days} days from today", field="expires_at"
        )
    if approver is not None and approver != "" and approver == actor:
        raise AcceptanceError("the approver must be someone other than you", field="approver")
    ids = list(dict.fromkeys(i for i in issue_ids if i))
    if not ids:
        raise AcceptanceError("choose at least one issue", field="issue_ids")
    if len(ids) > MAX_ISSUES:
        raise AcceptanceError(f"at most {MAX_ISSUES} issues at once", field="issue_ids")
    rows = {
        i.id: i
        for i in s.scalars(
            select(IssueRow)
            .join(Asset, Asset.id == IssueRow.asset_id)
            .where(IssueRow.id.in_(ids), Asset.org_id == org_id, IssueRow.asset_id == asset_id)
        )
    }
    missing = [i for i in ids if i not in rows]
    if missing:
        raise AcceptanceError(
            f"{len(missing)} issue(s) are not in this project", field="issue_ids", status=404
        )
    closed = [r.title for r in rows.values() if r.state not in OPEN_STATES]
    if closed and extends is None:
        raise AcceptanceError(f"already fixed: {closed[0][:120]}", field="issue_ids")
    taken = [
        (i, a)
        for i, a in s.execute(
            select(RiskAcceptanceIssue.issue_id, RiskAcceptance.id)
            .join(RiskAcceptance, RiskAcceptance.id == RiskAcceptanceIssue.acceptance_id)
            .where(RiskAcceptanceIssue.issue_id.in_(ids), RiskAcceptance.state.in_(LIVE))
        )
        if extends is None or a != extends.id
    ]
    if taken:
        raise AcceptanceError(
            f"{len(taken)} issue(s) are already covered by a risk acceptance",
            field="issue_ids",
            status=409,
        )
    ra = RiskAcceptance(
        org_id=org_id,
        asset_id=asset_id,
        decision=decision,
        justification=why,
        controls=ctl,
        proof_links=links,
        expires_at=expires,
        restart_sla=restart_sla,
        state="requested",
        requested_by=actor,
        requested_at=now,
        approver=approver or None,
        extends_id=extends.id if extends else None,
        legacy=False,
    )
    s.add(ra)
    s.flush()
    for i in ids:
        s.add(RiskAcceptanceIssue(acceptance_id=ra.id, issue_id=i, org_id=org_id))
    s.flush()
    _audit(s, actor, ra, "requested", extends=extends.id if extends else None)
    return ra


def extend(
    s: Session,
    ra: RiskAcceptance,
    *,
    expires_at: datetime | None,
    justification: str | None,
    actor: str,
    max_days: int,
) -> RiskAcceptance:
    """A new request for the same Issues and a later expiry; the current one runs until approved."""
    if ra.state != "approved":
        raise AcceptanceError("only an approved acceptance can be extended", status=409)
    if expires_at is not None and _utc(expires_at) <= _utc(ra.expires_at):
        raise AcceptanceError("an extension ends later than now", field="expires_at")
    return request(
        s,
        org_id=ra.org_id,
        asset_id=ra.asset_id,
        issue_ids=issue_ids_of(s, ra.id),
        decision=ra.decision,
        justification=justification or ra.justification,
        controls=ra.controls,
        proof_links=list(ra.proof_links or []),
        expires_at=expires_at,
        restart_sla=ra.restart_sla,
        approver=None,
        actor=actor,
        max_days=max_days,
        extends=ra,
    )


# --- decisions ------------------------------------------------------------------------------------


def _decider(ra: RiskAcceptance, actor: str) -> None:
    if ra.state != "requested":
        raise AcceptanceError(f"this request is {ra.state}, not waiting for approval", status=409)
    if actor == SHARED:
        raise AcceptanceError(
            "approving needs a personal API token: the shared token could be anyone",
            status=403,
        )
    if actor == ra.requested_by:
        raise AcceptanceError(
            "you requested this; someone else has to approve or reject it", status=403
        )
    if ra.approver and actor != ra.approver:
        raise AcceptanceError(f"this request asked {ra.approver} to decide", status=403)


def _accept_issues(s: Session, ra: RiskAcceptance, actor: str, now: datetime) -> None:
    reason = f"Risk acceptance ({ra.decision}): {ra.justification}"[:2000]
    for issue in issues_of(s, ra.id):
        issue.triage_status = "accepted"
        issue.triage_reason = reason
        issue.triage_expires_at = ra.expires_at
        issue.triaged_at, issue.triaged_by = now, actor


def approve(
    s: Session, ra: RiskAcceptance, *, actor: str, note: str | None, now: datetime | None = None
) -> RiskAcceptance:
    now = now or _now()
    _decider(ra, actor)
    if _utc(ra.expires_at) <= now:
        raise AcceptanceError("this request's expiry has passed; ask for a new one", status=409)
    ra.state, ra.decided_by, ra.decided_at = "approved", actor, now
    ra.decision_note = " ".join((note or "").split())[:2000] or None
    _accept_issues(s, ra, actor, now)
    if ra.extends_id:
        parent = s.get(RiskAcceptance, ra.extends_id)
        if parent is not None and parent.state == "approved":
            parent.state, parent.ended_at, parent.ended_by = "extended", now, actor
            parent.ended_reason = "extended"
    _audit(s, actor, ra, "approved")
    return ra


def reject(
    s: Session, ra: RiskAcceptance, *, actor: str, note: str | None, now: datetime | None = None
) -> RiskAcceptance:
    _decider(ra, actor)
    why = " ".join((note or "").split())
    if not why:
        raise AcceptanceError("say why it is rejected", field="note")
    ra.state, ra.decided_by, ra.decided_at = "rejected", actor, now or _now()
    ra.decision_note = why[:2000]
    _audit(s, actor, ra, "rejected")
    return ra


def withdraw(s: Session, ra: RiskAcceptance, *, actor: str) -> RiskAcceptance:
    if ra.state != "requested":
        raise AcceptanceError(f"this request is {ra.state}", status=409)
    if actor != ra.requested_by:
        raise AcceptanceError("only the requester can withdraw a request", status=403)
    ra.state, ra.ended_at, ra.ended_by, ra.ended_reason = "withdrawn", _now(), actor, "withdrawn"
    _audit(s, actor, ra, "withdrawn")
    return ra


def _end(s: Session, ra: RiskAcceptance, *, actor: str, reason: str, now: datetime) -> None:
    ra.state, ra.ended_at, ra.ended_by, ra.ended_reason = "expired", now, actor, reason
    for issue in issues_of(s, ra.id):
        if issue.triage_status != "accepted":
            continue  # someone reopened it already
        issue.triage_status, issue.triage_reason, issue.triage_expires_at = "open", None, None
        issue.triaged_at, issue.triaged_by = now, actor
        if ra.restart_sla:
            issue.sla_started_at, issue.sla_notified = now, None


def expire_now(
    s: Session, ra: RiskAcceptance, *, actor: str, now: datetime | None = None
) -> RiskAcceptance:
    if ra.state != "approved":
        raise AcceptanceError(f"this acceptance is {ra.state}, not approved", status=409)
    _end(s, ra, actor=actor, reason="expire_now", now=now or _now())
    _audit(s, actor, ra, "expired", reason="expire_now")
    return ra


def reinstate(
    s: Session, ra: RiskAcceptance, *, actor: str, now: datetime | None = None
) -> RiskAcceptance:
    """Undo an "expire now", inside the dates that were approved; no new approval needed."""
    now = now or _now()
    if ra.state != "expired" or ra.ended_reason != "expire_now":
        raise AcceptanceError("only an acceptance expired early can be reinstated", status=409)
    if _utc(ra.expires_at) <= now:
        raise AcceptanceError("its approved dates have passed; request an extension", status=409)
    others = s.execute(
        select(RiskAcceptanceIssue.issue_id)
        .join(RiskAcceptance, RiskAcceptance.id == RiskAcceptanceIssue.acceptance_id)
        .where(
            RiskAcceptanceIssue.issue_id.in_(issue_ids_of(s, ra.id)),
            RiskAcceptance.state.in_(LIVE),
            RiskAcceptance.id != ra.id,
        )
    ).all()
    if others:
        raise AcceptanceError("some of its issues are covered by another acceptance", status=409)
    ra.state, ra.ended_at, ra.ended_by, ra.ended_reason = "approved", None, None, None
    _accept_issues(s, ra, actor, now)
    _audit(s, actor, ra, "reinstated")
    return ra


# --- the expiry job -------------------------------------------------------------------------------


@dataclass
class ExpiryResult:
    expired: list[RiskAcceptance]


Notifier = Callable[[Session, str, str, RiskAcceptance], None]


def expire_due(
    s: Session, org_id: str, *, now: datetime | None = None, notify: Notifier | None = None
) -> ExpiryResult:
    """End every approved acceptance of the org whose date has come: its Issues reopen (and their
    SLA restarts, if asked). A pending request whose date passed can no longer be approved, so it
    lapses too."""
    now = now or _now()
    notify = notify if notify is not None else notify_integrations
    out = ExpiryResult([])
    due = list(
        s.scalars(
            select(RiskAcceptance).where(
                RiskAcceptance.org_id == org_id,
                RiskAcceptance.state.in_(LIVE),
                RiskAcceptance.expires_at <= now,
            )
        )
    )
    for ra in due:
        if ra.state == "requested":
            ra.state, ra.ended_at, ra.ended_by, ra.ended_reason = (
                "withdrawn", now, "system", "lapsed",
            )  # fmt: skip
            _audit(s, "system", ra, "lapsed")
            continue
        _end(s, ra, actor="system", reason="expiry", now=now)
        _audit(s, "system", ra, "expired", reason="expiry")
        out.expired.append(ra)
        try:
            notify(s, org_id, "expired", ra)
        except Exception:  # noqa: BLE001 - a dying notification must not stop expiry
            log.warning("risk acceptance notification failed", exc_info=True)
    return out


EXPIRY_WARNING = timedelta(days=7)


def warn_expiring(s: Session, org_id: str, *, now: datetime | None = None) -> int:
    """Announce, once each, the approved acceptances whose date is within seven days (an outbox
    event for rules, plan §45). An extension is a new acceptance, so it is announced afresh."""
    now = now or _now()
    n = 0
    for ra in s.scalars(
        select(RiskAcceptance).where(
            RiskAcceptance.org_id == org_id,
            RiskAcceptance.state == "approved",
            RiskAcceptance.expiry_warned_at.is_(None),
            RiskAcceptance.expires_at > now,
            RiskAcceptance.expires_at <= now + EXPIRY_WARNING,
        )
    ):
        ra.expiry_warned_at = now
        repo.add_outbox_event(
            s, org_id=org_id, event_type="risk_acceptance.expiring",
            payload={"acceptance_id": ra.id, "asset_id": ra.asset_id,
                     "issue_ids": issue_ids_of(s, ra.id),
                     "expires_at": _utc(ra.expires_at).isoformat()},
        )  # fmt: skip
        n += 1
    s.commit()
    return n


# --- notifications --------------------------------------------------------------------------------


def message(event: str, ra: RiskAcceptance, project: str, count: int) -> str:
    n = f"{count} issue{'s' if count != 1 else ''}"
    if event == "requested":
        who = ra.approver or "someone other than the requester"
        return (
            f"🛡️ Risk acceptance requested for {n} in *{project}* by {ra.requested_by}: "
            f"{ra.decision}, until {_utc(ra.expires_at):%d %b %Y}. Waiting for {who}."
        )
    if event == "approved":
        return (
            f"✅ Risk acceptance approved by {ra.decided_by} for {n} in *{project}*, "
            f"until {_utc(ra.expires_at):%d %b %Y}."
        )
    if event == "rejected":
        return f"✋ Risk acceptance for {n} in *{project}* rejected by {ra.decided_by}."
    return f"⏰ Risk acceptance for {n} in *{project}* expired; the issues are open again."


def notify_integrations(s: Session, org_id: str, event: str, ra: RiskAcceptance) -> None:
    from core.integrations import discord, slack

    settings = repo.get_integration_settings(s, org_id)
    if settings is None:
        return
    asset = s.get(Asset, ra.asset_id)
    text = message(event, ra, asset.label if asset else ra.asset_id, len(issue_ids_of(s, ra.id)))
    if settings.slack_webhook_url:
        try:
            slack.send(settings.slack_webhook_url, {"text": text})
        except Exception:  # noqa: BLE001
            log.warning("slack risk-acceptance notification failed", exc_info=True)
    if settings.discord_webhook_url:
        try:
            discord.send(settings.discord_webhook_url, {"content": text.replace("*", "**")})
        except Exception:  # noqa: BLE001
            log.warning("discord risk-acceptance notification failed", exc_info=True)
