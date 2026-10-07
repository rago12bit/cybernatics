"""Notifications for people (plan §49): watchers, the inbox, email, and the daily digest.

The outbox dispatcher hands every batch of events to `on_events`, which works out who should hear
about each one and how each of them asked to:
- `note.mentioned` -- the person mentioned;
- `issue.note_added` -- the Issue's watchers, except the author and anyone the note mentions;
- `issue.assigned` -- the new assignee (unless they assigned themselves);
- `issue.retest_*` -- the watchers, except whoever acted;
- `sla.due_soon`, `sla.breached` -- the assignee and the watchers;
- `risk_acceptance.*` -- the named approver when one is asked, the requester when it is decided,
  expiring or expired;
- `rule.held` -- every person who can confirm it (a live token with `rules:write`);
- `issue.ticket_status` -- the watchers.
Watching follows from taking part: being assigned, mentioned, writing a note, asking for a retest.

Each notification is written once per (person, event, kind), so a redelivered batch never notifies
twice. In-app is the inbox; email goes now, or into the daily digest at the person's hour (UTC), or
not at all. Text is plain everywhere: the inbox renders it as text and email is text/plain.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from core.collab.people import names as people_names
from core.notify import email as mail
from core.notify import prefs as prefs_service
from core.notify.kinds import PERSON_KINDS, TEAM_KINDS, TEAM_OWNER
from core.persistence import repo
from core.persistence.models import (
    Asset,
    IssueNote,
    IssueRow,
    IssueWatcher,
    Notification,
    NotificationPrefs,
    RiskAcceptance,
)

log = logging.getLogger(__name__)
INBOX_PAGE = 50


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _person(actor: str | None) -> bool:
    from core.collab.people import is_person

    return is_person(actor)


# --- watchers -------------------------------------------------------------------------------------


def watchers(s: Session, issue_id: str) -> list[IssueWatcher]:
    return list(
        s.scalars(
            select(IssueWatcher)
            .where(IssueWatcher.issue_id == issue_id)
            .order_by(IssueWatcher.created_at)
        )
    )


def watch(s: Session, org_id: str, issue_id: str, actor: str, reason: str = "manual") -> bool:
    """Idempotent; returns True when the person was not watching yet. Does not commit."""
    if not _person(actor):
        return False
    exists = s.scalar(
        select(IssueWatcher.id).where(
            IssueWatcher.issue_id == issue_id, IssueWatcher.actor == actor
        )
    )
    if exists:
        return False
    s.add(IssueWatcher(org_id=org_id, issue_id=issue_id, actor=actor, reason=reason))
    s.flush()
    return True


def unwatch(s: Session, issue_id: str, actor: str) -> bool:
    row = s.scalars(
        select(IssueWatcher).where(IssueWatcher.issue_id == issue_id, IssueWatcher.actor == actor)
    ).one_or_none()
    if row is None:
        return False
    s.delete(row)
    s.commit()
    return True


# --- writing a notification -----------------------------------------------------------------------


@dataclass
class Message:
    kind: str
    recipients: list[str]
    title: str
    body: str | None = None
    link: str | None = None
    issue_id: str | None = None
    actor: str | None = None


def deliver(
    s: Session,
    org_id: str,
    msg: Message,
    event_type: str,
    event_id: int | None,
    *,
    smtp: mail.SmtpConfig | None = None,
) -> list[Notification]:
    """One notification per recipient, as each recipient asked. Skips anyone who already has one
    for this event and kind, and the person who caused it."""
    out: list[Notification] = []
    cfg = smtp if smtp is not None else mail.SmtpConfig.from_env()
    # A title is one line wherever it goes: an issue title with a line break in it cannot start a
    # line of its own in an email or a digest.
    title = " ".join(msg.title.split())
    for who in dict.fromkeys(msg.recipients):
        if not _person(who) or who == msg.actor:
            continue
        if event_id is not None and s.scalar(
            select(Notification.id).where(
                Notification.recipient == who,
                Notification.event_id == event_id,
                Notification.kind == msg.kind,
            )
        ):
            continue
        p = prefs_service.get(s, org_id, who)
        in_app = prefs_service.mode(p, msg.kind, "in_app") == "instant"
        email_mode = prefs_service.mode(p, msg.kind, "email")
        email_state: str | None = None
        if email_mode != "off" and p is not None and p.email:
            email_state = "pending"
        if not in_app and email_state is None:
            continue
        n = Notification(
            org_id=org_id,
            recipient=who,
            kind=msg.kind,
            event_type=event_type,
            event_id=event_id,
            title=title[:500],
            body=(msg.body or "")[:4000] or None,
            link=msg.link,
            issue_id=msg.issue_id,
            actor=msg.actor,
            in_app=in_app,
            email_state=email_state,
        )
        s.add(n)
        s.flush()
        if email_state == "pending" and email_mode == "instant" and p is not None and p.email:
            _send_now(cfg, n, p.email)
        out.append(n)
    s.commit()
    return out


def _footer(link: str | None) -> str:
    base = mail_base_url()
    return f"\n\nOpen it: {base}{link}" if link and base else ""


def mail_base_url() -> str:
    import os

    return os.environ.get("BULWARK_PUBLIC_URL", "").rstrip("/")


def _send_now(cfg: mail.SmtpConfig | None, n: Notification, to: str) -> None:
    if cfg is None:
        n.email_state = "skipped"
        return
    try:
        mail.send(cfg, to, f"[Bulwark] {n.title}", f"{n.title}\n\n{n.body or ''}{_footer(n.link)}")
        n.email_state, n.emailed_at = "sent", _now()
    except Exception:  # noqa: BLE001 - the inbox still has it; email is best effort
        log.warning("notification email failed", exc_info=True)
        n.email_state = "failed"


# --- from events ----------------------------------------------------------------------------------


class _Ctx:
    def __init__(self, s: Session, org_id: str) -> None:
        self.s, self.org_id = s, org_id
        self._names: dict[str, str] = {}

    def name(self, actor: str | None) -> str:
        if not actor:
            return "Someone"
        if actor.startswith("ticket:"):
            return f"Its ticket, {actor.split(':', 1)[1]}"
        if actor.startswith("rule:"):
            from core.persistence.models import AutomationRule

            rule = self.s.get(AutomationRule, actor.split(":", 1)[1])
            return f"The rule “{rule.name}”" if rule else "A rule"
        if actor not in self._names:
            self._names.update(people_names(self.s, self.org_id, {actor}))
        return self._names.get(actor, "A scan" if actor.startswith("the scan") else actor)

    def issue(self, issue_id: str | None) -> IssueRow | None:
        return self.s.get(IssueRow, issue_id) if issue_id else None


def _project(s: Session, issue: IssueRow) -> str:
    asset = s.get(Asset, issue.asset_id)
    return asset.label if asset else "its project"


def _advisory_messages(c: _Ctx, p: dict[str, Any]) -> list[Message]:
    """A vulnerability affects the organization for the first time (plan §46.2): the team channels
    hear it, and so does each affected project's owner."""
    from core.advisories.view import header
    from core.persistence.models import Advisory as AdvisoryRecord
    from core.rules.notify import send_rule_message

    vk = str(p.get("vuln_key", ""))[:100]
    records = list(c.s.scalars(select(AdvisoryRecord).where(AdvisoryRecord.vuln_key == vk)))
    if not vk or not records:
        return []
    h = header(c.s, vk, records)
    n = int(p.get("projects") or 0)
    kev = " Known exploited (CISA KEV)." if h["kev"] else ""
    title = f"{vk} ({h['severity'].title()}) affects {n} project{'s' if n != 1 else ''}"
    body = f"{h['summary'][:300]}.{kev}"
    link = f"/app/advisories/{vk}"
    base = mail_base_url()
    try:
        send_rule_message(
            c.s, c.org_id, f"New advisory: {title}. {body} {base}{link}", kind="advisory"
        )
    except Exception:  # noqa: BLE001 - the team channels failing must not stop the owners' notes
        log.warning("advisory team notification failed", exc_info=True)
    owners = [str(o) for o in p.get("owners") or []]
    return (
        [Message("advisory", owners, f"New advisory: {title}", body, link, None, None)]
        if owners
        else []
    )


def _link(issue: IssueRow) -> str:
    return f"/app/projects/{issue.asset_id}/issues/{issue.id}"


def _watchers_of(s: Session, issue_id: str) -> list[str]:
    return [w.actor for w in watchers(s, issue_id)]


def _admins(s: Session, org_id: str) -> list[str]:
    from core.collab.people import people_who_can

    return [p.actor for p in people_who_can(s, org_id, "rules:write")]


def _messages(c: _Ctx, etype: str, p: dict[str, Any]) -> list[Message]:  # noqa: C901 - one table
    s, org = c.s, c.org_id
    issue = c.issue(p.get("issue_id"))
    title = f"“{issue.title[:150]}”" if issue else "an issue"
    link = _link(issue) if issue else None
    iid = issue.id if issue else None
    by = p.get("by")

    if etype == "note.mentioned" and issue:
        watch(s, org, issue.id, p.get("mentioned", ""), "mentioned")
        note = s.get(IssueNote, p.get("note_id")) if p.get("note_id") else None
        return [
            Message(
                "mention",
                [p.get("mentioned", "")],
                f"{c.name(by)} mentioned you on {title}",
                note.body[:600] if note and note.body else None,
                link,
                iid,
                by,
            )
        ]
    if etype == "issue.note_added" and issue:
        watch(s, org, issue.id, by or "", "note")
        skip = set(p.get("mentioned") or [])
        note = s.get(IssueNote, p.get("note_id")) if p.get("note_id") else None
        to = [w for w in _watchers_of(s, issue.id) if w not in skip]
        return [
            Message(
                "note",
                to,
                f"{c.name(by)} wrote a note on {title}",
                note.body[:600] if note and note.body else None,
                link,
                iid,
                by,
            )
        ]
    if etype == "issue.assigned" and issue and p.get("assignee"):
        watch(s, org, issue.id, p["assignee"], "assignee")
        return [
            Message(
                "assigned",
                [p["assignee"]],
                f"{c.name(by)} assigned {title} to you",
                f"{issue.severity.title()} in {_project(s, issue)}.",
                link,
                iid,
                by,
            )
        ]
    if etype.startswith("issue.retest_") and issue:
        if str(by or "").startswith("ticket:"):
            return []  # the ticket's own status notification already says so
        what = etype.removeprefix("issue.retest_")
        if what == "requested":
            watch(s, org, issue.id, by or "", "retest")
        words = {
            "requested": "marked ready for retest",
            "passed": "passed its retest",
            "failed": "failed its retest",
            "cancelled": "had its retest request cancelled",
        }
        detail = p.get("detail")
        line = f"{title} {words.get(what, what)}" + (
            f" ({c.name(by)})" if what == "requested" else ""
        )
        return [
            Message(
                "retest",
                _watchers_of(s, issue.id),
                line[0].upper() + line[1:],
                detail,
                link,
                iid,
                by if _person(by) else None,
            )
        ]
    if etype in ("sla.due_soon", "sla.breached") and issue:
        word = "is due soon" if etype == "sla.due_soon" else "breached its SLA"
        to = ([issue.assignee] if issue.assignee else []) + _watchers_of(s, issue.id)
        due = str(p.get("due_at", ""))[:10]
        return [
            Message(
                "sla", to, f"{title} {word}", f"Due {due} (UTC)." if due else None, link, iid, None
            )
        ]
    if etype.startswith("risk_acceptance."):
        ra = s.get(RiskAcceptance, p.get("acceptance_id")) if p.get("acceptance_id") else None
        if ra is None:
            return []
        what = etype.split(".", 1)[1]
        n = len(p.get("issue_ids") or [])
        what_n = f"{n} issue{'s' if n != 1 else ''}"
        link_ra = f"/app/risk-acceptances/{ra.id}"
        if what == "requested" and ra.approver:
            return [
                Message(
                    "risk_acceptance",
                    [ra.approver],
                    f"{c.name(ra.requested_by)} asks you to approve accepting the risk of {what_n}",
                    ra.justification[:600],
                    link_ra,
                    None,
                    ra.requested_by,
                )
            ]
        if what in ("approved", "rejected"):
            return [
                Message(
                    "risk_acceptance",
                    [ra.requested_by],
                    f"{c.name(ra.decided_by)} {what} your risk acceptance for {what_n}",
                    ra.decision_note,
                    link_ra,
                    None,
                    ra.decided_by,
                )
            ]
        if what in ("expiring", "expired"):
            word = (
                "expires within 7 days"
                if what == "expiring"
                else "has expired; the issues are open"
            )
            return [
                Message(
                    "risk_acceptance",
                    [ra.requested_by],
                    f"Your risk acceptance for {what_n} {word}",
                    None,
                    link_ra,
                    None,
                    None,
                )
            ]
        return []
    if etype == "rule.held":
        return [
            Message(
                "rules",
                _admins(s, org),
                f"The rule “{str(p.get('name', ''))[:100]}” waits for confirmation: "
                f"{p.get('count')} issues",
                None,
                "/app/automation",
                None,
                None,
            )
        ]
    if etype == "advisory.matched":
        return _advisory_messages(c, p)
    if etype == "issue.ticket_status" and issue:
        return [
            Message(
                "ticket",
                _watchers_of(s, issue.id),
                f"{p.get('ticket')} for {title} is now “{str(p.get('status', ''))[:60]}”",
                p.get("effect"),
                link,
                iid,
                None,
            )
        ]
    return []


def on_events(s: Session, org_id: str, events: Sequence[Any]) -> int:
    """The dispatcher's subscriber. Returns how many notifications it wrote."""
    c = _Ctx(s, org_id)
    cfg = mail.SmtpConfig.from_env()
    written = 0
    for ev in events:
        try:
            for msg in _messages(c, ev.type, ev.payload):
                written += len(deliver(s, org_id, msg, ev.type, ev.id, smtp=cfg))
        except Exception:  # noqa: BLE001 - one event must not stop the rest
            s.rollback()
            log.warning("notification for event %s failed", ev.id, exc_info=True)
    s.commit()
    return written


def notify_people(
    s: Session,
    org_id: str,
    people: Iterable[str],
    title: str,
    body: str | None,
    link: str | None,
    *,
    actor: str | None = None,
    event_id: int | None = None,
) -> int:
    """For a rule's notify action that names people."""
    return len(
        deliver(
            s,
            org_id,
            Message("rules", list(people), title, body, link, None, actor),
            "rule.notify",
            event_id,
        )
    )


# --- the inbox ------------------------------------------------------------------------------------


def inbox(
    s: Session, org_id: str, actor: str, *, unread_only: bool = False, limit: int = INBOX_PAGE
) -> list[Notification]:
    q = select(Notification).where(
        Notification.org_id == org_id,
        Notification.recipient == actor,
        Notification.in_app.is_(True),
    )
    if unread_only:
        q = q.where(Notification.read_at.is_(None))
    return list(s.scalars(q.order_by(Notification.created_at.desc()).limit(limit)))


def unread(s: Session, org_id: str, actor: str) -> int:
    return int(
        s.scalar(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.org_id == org_id,
                Notification.recipient == actor,
                Notification.in_app.is_(True),
                Notification.read_at.is_(None),
            )
        )
        or 0
    )


def mark_read(s: Session, org_id: str, actor: str, ids: list[str] | None) -> int:
    q = update(Notification).where(
        Notification.org_id == org_id,
        Notification.recipient == actor,
        Notification.read_at.is_(None),
    )
    if ids is not None:
        q = q.where(Notification.id.in_(ids))
    n = s.execute(q.values(read_at=_now())).rowcount or 0  # type: ignore[attr-defined]
    s.commit()
    return int(n)


# --- the daily digest -----------------------------------------------------------------------------


def _slot(hour: int, now: datetime) -> datetime:
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    return slot if slot <= now else slot - timedelta(days=1)


def _due(row: NotificationPrefs | None, now: datetime) -> bool:
    hour = row.digest_hour if row else 8
    last = _aware(row.last_digest_at) if row and row.last_digest_at else None
    return last is None or last < _slot(hour, now)


@dataclass
class DigestResult:
    emails: int = 0
    team_messages: int = 0
    skipped: int = 0


def digest_text(items: list[Notification], kinds: dict[str, str]) -> str:
    by_kind: dict[str, list[Notification]] = defaultdict(list)
    for n in items:
        by_kind[n.kind].append(n)
    lines: list[str] = []
    for kind, label in kinds.items():
        group = by_kind.get(kind)
        if not group:
            continue
        lines.append(f"{label} ({len(group)}):")
        for n in group[:20]:
            base = mail_base_url()
            lines.append(f"  - {n.title}" + (f" ({base}{n.link})" if base and n.link else ""))
        if len(group) > 20:
            lines.append(f"  ...and {len(group) - 20} more")
        lines.append("")
    return "\n".join(lines).rstrip()


def run_digests(
    s: Session,
    org_id: str,
    *,
    now: datetime | None = None,
    smtp: mail.SmtpConfig | None = None,
    team_sender: Any = None,
) -> DigestResult:
    """Everyone whose digest hour has come: one email with what is pending; and, if the team chose
    a digest for anything, one message to the team channels."""
    now = now or _now()
    cfg = smtp if smtp is not None else mail.SmtpConfig.from_env()
    out = DigestResult()
    pending = list(
        s.scalars(
            select(Notification)
            .where(Notification.org_id == org_id, Notification.email_state == "pending")
            .order_by(Notification.created_at)
        )
    )
    by_owner: dict[str, list[Notification]] = defaultdict(list)
    for n in pending:
        by_owner[n.recipient].append(n)
    for owner, items in by_owner.items():
        row = prefs_service.get(s, org_id, owner)
        if owner != TEAM_OWNER:
            # Instant email that could not be sent (no server) is dropped here, not retried forever.
            if not _due(row, now):
                continue
            if cfg is None or row is None or not row.email:
                for n in items:
                    n.email_state = "skipped"
                out.skipped += len(items)
                continue
            body = digest_text(items, PERSON_KINDS)
            try:
                mail.send(
                    cfg,
                    row.email,
                    f"[Bulwark] Your daily digest: {len(items)} update"
                    f"{'s' if len(items) != 1 else ''}",
                    body,
                )
            except Exception:  # noqa: BLE001
                log.warning("digest email failed for %s", owner, exc_info=True)
                continue
            for n in items:
                n.email_state, n.emailed_at = "sent", now
            row.last_digest_at = now
            out.emails += 1
            continue
        if not _due(row, now):
            continue
        text = "Bulwark daily digest\n\n" + digest_text(items, TEAM_KINDS)
        sender = team_sender or _send_team_digest
        if sender(s, org_id, text):
            for n in items:
                n.email_state, n.emailed_at = "sent", now
            if row is None:
                row = NotificationPrefs(org_id=org_id, owner=TEAM_OWNER, prefs={}, digest_hour=8)
                s.add(row)
            row.last_digest_at = now
            out.team_messages += 1
    s.commit()
    return out


def _send_team_digest(s: Session, org_id: str, text: str) -> bool:
    """One message to every team channel the organization configured; True if any took it."""
    from core.integrations import discord, slack
    from core.integrations.webhooks import deliver_signed
    from core.notify.team import send_teams
    from core.rules.notify import slack_escape

    settings = repo.get_integration_settings(s, org_id)
    if settings is None:
        return False
    sent = send_teams(s, org_id, text, "Bulwark daily digest")
    if settings.slack_webhook_url:
        try:
            slack.send(settings.slack_webhook_url, {"text": slack_escape(text)[:3900]})
            sent = True
        except Exception:  # noqa: BLE001 - one channel failing must not stop the others
            log.warning("team digest to Slack failed", exc_info=True)
    if settings.discord_webhook_url:
        try:
            discord.send(
                settings.discord_webhook_url,
                {"content": text[:1900], "allowed_mentions": {"parse": []}},
            )
            sent = True
        except Exception:  # noqa: BLE001
            log.warning("team digest to Discord failed", exc_info=True)
    if settings.outbound_webhook_url and settings.outbound_webhook_secret:
        try:
            deliver_signed(
                settings.outbound_webhook_url,
                {"type": "digest", "text": text},
                settings.outbound_webhook_secret,
            )
            sent = True
        except Exception:  # noqa: BLE001
            log.warning("team digest to the webhook failed", exc_info=True)
    return sent


__all__ = [
    "Message",
    "deliver",
    "inbox",
    "mark_read",
    "notify_people",
    "on_events",
    "run_digests",
    "unread",
    "unwatch",
    "watch",
    "watchers",
]
