"""The team channels -- Slack, Discord, Microsoft Teams and the outbound webhook -- for each kind of
team notification: off, instant, or one message in the daily digest (plan §49, "so notifications
don't become noise").

Every existing team notifier (scan summaries, SLA crossings, risk acceptances, a rule's notify)
asks `gate` first: instant sends now as before; digest stores the line for the digest; off drops
it. Teams goes wherever the others go.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from core.notify import prefs
from core.notify.kinds import TEAM_CHANNEL, TEAM_OWNER
from core.persistence import repo
from core.persistence.models import Notification

log = logging.getLogger(__name__)


def mode(s: Session, org_id: str, kind: str) -> str:
    return prefs.mode(prefs.get(s, org_id, TEAM_OWNER), kind, TEAM_CHANNEL)


def gate(s: Session, org_id: str, kind: str, text: str, title: str | None = None) -> bool:
    """True: send now. False: it was queued for the digest, or the team turned this kind off."""
    m = mode(s, org_id, kind)
    if m == "instant":
        return True
    if m == "digest":
        s.add(
            Notification(
                org_id=org_id,
                recipient=TEAM_OWNER,
                kind=kind,
                event_type=kind,
                title=(title or text)[:500],
                body=text[:4000],
                in_app=False,
                email_state="pending",
            )
        )
        s.commit()
    return False


def send_teams(s: Session, org_id: str, text: str, title: str | None = None) -> bool:
    from core.integrations import teams

    settings = repo.get_integration_settings(s, org_id)
    if settings is None or not settings.teams_webhook_url:
        return False
    try:
        teams.send(settings.teams_webhook_url, teams.card(text, title))
        return True
    except Exception:  # noqa: BLE001 - one channel failing must not stop the others
        log.warning("teams notification failed", exc_info=True)
        return False
