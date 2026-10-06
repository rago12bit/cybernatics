"""Notification preferences: one row per person (their actor) or for the team (plan §49).

A missing row, kind or channel means the default, so a new kind of event is on for everyone
without a migration: in-app instant and email in the daily digest for people; instant for the team
channels, which is what every organization had before preferences existed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.notify.kinds import (
    PERSON_CHANNELS,
    PERSON_DEFAULTS,
    PERSON_KINDS,
    TEAM_CHANNEL,
    TEAM_DEFAULT,
    TEAM_KINDS,
    TEAM_MODES,
    TEAM_OWNER,
)
from core.persistence import repo
from core.persistence.models import NotificationPrefs

_EMAIL = re.compile(r"^[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")


class PrefsError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def get(s: Session, org_id: str, owner: str) -> NotificationPrefs | None:
    return s.scalars(
        select(NotificationPrefs).where(
            NotificationPrefs.org_id == org_id, NotificationPrefs.owner == owner
        )
    ).one_or_none()


def mode(row: NotificationPrefs | None, kind: str, channel: str) -> str:
    stored = ((row.prefs if row else None) or {}).get(kind, {}).get(channel)
    if channel == TEAM_CHANNEL:
        return stored if stored in TEAM_MODES else TEAM_DEFAULT
    allowed = PERSON_CHANNELS.get(channel, ())
    return stored if stored in allowed else PERSON_DEFAULTS.get(channel, "off")


def view(row: NotificationPrefs | None, owner: str) -> dict[str, Any]:
    team = owner == TEAM_OWNER
    kinds = TEAM_KINDS if team else PERSON_KINDS
    channels = (TEAM_CHANNEL,) if team else tuple(PERSON_CHANNELS)
    return {
        "owner": owner,
        "email": row.email if row and not team else None,
        "digest_hour": row.digest_hour if row else 8,
        "kinds": [
            {"key": k, "label": label, "modes": {c: mode(row, k, c) for c in channels}}
            for k, label in kinds.items()
        ],
        "channels": {c: list(TEAM_MODES if team else PERSON_CHANNELS[c]) for c in channels},
    }


def save(
    s: Session, org_id: str, owner: str, raw: dict[str, Any], *, actor: str
) -> NotificationPrefs:
    team = owner == TEAM_OWNER
    kinds = TEAM_KINDS if team else PERSON_KINDS
    out: dict[str, dict[str, str]] = {}
    raw_modes = raw.get("modes")
    modes: dict[str, Any] = raw_modes if isinstance(raw_modes, dict) else {}
    for kind, chosen in modes.items():
        if kind not in kinds or not isinstance(chosen, dict):
            raise PrefsError("modes", f"Unknown kind of notification: {str(kind)[:40]}.")
        for channel, value in chosen.items():
            allowed = (
                TEAM_MODES
                if team and channel == TEAM_CHANNEL
                else (PERSON_CHANNELS.get(channel, ()) if not team else ())
            )
            if value not in allowed:
                raise PrefsError(
                    f"modes.{kind}.{channel}",
                    f"{channel} is one of: {', '.join(allowed) or 'nothing'}.",
                )
            out.setdefault(kind, {})[channel] = value
    hour = raw.get("digest_hour", 8)
    if isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23:
        raise PrefsError("digest_hour", "An hour from 0 to 23 (UTC).")
    email = (raw.get("email") or "").strip() or None
    if email is not None and (team or not _EMAIL.match(email) or len(email) > 320):
        raise PrefsError("email", "That is not an email address.")
    row = get(s, org_id, owner)
    if row is None:
        row = NotificationPrefs(org_id=org_id, owner=owner)
        s.add(row)
    row.prefs, row.digest_hour, row.email = out, hour, email
    row.updated_at = datetime.now(timezone.utc)
    s.flush()
    repo.append_audit_entry(  # commits; the address itself is not logged
        s,
        actor=actor,
        action="notifications.prefs.changed",
        target=f"prefs:{owner}",
        payload={"org_id": org_id, "modes": out, "digest_hour": hour, "email_set": bool(email)},
    )
    return row
