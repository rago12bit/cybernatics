"""Notifications API (Week 66, plan §49).

    GET    /v2/notifications?unread=          your inbox, newest first, and how many are unread
    POST   /v2/notifications/read             mark some ({"ids": [...]}) or all ({}) read
    GET    /v2/notification-prefs             yours: per kind, in-app and email; your address
    PUT    /v2/notification-prefs             change them
    GET    /v2/notification-prefs/team        the team channels': per kind, off/instant/digest
    PUT    /v2/notification-prefs/team        change them (scans:write, like integrations)
    GET    /v2/issues/{id}/watchers           who watches it, and whether you do
    PUT    /v2/issues/{id}/watch              watch it          DELETE: stop

"You" is the token you signed in with; the shared token is nobody, so it has no inbox. Reading is
`scans:read`; changing your own preferences or watching is too (it changes only your own view);
the team's preferences need `scans:write`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from api.retest import issue_for
from core.collab.people import names
from core.notify import prefs as prefs_service
from core.notify import service as notify
from core.notify.email import SmtpConfig
from core.notify.kinds import TEAM_OWNER

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class NotificationOut(BaseModel):
    id: str
    kind: str
    title: str
    body: str | None
    link: str | None
    issue_id: str | None
    actor: str | None
    created_at: datetime
    read: bool
    email: str | None = Field(description="pending (next digest), sent, skipped, failed, or none")


class InboxOut(BaseModel):
    notifications: list[NotificationOut]
    unread: int
    you: str
    person: bool
    names: dict[str, str]


class ReadIn(BaseModel):
    ids: list[str] | None = Field(default=None, max_length=500)


class PrefsIn(BaseModel):
    modes: dict[str, dict[str, str]] = Field(default_factory=dict)
    digest_hour: int = 8
    email: str | None = Field(default=None, max_length=320)


class WatchersOut(BaseModel):
    watchers: list[dict[str, str]]
    watching: bool
    names: dict[str, str]


def _bad(exc: prefs_service.PrefsError) -> HTTPException:
    return HTTPException(422, {"field": exc.field, "message": str(exc)})


def register_notify_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/notifications",
        response_model=InboxOut,
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def inbox(
        unread: bool = Query(default=False),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> InboxOut:
        rows = notify.inbox(s, org, auth.actor, unread_only=unread)
        actors = {r.actor for r in rows if r.actor}
        return InboxOut(
            notifications=[
                NotificationOut(
                    id=r.id,
                    kind=r.kind,
                    title=r.title,
                    body=r.body,
                    link=r.link,
                    issue_id=r.issue_id,
                    actor=r.actor,
                    created_at=r.created_at,
                    read=r.read_at is not None,
                    email=r.email_state,
                )
                for r in rows
            ],
            unread=notify.unread(s, org, auth.actor),
            you=auth.actor,
            person=auth.actor.startswith("token:"),
            names=names(s, org, actors),
        )

    @app.post(
        "/v2/notifications/read",
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def mark_read(
        body: ReadIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, int]:
        ids = [i for i in body.ids if _UUID.match(i)] if body.ids is not None else None
        changed = notify.mark_read(s, org, auth.actor, ids)
        return {"marked": changed, "unread": notify.unread(s, org, auth.actor)}

    def _prefs_view(s: Session, org: str, owner: str) -> dict[str, Any]:
        out = prefs_service.view(prefs_service.get(s, org, owner), owner)
        out["email_available"] = SmtpConfig.from_env() is not None
        return out

    @app.get(
        "/v2/notification-prefs",
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def my_prefs(
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        return {**_prefs_view(s, org, auth.actor), "person": auth.actor.startswith("token:")}

    @app.put(
        "/v2/notification-prefs",
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def save_my_prefs(
        body: PrefsIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        if not auth.actor.startswith("token:"):
            raise HTTPException(409, "The shared token is nobody: sign in with a personal token.")
        try:
            prefs_service.save(s, org, auth.actor, body.model_dump(), actor=auth.actor)
        except prefs_service.PrefsError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return {**_prefs_view(s, org, auth.actor), "person": True}

    @app.get(
        "/v2/notification-prefs/team",
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def team_prefs(s: Session = Depends(db), org: str = Depends(current_org)) -> dict[str, Any]:
        return _prefs_view(s, org, TEAM_OWNER)

    @app.put(
        "/v2/notification-prefs/team",
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def save_team_prefs(
        body: PrefsIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            prefs_service.save(
                s, org, TEAM_OWNER, {**body.model_dump(), "email": None}, actor=auth.actor
            )
        except prefs_service.PrefsError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return _prefs_view(s, org, TEAM_OWNER)

    def _watchers(s: Session, org: str, issue_id: str, you: str) -> WatchersOut:
        rows = notify.watchers(s, issue_id)
        return WatchersOut(
            watchers=[{"actor": w.actor, "reason": w.reason} for w in rows],
            watching=any(w.actor == you for w in rows),
            names=names(s, org, {w.actor for w in rows}),
        )

    @app.get(
        "/v2/issues/{issue_id}/watchers",
        response_model=WatchersOut,
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_watchers(
        issue_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> WatchersOut:
        issue = issue_for(s, issue_id, org)
        return _watchers(s, org, issue.id, auth.actor)

    @app.put(
        "/v2/issues/{issue_id}/watch",
        response_model=WatchersOut,
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def watch(
        issue_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> WatchersOut:
        issue = issue_for(s, issue_id, org)
        if not auth.actor.startswith("token:"):
            raise HTTPException(409, "The shared token is nobody: sign in with a personal token.")
        notify.watch(s, org, issue.id, auth.actor, "manual")
        s.commit()
        return _watchers(s, org, issue.id, auth.actor)

    @app.delete(
        "/v2/issues/{issue_id}/watch",
        response_model=WatchersOut,
        tags=["notifications"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def unwatch(
        issue_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> WatchersOut:
        issue = issue_for(s, issue_id, org)
        notify.unwatch(s, issue.id, auth.actor)
        return _watchers(s, org, issue.id, auth.actor)
