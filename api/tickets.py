"""Tickets and issue groups API (Week 66, plan §49).

    GET    /v2/projects/{id}/tickets          where the project's tickets go, and who owns status
    PUT    /v2/projects/{id}/tickets          change it (scans:write, like integrations)
    GET    /v2/projects/{id}/groups           its groups, with how many Issues each has
    POST   /v2/projects/{id}/groups           make one
    GET    /v2/groups/{id}                    a group: its Issues and its ticket
    PUT    /v2/issues/{id}/group              put the Issue in a group, or none
    GET    /v2/issues/{id}/ticket             its ticket (status, assignee, last synced) and group
    POST   /v2/issues/{id}/ticket             file it (its group's, if grouped), or update it
    POST   /v2/issues/{id}/ticket/sync        read the ticket now, and push what Bulwark owns

Reading is `scans:read`; everything else `scans:write`. Every change is audit-logged.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from api.retest import issue_for
from core.integrations.ssrf import WebhookUrlError
from core.persistence import repo
from core.persistence.models import IssueGroup, TicketConfig
from core.tickets import config as ticket_config
from core.tickets import groups as group_service
from core.tickets import sync

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class TicketConfigIn(BaseModel):
    provider: str = Field(max_length=16)
    target: str = Field(max_length=200)
    issue_type: str | None = Field(default=None, max_length=64)
    status_source: str = "ticket"
    status_map: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True


class TicketConfigOut(BaseModel):
    configured: bool
    provider: str | None = None
    target: str | None = None
    issue_type: str | None = None
    status_source: str = "ticket"
    status_map: dict[str, str] = Field(default_factory=dict)
    effective_map: dict[str, str] = Field(default_factory=dict)
    enabled: bool = False
    updated_by: str | None = None
    updated_at: datetime | None = None
    credentials: dict[str, bool]


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class GroupOut(BaseModel):
    id: str
    name: str
    project_id: str
    count: int
    created_at: datetime


class GroupDetail(GroupOut):
    issues: list[dict[str, Any]]
    ticket: dict[str, Any] | None


class IssueGroupIn(BaseModel):
    group_id: str | None = None
    name: str | None = Field(default=None, max_length=200, description="make or join by name")


class TicketView(BaseModel):
    ticket: dict[str, Any] | None
    group: dict[str, Any] | None
    configured: bool
    provider: str | None
    status_source: str | None


def _bad(field: str, message: str) -> HTTPException:
    return HTTPException(422, {"field": field, "message": message})


def _config_out(s: Session, org: str, row: TicketConfig | None) -> TicketConfigOut:
    settings = repo.get_integration_settings(s, org)
    creds = {
        "jira": bool(
            settings and settings.jira_base_url and settings.jira_email and settings.jira_api_token
        ),
        "github": bool(settings and settings.github_token),
    }
    if row is None:
        return TicketConfigOut(configured=False, credentials=creds)
    return TicketConfigOut(
        configured=True,
        provider=row.provider,
        target=row.target,
        issue_type=row.issue_type,
        status_source=row.status_source,
        status_map=row.status_map,
        effective_map=ticket_config.effective_map(row),
        enabled=row.enabled,
        updated_by=row.updated_by,
        updated_at=row.updated_at,
        credentials=creds,
    )


def _project(s: Session, org: str, project_id: str) -> str:
    asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
    if asset is None:
        raise HTTPException(404, "project not found")
    return asset.id


def _group_out(g: IssueGroup, count: int) -> GroupOut:
    return GroupOut(
        id=g.id, name=g.name, project_id=g.asset_id, count=count, created_at=g.created_at
    )


def register_ticket_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/projects/{project_id}/tickets",
        response_model=TicketConfigOut,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_config(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> TicketConfigOut:
        return _config_out(s, org, ticket_config.get(s, _project(s, org, project_id)))

    @app.put(
        "/v2/projects/{project_id}/tickets",
        response_model=TicketConfigOut,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def save_config(
        project_id: str,
        body: TicketConfigIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> TicketConfigOut:
        asset_id = _project(s, org, project_id)
        try:
            row = ticket_config.save(s, org, asset_id, body.model_dump(), actor=auth.actor)
        except ticket_config.ConfigError as exc:
            s.rollback()
            raise _bad(exc.field, str(exc)) from exc
        return _config_out(s, org, row)

    @app.get(
        "/v2/projects/{project_id}/groups",
        response_model=list[GroupOut],
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_groups(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[GroupOut]:
        asset_id = _project(s, org, project_id)
        return [_group_out(g, n) for g, n in group_service.for_project(s, org, asset_id)]

    @app.post(
        "/v2/projects/{project_id}/groups",
        response_model=GroupOut,
        status_code=201,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def make_group(
        project_id: str,
        body: GroupIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> GroupOut:
        asset_id = _project(s, org, project_id)
        try:
            g = group_service.get_or_create(s, org, asset_id, body.name, actor=auth.actor)
        except group_service.GroupError as exc:
            raise _bad("name", str(exc)) from exc
        s.commit()
        return _group_out(g, len(group_service.members(s, g.id)))

    @app.get(
        "/v2/groups/{group_id}",
        response_model=GroupDetail,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_group(
        group_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> GroupDetail:
        g = group_service.get(s, org, group_id) if _UUID.match(group_id) else None
        if g is None:
            raise HTTPException(404, "group not found")
        members = group_service.members(s, g.id)
        ticket = sync.view(s, members[0]) if members else None
        return GroupDetail(
            **_group_out(g, len(members)).model_dump(),
            issues=[
                {"id": m.id, "title": m.title, "severity": m.severity, "state": m.state}
                for m in members
            ],
            ticket=ticket,
        )

    @app.put(
        "/v2/issues/{issue_id}/group",
        response_model=TicketView,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_issue_group(
        issue_id: str,
        body: IssueGroupIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> TicketView:
        issue = issue_for(s, issue_id, org)
        group = None
        try:
            if body.name:
                group = group_service.get_or_create(
                    s, org, issue.asset_id, body.name, actor=auth.actor
                )
            elif body.group_id:
                group = (
                    group_service.get(s, org, body.group_id) if _UUID.match(body.group_id) else None
                )
                if group is None:
                    raise HTTPException(404, "group not found")
            group_service.set_group(s, org, issue, group, actor=auth.actor)
        except group_service.GroupError as exc:
            s.rollback()
            raise _bad("group", str(exc)) from exc
        return _ticket_view(s, issue)

    def _ticket_view(s: Session, issue: Any) -> TicketView:
        cfg = ticket_config.get(s, issue.asset_id)
        g = s.get(IssueGroup, issue.group_id) if issue.group_id else None
        group = None
        if g is not None:
            group = {"id": g.id, "name": g.name, "count": len(group_service.members(s, g.id))}
        return TicketView(
            ticket=sync.view(s, issue),
            group=group,
            configured=bool(cfg and cfg.enabled),
            provider=cfg.provider if cfg else None,
            status_source=cfg.status_source if cfg else None,
        )

    @app.get(
        "/v2/issues/{issue_id}/ticket",
        response_model=TicketView,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_ticket(
        issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> TicketView:
        return _ticket_view(s, issue_for(s, issue_id, org))

    def _run(fn: Any) -> Any:
        try:
            return fn()
        except sync.TicketError as exc:
            raise HTTPException(409, str(exc)) from exc
        except WebhookUrlError as exc:
            raise HTTPException(422, f"Jira's address was refused: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - Jira or GitHub said no; say what they said
            raise HTTPException(502, f"The ticket system refused: {exc}") from exc

    @app.post(
        "/v2/issues/{issue_id}/ticket",
        response_model=TicketView,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def file_ticket(
        issue_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> TicketView:
        issue = issue_for(s, issue_id, org)
        _run(lambda: sync.file(s, org, issue, actor=auth.actor))
        return _ticket_view(s, issue)

    @app.post(
        "/v2/issues/{issue_id}/ticket/sync",
        response_model=TicketView,
        tags=["tickets"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def sync_ticket(
        issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> TicketView:
        issue = issue_for(s, issue_id, org)
        link = sync.link_for_issue(s, issue.id)
        if link is None:
            raise HTTPException(409, "This issue has no ticket yet.")
        _run(
            lambda: (
                sync.pull(s, org, link.provider, link.external_id),
                sync.push(s, org, link.provider, link.external_id),
            )
        )
        return _ticket_view(s, issue)
