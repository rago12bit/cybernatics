"""Advisory API (plan §46.2, §55.5): what affects us, one advisory's impact, Issues in one click.

    GET  /v2/advisories?state=new&q=log4j&kev=true
    GET  /v2/advisories/{vuln_key}                 the impact view
    POST /v2/advisories/{vuln_key}/issues          create Issues (and tickets) for it
    GET  /v2/advisory-feeds                        where each source stands
    PUT  /v2/projects/{id}/owner                   who to ask about a project

Reading is `scans:read`; creating Issues is `ingest:write` (they arrive as an import); setting an
owner is `scans:write`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core.advisories import issues as advisory_issues
from core.advisories import view
from core.collab import assign
from core.collab.people import names
from core.persistence import repo
from core.persistence.models import Advisory, FeedState, KevEntry

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
STATES = ("new", "issues")


class AdvisoryRow(BaseModel):
    vuln_key: str
    ids: list[str]
    summary: str
    severity: str
    cvss: float | None
    kev: bool
    malicious: bool
    published: datetime | None
    first_seen_at: datetime
    state: str
    projects: int
    libraries: list[str]
    imported_by_app: int
    internet_facing: int
    uncertain: int


class Kev(BaseModel):
    cve: str
    date_added: str
    due_date: str
    name: str
    ransomware: str


class IssueRef(BaseModel):
    id: str
    state: str


class Use(BaseModel):
    project_id: str
    project: str
    portfolio: str | None
    library: str
    ecosystem: str
    purl: str
    version: str
    fixed_version: str | None
    certain: bool
    resolved_at: datetime | None
    first_seen_at: datetime
    relation: str
    paths: list[str]
    reachable: bool | None
    reachable_reason: str
    exposure: str
    owner: str | None
    issues: list[IssueRef]


class ImpactCounts(BaseModel):
    projects: int
    portfolios: int
    imported_by_app: int
    internet_facing: int
    uncertain: int
    with_fix: int
    with_issues: int


class ImpactOut(BaseModel):
    vuln_key: str
    ids: list[str]
    aliases: list[str]
    cves: list[str]
    summary: str
    details: str
    severity: str
    cvss: float | None
    cvss_vector: str
    malicious: bool
    kev: Kev | None
    published: datetime | None
    modified: datetime
    references: list[str]
    withdrawn: bool
    state: str
    first_seen_at: datetime
    uses: list[Use]
    no_longer_affected: list[Use]
    summary_counts: ImpactCounts


class CreateIn(BaseModel):
    project_ids: list[str] | None = Field(default=None, max_length=1000)


class CreateOut(BaseModel):
    projects: int
    issues: int
    tickets: int
    ticket_errors: list[str]
    issue_ids: dict[str, list[str]]


class FeedOut(BaseModel):
    source: str
    last_run_at: datetime | None
    last_success_at: datetime | None
    records: int
    last_error: str | None


class FeedsOut(BaseModel):
    feeds: list[FeedOut]
    advisories: int
    kev_entries: int


class OwnerIn(BaseModel):
    owner: str | None = Field(default=None, max_length=100)


class OwnerOut(BaseModel):
    project_id: str
    owner: str | None
    owner_name: str | None


def _key(vuln_key: str) -> str:
    if not _KEY.match(vuln_key):
        raise HTTPException(404, "advisory not found")
    return vuln_key


def register_advisory_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/advisories",
        response_model=list[AdvisoryRow],
        tags=["advisories"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_advisories(
        state: str | None = Query(default=None),
        q: str = Query(default="", max_length=200),
        kev: bool = Query(default=False),
        limit: int = Query(default=100, ge=1, le=500),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[AdvisoryRow]:
        if state is not None and state not in STATES:
            message = f"state is one of {', '.join(STATES)}"
            raise HTTPException(422, {"field": "state", "message": message})
        rows = view.listing(s, org, state=state, q=q, kev_only=kev, limit=limit)
        return [AdvisoryRow(**r) for r in rows]

    @app.get(
        "/v2/advisories/{vuln_key}",
        response_model=ImpactOut,
        tags=["advisories"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_impact(
        vuln_key: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ImpactOut:
        found = view.impact(s, org, _key(vuln_key))
        if found is None:
            raise HTTPException(404, "advisory not found")
        return ImpactOut(**found)

    @app.post(
        "/v2/advisories/{vuln_key}/issues",
        response_model=CreateOut,
        tags=["advisories"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def create_issues(
        vuln_key: str,
        body: CreateIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> CreateOut:
        if body.project_ids is not None and any(not _UUID.match(p) for p in body.project_ids):
            raise HTTPException(422, {"field": "project_ids", "message": "not a project id"})
        try:
            out = advisory_issues.create(
                s, org, _key(vuln_key), actor=auth.actor, project_ids=body.project_ids
            )
        except LookupError as exc:
            raise HTTPException(404, "advisory not found") from exc
        repo.append_audit_entry(
            s, actor=auth.actor, action="advisory.issues_created", target=vuln_key,
            payload={"projects": out.projects, "issues": out.issues, "tickets": out.tickets},
        )  # fmt: skip
        return CreateOut(**out.__dict__)

    @app.get(
        "/v2/advisory-feeds",
        response_model=FeedsOut,
        tags=["advisories"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def feeds(s: Session = Depends(db)) -> FeedsOut:
        rows = list(s.scalars(select(FeedState).order_by(FeedState.source)))
        return FeedsOut(
            feeds=[
                FeedOut(source=r.source, last_run_at=r.last_run_at,
                        last_success_at=r.last_success_at, records=r.records,
                        last_error=r.last_error)
                for r in rows
            ],  # fmt: skip
            advisories=s.scalar(select(func.count()).select_from(Advisory)) or 0,
            kev_entries=s.scalar(select(func.count()).select_from(KevEntry)) or 0,
        )

    @app.put(
        "/v2/projects/{project_id}/owner",
        response_model=OwnerOut,
        tags=["advisories"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_owner(
        project_id: str,
        body: OwnerIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> OwnerOut:
        asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
        if asset is None:
            raise HTTPException(404, "project not found")
        try:
            person = assign.resolve(s, org, body.owner) if body.owner else None
        except assign.AssignError as exc:
            raise HTTPException(422, {"field": "owner", "message": str(exc)}) from exc
        previous = asset.owner
        asset.owner = person.actor if person else None
        s.flush()
        repo.append_audit_entry(  # commits
            s, actor=auth.actor, action="project.owner_set", target=asset.id,
            payload={"owner": asset.owner, "previous": previous},
        )  # fmt: skip
        return _owner(s, org, asset.id, asset.owner)

    @app.get(
        "/v2/projects/{project_id}/owner",
        response_model=OwnerOut,
        tags=["advisories"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_owner(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> OwnerOut:
        asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
        if asset is None:
            raise HTTPException(404, "project not found")
        return _owner(s, org, asset.id, asset.owner)


def _owner(s: Session, org: str, project_id: str, owner: str | None) -> OwnerOut:
    shown: Any = names(s, org, {owner}).get(owner) if owner else None
    return OwnerOut(project_id=project_id, owner=owner, owner_name=shown)
