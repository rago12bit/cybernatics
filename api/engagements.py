"""The assessment engagement API (Week 64, plan §43.1, §55.2).

    GET   /v2/projects/{id}/engagements           the project's assessments (not its standing ci and
                                                  import engagements)
    POST  /v2/projects/{id}/engagements           create one: scope, lead, testers, dates, checklist
    GET   /v2/engagements/{id}                    the engagement screen: fields, checklist progress,
                                                  findings (with "also found by"), tests
    PATCH /v2/engagements/{id}                    edit, or move along planned / in progress /
                                                  reporting (and reopen a closed one)
    GET   /v2/engagements/{id}/checklist          every checklist entry with its result
    PUT   /v2/engagements/{id}/checklist/{item}   record one entry's result (or clear it)
    POST  /v2/engagements/{id}/close              close it and write its report
    GET   /v2/engagements/{id}/report?format=     the report, as a Markdown or HTML download
    GET   /v2/checklists                          the checklists an engagement can follow

Reading is `scans:read`; every change is `scans:write` and audit-logged. Adding findings and results
uses the manual finding form and the import API, naming the engagement.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core.collab.people import names
from core.engagements import checklists, report
from core.engagements import service as engagements
from core.persistence import repo
from core.persistence.models import Engagement

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class ChecklistSummary(BaseModel):
    id: str
    name: str
    total: int
    done: int = Field(description="Passed, failed or not applicable.")
    pass_: int = Field(alias="pass")
    fail: int
    not_applicable: int
    in_progress: int
    attribution: str

    model_config = {"populate_by_name": True}


class EngagementOut(BaseModel):
    id: str
    project_id: str
    project: str
    name: str
    engagement_type: str
    status: str
    scope_targets: list[str]
    scope_routes: list[str]
    out_of_scope: str | None
    lead: str | None
    testers: list[str]
    starts_at: datetime | None
    ends_at: datetime | None
    checklist: ChecklistSummary | None
    closed_at: datetime | None
    report_generated_at: datetime | None
    created_by: str | None
    created_at: datetime
    names: dict[str, str] = Field(default_factory=dict, description="Display names for actors.")


class FindingOut(BaseModel):
    issue_id: str
    title: str
    severity: str
    path: str
    state: str
    triage_status: str
    retest_status: str | None
    retest_requested_by: str | None
    priority_band: str | None
    test: str
    manual_finding_id: str | None
    also_found_by: list[str] = Field(description="Other sources reporting the same Issue.")
    first_seen_at: datetime
    fixed_at: datetime | None


class TestOut(BaseModel):
    id: str
    name: str
    parser: str | None
    findings: int
    uploads: int
    last_upload_at: datetime | None


class EngagementDetail(EngagementOut):
    findings: list[FindingOut]
    tests: list[TestOut]


class EngagementIn(BaseModel):
    name: str | None = Field(default=None, max_length=300)
    engagement_type: str | None = Field(default=None, description="pentest, audit, assessment.")
    status: str | None = None
    scope_targets: list[str] | None = None
    scope_routes: list[str] | None = None
    out_of_scope: str | None = Field(default=None, max_length=5000)
    lead: str | None = Field(default=None, max_length=200)
    testers: list[str] | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    checklist: str | None = None


class ItemOut(BaseModel):
    id: str
    group: str
    title: str
    level: int | None
    cwe: str | None
    reference: str | None
    status: str | None
    note: str | None
    updated_by: str | None
    updated_at: datetime | None


class ChecklistOut(BaseModel):
    summary: ChecklistSummary
    items: list[ItemOut]


class ItemIn(BaseModel):
    status: str | None = Field(description="in_progress, pass, fail, not_applicable; null clears.")
    note: str | None = Field(default=None, max_length=5000)


class CloseIn(BaseModel):
    summary: str | None = Field(default=None, max_length=5000)


class CatalogueOut(BaseModel):
    id: str
    name: str
    items: int
    source: str
    attribution: str


def _bad(exc: engagements.EngagementError) -> HTTPException:
    return HTTPException(422, {"field": exc.field, "message": str(exc)})


def _get(s: Session, engagement_id: str, org: str) -> Engagement:
    e = engagements.get(s, engagement_id, org) if _UUID.match(engagement_id) else None
    if e is None:
        raise HTTPException(404, "engagement not found")
    return e


def _out(s: Session, e: Engagement) -> dict[str, Any]:
    state = engagements.checklist_state(s, e)
    actors = {a for a in (e.created_by,) if a}
    return {
        "id": e.id, "project_id": e.asset_id, "project": engagements.project_label(s, e),
        "name": e.name, "engagement_type": e.engagement_type, "status": e.status,
        "scope_targets": list(e.scope_targets or []), "scope_routes": list(e.scope_routes or []),
        "out_of_scope": e.out_of_scope, "lead": e.lead, "testers": list(e.testers or []),
        "starts_at": e.started_at, "ends_at": e.target_end_at,
        "checklist": state.summary() if state else None, "closed_at": e.closed_at,
        "report_generated_at": e.report_generated_at, "created_by": e.created_by,
        "created_at": e.created_at, "names": names(s, e.org_id, actors),
    }  # fmt: skip


def register_engagement_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/checklists",
        response_model=list[CatalogueOut],
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_checklists() -> list[CatalogueOut]:
        return [
            CatalogueOut(id=c.id, name=c.name, items=len(c.items), source=c.source,
                         attribution=checklists.ATTRIBUTION)  # fmt: skip
            for c in checklists.catalogue().values()
        ]

    @app.get(
        "/v2/projects/{project_id}/engagements",
        response_model=list[EngagementOut],
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_engagements(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[dict[str, Any]]:
        asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
        if asset is None:
            raise HTTPException(404, "project not found")
        return [_out(s, e) for e in engagements.list_for_project(s, asset.id, org)]

    @app.post(
        "/v2/projects/{project_id}/engagements",
        response_model=EngagementOut,
        status_code=201,
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def create_engagement(
        project_id: str,
        body: EngagementIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
        if asset is None:
            raise HTTPException(404, "project not found")
        try:
            e = engagements.create(
                s, org_id=org, asset_id=asset.id, data=body.model_dump(exclude_unset=True),
                actor=auth.actor,
            )  # fmt: skip
        except engagements.EngagementError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return _out(s, e)

    @app.get(
        "/v2/engagements/{engagement_id}",
        response_model=EngagementDetail,
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_engagement(
        engagement_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        e = _get(s, engagement_id, org)
        found = engagements.findings(s, e)
        out = _out(s, e)
        actors = {f["retest_requested_by"] for f in found if f["retest_requested_by"]}
        out["names"].update(names(s, org, actors))
        return {**out, "findings": found, "tests": engagements.tests(s, e)}

    @app.patch(
        "/v2/engagements/{engagement_id}",
        response_model=EngagementOut,
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def patch_engagement(
        engagement_id: str,
        body: EngagementIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        e = _get(s, engagement_id, org)
        try:
            engagements.update(s, e, body.model_dump(exclude_unset=True), actor=auth.actor)
        except engagements.EngagementError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return _out(s, e)

    @app.get(
        "/v2/engagements/{engagement_id}/checklist",
        response_model=ChecklistOut,
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_checklist(
        engagement_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        e = _get(s, engagement_id, org)
        state = engagements.checklist_state(s, e)
        if state is None:
            raise HTTPException(404, "this engagement has no checklist")
        items = []
        for i in state.checklist.items:
            r = state.rows.get(i.id)
            items.append(
                {"id": i.id, "group": i.group, "title": i.title, "level": i.level, "cwe": i.cwe,
                 "reference": i.reference, "status": r.status if r else None,
                 "note": r.note if r else None, "updated_by": r.updated_by if r else None,
                 "updated_at": r.updated_at if r else None}  # fmt: skip
            )
        return {"summary": state.summary(), "items": items}

    @app.put(
        "/v2/engagements/{engagement_id}/checklist/{item_id}",
        response_model=ChecklistSummary,
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def put_checklist_item(
        engagement_id: str,
        item_id: str,
        body: ItemIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        e = _get(s, engagement_id, org)
        try:
            engagements.set_item(s, e, item_id[:40], body.status, body.note, actor=auth.actor)
        except engagements.EngagementError as exc:
            s.rollback()
            raise _bad(exc) from exc
        state = engagements.checklist_state(s, e)
        assert state is not None
        return state.summary()

    @app.post(
        "/v2/engagements/{engagement_id}/close",
        response_model=EngagementOut,
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def close_engagement(
        engagement_id: str,
        body: CloseIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        e = _get(s, engagement_id, org)
        try:
            engagements.close(s, e, actor=auth.actor, summary=body.summary)
        except engagements.EngagementError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return _out(s, e)

    @app.get(
        "/v2/engagements/{engagement_id}/report",
        tags=["engagements"],
        dependencies=[Depends(require_scope("scans:read"))],
        responses={200: {"content": {"text/markdown": {}, "text/html": {}}}},
    )
    def get_report(
        engagement_id: str,
        format: str = Query(default="md", pattern="^(md|html)$"),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> Response:
        """A download, never rendered by the app: the HTML forbids script and remote loads."""
        e = _get(s, engagement_id, org)
        if not e.report:
            raise HTTPException(404, "no report yet: close the engagement to write it")
        stem = _SAFE.sub("-", e.name).strip("-")[:80] or "engagement"
        if format == "html":
            body, media, ext = report.html_page(e.report), "text/html; charset=utf-8", "html"
        else:
            body, media, ext = report.markdown(e.report), "text/markdown; charset=utf-8", "md"
        return Response(
            content=body,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{stem}-report.{ext}"',
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": report.CSP,
                "Cache-Control": "no-store",
            },
        )
