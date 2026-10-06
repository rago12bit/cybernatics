"""VEX API (plan §46.3, §55.5): drafts with evidence, a person's decision, and the exports.

    POST /v2/advisories/{vuln_key}/vex-drafts      propose VEX where there is evidence
    POST /v2/vex/{id}/confirm | reject | withdraw   a person decides (a personal token)
    GET  /v2/projects/{id}/vex                      the project's statements and what it exports
    GET  /v2/projects/{id}/vex/openvex              OpenVEX v0.2.0 download
    GET  /v2/projects/{id}/vex/cyclonedx            CycloneDX 1.6 VEX download

Reading is `scans:read`; drafting and deciding are `scans:write`, like triage.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.advisories import VexStatementOut, _key
from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core.persistence import repo
from core.persistence.models import Library, VexStatement
from core.vex import export, service
from core.vex.service import VexError

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class DraftOut(BaseModel):
    proposed: int
    already: int
    skipped: dict[str, int]
    ids: list[str]


class DecisionIn(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ExportItem(BaseModel):
    vuln_key: str
    library: str
    version: str
    purl: str
    status: str
    justification: str | None
    basis: str
    impact_statement: str | None
    action_statement: str | None


class ProjectVexOut(BaseModel):
    project_id: str
    project: str
    counts: dict[str, int]
    statements: list[VexStatementOut]
    exported: list[ExportItem]


def _err(exc: VexError) -> HTTPException:
    return HTTPException(exc.status, str(exc))


def _project(s: Session, project_id: str, org: str) -> Any:
    asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
    if asset is None:
        raise HTTPException(404, "project not found")
    return asset


def _download(doc: dict[str, Any], name: str) -> Response:
    return Response(
        content=json.dumps(doc, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


def register_vex_routes(app: FastAPI) -> None:
    @app.post(
        "/v2/advisories/{vuln_key}/vex-drafts",
        response_model=DraftOut,
        tags=["vex"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def draft_vex(
        vuln_key: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> DraftOut:
        """Propose `not_affected` (`vulnerable_code_not_in_execute_path`) for each open use with
        evidence; nothing is exported until a person confirms it."""
        out = service.draft(s, org, _key(vuln_key), actor=auth.actor)
        return DraftOut(**out.__dict__)

    def _decide(
        fn: Any, statement_id: str, body: DecisionIn, org: str, actor: str, s: Session
    ) -> VexStatementOut:
        if not _UUID.match(statement_id):
            raise HTTPException(404, "VEX statement not found")
        try:
            st = fn(s, org, statement_id, actor=actor, note=body.note)
        except VexError as exc:
            raise _err(exc) from exc
        return VexStatementOut(**service.view(st, s.get(Library, st.library_id)))

    @app.post("/v2/vex/{statement_id}/confirm", response_model=VexStatementOut, tags=["vex"],
              dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def confirm_vex(
        statement_id: str,
        body: DecisionIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> VexStatementOut:
        return _decide(service.confirm, statement_id, body, org, auth.actor, s)

    @app.post("/v2/vex/{statement_id}/reject", response_model=VexStatementOut, tags=["vex"],
              dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def reject_vex(
        statement_id: str,
        body: DecisionIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> VexStatementOut:
        return _decide(service.reject, statement_id, body, org, auth.actor, s)

    @app.post("/v2/vex/{statement_id}/withdraw", response_model=VexStatementOut, tags=["vex"],
              dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def withdraw_vex(
        statement_id: str,
        body: DecisionIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> VexStatementOut:
        def fn(s: Session, org: str, sid: str, *, actor: str, note: str | None) -> VexStatement:
            return service.withdraw(s, org, sid, actor=actor, reason=note or "withdrawn")

        return _decide(fn, statement_id, body, org, auth.actor, s)

    @app.get("/v2/projects/{project_id}/vex", response_model=ProjectVexOut, tags=["vex"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def project_vex(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ProjectVexOut:
        asset = _project(s, project_id, org)
        rows = s.execute(
            select(VexStatement, Library)
            .join(Library, Library.id == VexStatement.library_id)
            .where(VexStatement.org_id == org, VexStatement.asset_id == asset.id)
            .order_by(VexStatement.proposed_at.desc())
            .limit(1000)
        ).all()
        items = export.statements(s, org, asset)
        return ProjectVexOut(
            project_id=asset.id, project=asset.label,
            counts=dict(Counter(i["status"] for i in items)),
            statements=[VexStatementOut(**service.view(st, lib)) for st, lib in rows],
            exported=[ExportItem(**{k: i[k] for k in ExportItem.model_fields}) for i in items],
        )  # fmt: skip

    @app.get("/v2/projects/{project_id}/vex/openvex", tags=["vex"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def project_openvex(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> Response:
        asset = _project(s, project_id, org)
        stem = _SAFE.sub("-", asset.label).strip("-")[:80] or "project"
        return _download(export.openvex(s, org, asset), f"{stem}.openvex.json")

    @app.get("/v2/projects/{project_id}/vex/cyclonedx", tags=["vex"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def project_cyclonedx_vex(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> Response:
        asset = _project(s, project_id, org)
        stem = _SAFE.sub("-", asset.label).strip("-")[:80] or "project"
        return _download(export.cyclonedx(s, org, asset), f"{stem}.vex.cdx.json")
