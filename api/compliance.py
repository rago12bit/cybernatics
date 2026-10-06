"""Compliance API (plan §47): mappings, the ASVS benchmark per project, evidence packs.

    GET  /v2/compliance/frameworks                     every mapping, with its source and version
    GET  /v2/compliance/frameworks/{id}                one mapping's controls
    GET  /v2/projects/{id}/asvs?level=2                the project's ASVS checklist
    PUT  /v2/projects/{id}/asvs/{requirement}          a person's status for one requirement
    POST /v2/evidence-packs/preview                    what a pack for a period would hold
    POST /v2/evidence-packs                            generate one (signed when a key is set)
    GET  /v2/evidence-packs                            the packs generated
    GET  /v2/evidence-packs/{id}/bundle                the zip

Reading is `scans:read`; setting a status and generating a pack are `scans:write`.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core import compliance
from core.compliance import asvs
from core.evidence import pack
from core.persistence import repo
from core.persistence.models import EvidencePack

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_REQ = re.compile(r"^V\d{1,2}\.\d{1,2}\.\d{1,2}$")


class FrameworkOut(BaseModel):
    id: str
    name: str
    framework_version: str
    source: dict[str, str]
    mapping_version: int
    mapping_date: str
    controls: int


class ControlOut(BaseModel):
    id: str
    title: str
    group: str
    level: int | None
    evidence: list[str]
    cwes: list[str]
    note: str


class FrameworkDetail(FrameworkOut):
    disclaimer: str
    evidence_kinds: dict[str, str]
    items: list[ControlOut]


class StatusIn(BaseModel):
    status: Literal["met", "not_met", "not_applicable"] | None
    note: str = Field(default="", max_length=4000)
    links: list[str] = Field(default_factory=list, max_length=10)


class PackIn(BaseModel):
    start: date
    end: date
    frameworks: list[str] = Field(default_factory=list, max_length=10)


class PackOut(BaseModel):
    id: str
    period_start: date
    period_end: date
    frameworks: list[str]
    summary: dict[str, Any]
    sha256: str
    signed: bool
    size: int
    created_by: str
    created_at: datetime


def _pack_out(p: EvidencePack) -> PackOut:
    return PackOut(
        id=p.id, period_start=p.period_start, period_end=p.period_end, frameworks=p.frameworks,
        summary=p.summary, sha256=p.sha256, signed=p.signed, size=len(p.bundle),
        created_by=p.created_by, created_at=p.created_at,
    )  # fmt: skip


def _project(s: Session, project_id: str, org: str) -> Any:
    asset = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
    if asset is None:
        raise HTTPException(404, "project not found")
    return asset


def register_compliance_routes(app: FastAPI) -> None:
    @app.get("/v2/compliance/frameworks", response_model=list[FrameworkOut], tags=["compliance"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def list_frameworks() -> list[FrameworkOut]:
        return [FrameworkOut(**f.summary()) for f in compliance.frameworks().values()]

    @app.get("/v2/compliance/frameworks/{framework_id}", response_model=FrameworkDetail,
             tags=["compliance"], dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def get_framework(framework_id: str) -> FrameworkDetail:
        fw = compliance.get(framework_id)
        if fw is None:
            raise HTTPException(404, "framework not found")
        return FrameworkDetail(
            **fw.summary(), disclaimer=compliance.DISCLAIMER, evidence_kinds=compliance.EVIDENCE,
            items=[ControlOut(id=c.id, title=c.title, group=c.group, level=c.level,
                              evidence=list(c.evidence), cwes=list(c.cwes), note=c.note)
                   for c in fw.controls],
        )  # fmt: skip

    @app.get("/v2/projects/{project_id}/asvs", tags=["compliance"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def project_asvs(
        project_id: str,
        level: int = Query(default=2, ge=1, le=3),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, Any]:
        asset = _project(s, project_id, org)
        out = asvs.benchmark(s, org, asset.id, level=level)
        return {"project_id": asset.id, "project": asset.label, **out}

    @app.put("/v2/projects/{project_id}/asvs/{requirement}", tags=["compliance"],
             dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def set_asvs_status(
        project_id: str,
        requirement: str,
        body: StatusIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        asset = _project(s, project_id, org)
        if not _REQ.match(requirement):
            raise HTTPException(404, "requirement not found")
        try:
            row = asvs.set_status(
                s, org, asset.id, requirement, status=body.status, note=body.note,
                links=body.links, actor=auth.actor,
            )  # fmt: skip
        except asvs.ComplianceError as exc:
            raise HTTPException(422, str(exc)) from exc
        if row is None:
            return {"requirement": requirement, "status": None}
        return {"requirement": requirement, "status": row.status, "note": row.note,
                "links": row.links, "set_by": row.set_by, "set_at": row.set_at}  # fmt: skip

    @app.post("/v2/evidence-packs/preview", tags=["compliance"],
              dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def preview_pack(
        body: PackIn, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        """What a pack for this period would hold, without generating or signing it."""
        try:
            ev = pack.collect(s, org, body.start, body.end, body.frameworks)
        except pack.PackError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {**pack.summary(ev), "signing": pack.signing_configured(),
                "disclaimer": compliance.DISCLAIMER}  # fmt: skip

    @app.post("/v2/evidence-packs", response_model=PackOut, status_code=201, tags=["compliance"],
              dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def create_pack(
        body: PackIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> PackOut:
        try:
            row = pack.create(s, org, body.start, body.end, body.frameworks, actor=auth.actor)
        except pack.PackError as exc:
            raise HTTPException(422, str(exc)) from exc
        except pack.SigningError as exc:
            raise HTTPException(503, str(exc)) from exc
        return _pack_out(row)

    @app.get("/v2/evidence-packs", response_model=list[PackOut], tags=["compliance"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def list_packs(s: Session = Depends(db), org: str = Depends(current_org)) -> list[PackOut]:
        rows = s.scalars(
            select(EvidencePack)
            .where(EvidencePack.org_id == org)
            .order_by(EvidencePack.created_at.desc())
            .limit(100)
        )
        return [_pack_out(p) for p in rows]

    @app.get("/v2/evidence-packs/{pack_id}/bundle", tags=["compliance"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def get_pack_bundle(
        pack_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> Response:
        p = s.get(EvidencePack, pack_id) if _UUID.match(pack_id) else None
        if p is None or p.org_id != org:
            raise HTTPException(404, "evidence pack not found")
        name = f"evidence-pack-{p.period_start}-{p.period_end}.zip"
        return Response(
            content=p.bundle,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{name}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
                "X-Content-SHA256": p.sha256,
            },
        )
