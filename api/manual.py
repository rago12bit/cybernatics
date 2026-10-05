"""Manual findings API (Week 59, plan §43.2, ADR-0044).

    POST /v2/cvss/v4                         score a CVSS 4.0 vector (the calculator's one source)
    GET  /v2/cwe?q=                          search weaknesses for the CWE picker
    GET  /v2/projects/{id}/routes            routes code intelligence found (the route picker)
    POST /v2/projects/{id}/manual-findings   record a finding; it becomes an Issue through ingest
    GET  /v2/projects/{id}/manual-findings   the project's manual findings
    GET  /v2/manual-findings/{id}            one, with its attachments
    POST /v2/manual-findings/{id}/attachments    add evidence (screenshot, HTTP capture)
    POST /v2/attachments/{id}/link           a short-lived download link
    GET  /v2/attachments/{id}/download       the file, by link only: always a download, never shown

Recording a finding is `ingest:write` (it is an ingest source, ADR-0040); reading is `ingest:read`.
A field error comes back as 422 with `{"field", "message"}`, so the form can show it next to the
field. The download endpoint takes no bearer token: the signed link is the credential, scoped to
one attachment and one organization for five minutes, which lets it be served from an origin that
holds no cookies and no tokens at all (threat T24).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.manual import attachments, cvss4, cwe, service
from core.manual.routes import latest_routes
from core.persistence import repo
from core.persistence.models import EvidenceAttachment, ManualFinding
from core.tenancy import set_session_org

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class CvssIn(BaseModel):
    vector: str = Field(max_length=300)


class CvssOut(BaseModel):
    vector: str = Field(description="Normalized: metrics in the specification's order.")
    score: float
    rating: str = Field(description="FIRST's rating: None, Low, Medium, High, Critical.")
    severity: str = Field(description="Bulwark's severity; a 0.0 score is INFO.")


class CweOut(BaseModel):
    id: str
    name: str = Field(description="Empty for a valid CWE the bundled catalogue does not describe.")


class RouteOut(BaseModel):
    method: str
    route: str
    path: str
    line: int
    symbol: str
    framework: str


class RoutesOut(BaseModel):
    scan_id: str | None = Field(
        description="The scan the routes come from; null when none has any."
    )
    routes: list[RouteOut]


class ManualIn(BaseModel):
    title: str = Field(max_length=1000)
    cwe: str | None = Field(default=None, max_length=20)
    cvss_vector: str | None = Field(default=None, max_length=300)
    severity: str | None = Field(default=None, description="Only when there is no CVSS vector.")
    location_kind: str = Field(default="route", description="'route' or 'file'.")
    method: str | None = Field(default=None, max_length=10)
    route: str | None = Field(default=None, max_length=1000)
    host: str | None = Field(default=None, max_length=300)
    path: str | None = Field(default=None, max_length=2000)
    line: int | None = None
    steps: str = Field(default="", max_length=40_000)
    impact: str = Field(default="", max_length=40_000)
    recommendation: str = Field(default="", max_length=40_000)
    references: list[str] = Field(default_factory=list)
    engagement_id: str | None = None
    test_name: str | None = Field(default=None, max_length=200)


class AttachmentOut(BaseModel):
    id: str
    file_name: str
    declared_type: str | None
    sniffed_type: str = Field(description="What the bytes are, whatever they were called.")
    active_content: bool = Field(description="HTML, SVG, XML or PDF: could run script if rendered.")
    size_bytes: int
    sha256: str
    encrypted: bool
    created_at: datetime


class ManualOut(BaseModel):
    id: str
    issue_id: str
    import_id: str | None
    asset_id: str
    test_id: str
    title: str
    cwe: str | None
    cwe_name: str | None
    severity: str
    cvss_vector: str | None
    cvss_score: float | None
    location_kind: str
    method: str | None
    route: str | None
    host: str | None
    path: str | None
    line: int | None
    steps: str
    impact: str
    recommendation: str
    references: list[str]
    related_issue_id: str | None = Field(
        description="An automated Issue on the same handler with a related CWE, whose taint path "
        "this finding carries."
    )
    related_source: str | None
    created_by: str | None
    created_at: datetime
    attachments: list[AttachmentOut] = []


class RecordedOut(BaseModel):
    manual: ManualOut
    issue_id: str
    import_id: str
    created: bool = Field(description="False when the same finding was already recorded.")


class LinkOut(BaseModel):
    url: str
    expires_at: datetime


def _attachment(a: EvidenceAttachment) -> AttachmentOut:
    return AttachmentOut(
        id=a.id, file_name=a.file_name, declared_type=a.declared_type, sniffed_type=a.sniffed_type,
        active_content=a.active_content, size_bytes=a.size_bytes, sha256=a.sha256,
        encrypted=a.encrypted, created_at=a.created_at,
    )  # fmt: skip


def _manual(row: ManualFinding, files: list[EvidenceAttachment] | None = None) -> ManualOut:
    return ManualOut(
        id=row.id, issue_id=row.issue_id, import_id=row.import_id, asset_id=row.asset_id,
        test_id=row.test_id, title=row.title, cwe=row.cwe,
        cwe_name=cwe.name_of(row.cwe) if row.cwe else None, severity=row.severity,
        cvss_vector=row.cvss_vector, cvss_score=row.cvss_score, location_kind=row.location_kind,
        method=row.method, route=row.route, host=row.host, path=row.path, line=row.line,
        steps=row.steps, impact=row.impact, recommendation=row.recommendation,
        references=list(row.references or []), related_issue_id=row.related_issue_id,
        related_source=row.related_source, created_by=row.created_by, created_at=row.created_at,
        attachments=[_attachment(a) for a in files or []],
    )  # fmt: skip


def _project(s: Session, project_id: str, org: str) -> None:
    if not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None:
        raise HTTPException(404, "project not found")


def _get_manual(s: Session, manual_id: str, org: str) -> ManualFinding:
    row = service.get(s, manual_id, org) if _UUID.match(manual_id) else None
    if row is None:
        raise HTTPException(404, "manual finding not found")
    return row


def register_manual_routes(app: FastAPI) -> None:
    @app.post("/v2/cvss/v4", response_model=CvssOut, tags=["manual findings"],
              dependencies=[Depends(require_auth)])  # fmt: skip
    def score_cvss(body: CvssIn) -> CvssOut:
        try:
            return CvssOut(**cvss4.score(body.vector).to_dict())  # type: ignore[arg-type]
        except cvss4.CvssError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/v2/cwe", response_model=list[CweOut], tags=["manual findings"],
             dependencies=[Depends(require_auth)])  # fmt: skip
    def search_cwe(
        q: str = Query("", max_length=100), limit: int = Query(20, ge=1, le=50)
    ) -> list[CweOut]:
        return [CweOut(id=i, name=n) for i, n in cwe.search(q, limit)]

    @app.get(
        "/v2/projects/{project_id}/routes",
        response_model=RoutesOut,
        tags=["manual findings"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_routes(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> RoutesOut:
        _project(s, project_id, org)
        found = latest_routes(s, project_id, org)
        return RoutesOut(
            scan_id=found.scan_id, routes=[RouteOut(**r.to_dict()) for r in found.routes]  # type: ignore[arg-type]
        )

    @app.post(
        "/v2/projects/{project_id}/manual-findings",
        status_code=201,
        response_model=RecordedOut,
        tags=["manual findings"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def record_manual(
        project_id: str,
        body: ManualIn,
        response: Response,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RecordedOut:
        _project(s, project_id, org)
        try:
            done = service.record(
                s,
                org_id=org,
                asset_id=project_id,
                body=service.ManualFindingIn(**body.model_dump()),
                created_by=auth.actor,
            )
        except service.ManualFindingError as exc:
            raise HTTPException(422, {"field": exc.field, "message": str(exc)}) from exc
        if not done.created:
            response.status_code = 200
        return RecordedOut(
            manual=_manual(done.manual, attachments.list_for(s, done.manual.id, org)),
            issue_id=done.issue_id,
            import_id=done.import_id,
            created=done.created,
        )

    @app.get(
        "/v2/projects/{project_id}/manual-findings",
        response_model=list[ManualOut],
        tags=["manual findings"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_manual(
        project_id: str,
        issue_id: str | None = Query(None),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[ManualOut]:
        _project(s, project_id, org)
        rows = (
            service.for_issue(s, issue_id, org)
            if issue_id
            else service.for_project(s, project_id, org)
        )
        return [
            _manual(r, attachments.list_for(s, r.id, org)) for r in rows if r.asset_id == project_id
        ]

    @app.get(
        "/v2/manual-findings/{manual_id}",
        response_model=ManualOut,
        tags=["manual findings"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def get_manual(
        manual_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ManualOut:
        row = _get_manual(s, manual_id, org)
        return _manual(row, attachments.list_for(s, row.id, org))

    @app.post(
        "/v2/manual-findings/{manual_id}/attachments",
        status_code=201,
        response_model=AttachmentOut,
        tags=["manual findings"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    async def add_attachment(
        manual_id: str,
        file: UploadFile = File(...),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> AttachmentOut:
        row = _get_manual(s, manual_id, org)
        data = await file.read(attachments.MAX_BYTES + 1)
        try:
            stored = attachments.store(
                s,
                manual=row,
                data=data,
                file_name=file.filename,
                declared_type=file.content_type,
                created_by=auth.actor,
                openbao_addr=st.settings.openbao_addr,
                openbao_token=st.settings.openbao_token,
            )
        except attachments.AttachmentError as exc:
            s.rollback()
            raise HTTPException(413 if "10 MB" in str(exc) else 422, str(exc)) from exc
        return _attachment(stored)

    @app.post(
        "/v2/attachments/{attachment_id}/link",
        response_model=LinkOut,
        tags=["manual findings"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def attachment_link(
        attachment_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> LinkOut:
        row = attachments.get(s, attachment_id, org) if _UUID.match(attachment_id) else None
        if row is None:
            raise HTTPException(404, "attachment not found")
        token, expires = attachments.sign(attachments.link_key(st.settings.api_token), row.id, org)
        base = st.settings.attachments_origin
        return LinkOut(
            url=f"{base}/v2/attachments/{row.id}/download?token={token}",
            expires_at=datetime.fromtimestamp(expires, tz=timezone.utc),
        )

    @app.get("/v2/attachments/{attachment_id}/download", tags=["manual findings"])
    def download_attachment(
        attachment_id: str, token: str = Query(..., max_length=400), st: AppState = Depends(state)
    ) -> Response:
        org = (
            attachments.verify(attachments.link_key(st.settings.api_token), attachment_id, token)
            if _UUID.match(attachment_id)
            else None
        )
        if org is None:
            raise HTTPException(404, "this link is not valid or has expired")
        with st.sessions() as s:
            set_session_org(s, org)
            row = attachments.get(s, attachment_id, org)
            if row is None:
                raise HTTPException(404, "this link is not valid or has expired")
            try:
                data = attachments.read(
                    row,
                    openbao_addr=st.settings.openbao_addr,
                    openbao_token=st.settings.openbao_token,
                )
            except attachments.AttachmentError as exc:
                raise HTTPException(503, str(exc)) from exc
            return Response(content=data, headers=attachments.download_headers(row))
