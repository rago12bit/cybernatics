"""Risk acceptance API (Week 62, plan §44.2, §55.3, ADR-0046).

    GET  /v2/risk-acceptance-policy                  the maximum length, and who may approve
    POST /v2/projects/{id}/risk-acceptances          request one (the Issues stay open)
    GET  /v2/projects/{id}/risk-acceptances          the project's, newest first
    GET  /v2/risk-acceptances?state=requested        the organization's (the approvals queue)
    GET  /v2/risk-acceptances/{id}                   one, with its Issues, proof and audit trail
    POST /v2/risk-acceptances/{id}/approve           four-eyes: not the requester, a personal token
    POST /v2/risk-acceptances/{id}/reject            the same rule, with a reason
    POST /v2/risk-acceptances/{id}/withdraw          the requester takes it back
    POST /v2/risk-acceptances/{id}/expire            expire now: the Issues reopen
    POST /v2/risk-acceptances/{id}/reinstate         undo "expire now", within the approved dates
    POST /v2/risk-acceptances/{id}/extend            a new request for a later date
    POST /v2/risk-acceptances/{id}/attachments       add proof (encrypted; downloaded by link)

Reading is `scans:read`; everything else `scans:write`. The rules live in
`core.acceptance.service`, so the screens cannot be the only thing enforcing them.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.acceptance import service
from core.manual import attachments
from core.persistence import repo
from core.persistence.models import AuditEntry, EvidenceAttachment, RiskAcceptance

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class IssueBrief(BaseModel):
    id: str
    title: str
    severity: str
    path: str
    state: str
    triage_status: str


class ProofFile(BaseModel):
    id: str
    file_name: str
    content_type: str
    active_content: bool
    size_bytes: int
    created_at: datetime


class TrailEntry(BaseModel):
    at: datetime
    actor: str
    action: str


class AcceptanceOut(BaseModel):
    id: str
    project_id: str
    project: str
    decision: str
    justification: str
    controls: str
    proof_links: list[str]
    proof_files: list[ProofFile] = []
    expires_at: datetime
    days: int = Field(description="Whole days from the request to the expiry.")
    restart_sla: bool
    state: str
    requested_by: str
    requested_at: datetime
    approver: str | None
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    ended_at: datetime | None
    ended_by: str | None
    ended_reason: str | None
    extends_id: str | None
    legacy: bool
    issue_count: int
    issues: list[IssueBrief] = []
    trail: list[TrailEntry] = []
    can_decide: bool = Field(description="Whether the caller may approve or reject it.")
    names: dict[str, str] = Field(
        default_factory=dict, description="Each actor's token name, to show people, not prefixes."
    )


class RequestIn(BaseModel):
    issue_ids: list[str] = Field(min_length=1, max_length=service.MAX_ISSUES)
    decision: str
    justification: str = Field(default="", max_length=4000)
    controls: str = Field(default="", max_length=4000)
    proof_links: list[str] = Field(default_factory=list, max_length=20)
    expires_at: datetime | None = None
    restart_sla: bool = False
    approver: str | None = Field(default=None, max_length=200)


class NoteIn(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ExtendIn(BaseModel):
    expires_at: datetime | None = None
    justification: str | None = Field(default=None, max_length=4000)


class Approver(BaseModel):
    actor: str
    name: str


class PolicyOut(BaseModel):
    max_days: int
    you: str
    approvers: list[Approver]
    can_approve: bool = Field(description="False with the shared token: it could be anyone.")


def _error(exc: service.AcceptanceError) -> HTTPException:
    return HTTPException(
        exc.status, {"field": exc.field, "message": str(exc)} if exc.field else str(exc)
    )


def _can_decide(ra: RiskAcceptance, actor: str) -> bool:
    try:
        service._decider(ra, actor)
    except service.AcceptanceError:
        return False
    return True


def _out(s: Session, ra: RiskAcceptance, actor: str, full: bool = False) -> AcceptanceOut:
    asset = repo.get_asset(s, ra.asset_id, org_id=ra.org_id)
    rows = service.issues_of(s, ra.id) if full else []
    count = len(rows) if full else len(service.issue_ids_of(s, ra.id))
    requested = ra.requested_at
    out = AcceptanceOut(
        id=ra.id, project_id=ra.asset_id, project=asset.label if asset else ra.asset_id,
        decision=ra.decision, justification=ra.justification, controls=ra.controls,
        proof_links=list(ra.proof_links or []), expires_at=ra.expires_at,
        days=max((ra.expires_at - requested).days, 0), restart_sla=ra.restart_sla,
        state=ra.state, requested_by=ra.requested_by, requested_at=ra.requested_at,
        approver=ra.approver, decided_by=ra.decided_by, decided_at=ra.decided_at,
        decision_note=ra.decision_note, ended_at=ra.ended_at, ended_by=ra.ended_by,
        ended_reason=ra.ended_reason, extends_id=ra.extends_id, legacy=ra.legacy,
        issue_count=count, can_decide=_can_decide(ra, actor),
    )  # fmt: skip
    if full:
        out.issues = [
            IssueBrief(id=i.id, title=i.title, severity=i.severity, path=i.path, state=i.state,
                       triage_status=i.triage_status)  # fmt: skip
            for i in rows
        ]
        out.proof_files = [
            ProofFile(id=f.id, file_name=f.file_name, content_type=f.sniffed_type,
                      active_content=f.active_content, size_bytes=f.size_bytes,
                      created_at=f.created_at)  # fmt: skip
            for f in s.scalars(
                select(EvidenceAttachment)
                .where(EvidenceAttachment.risk_acceptance_id == ra.id)
                .order_by(EvidenceAttachment.created_at)
            )
        ]
        out.trail = [
            TrailEntry(at=e.timestamp, actor=e.actor, action=e.action.split(".", 1)[-1])
            for e in s.scalars(
                select(AuditEntry)
                .where(AuditEntry.target == f"risk_acceptance:{ra.id}")
                .order_by(AuditEntry.seq)
            )
        ]
    actors = {
        ra.requested_by,
        ra.approver,
        ra.decided_by,
        ra.ended_by,
        *(e.actor for e in out.trail),
    }
    out.names = _names(s, ra.org_id, {a for a in actors if a})
    return out


def _names(s: Session, org: str, actors: set[str]) -> dict[str, str]:
    from core.collab.people import names

    return names(s, org, actors)


def _get(s: Session, acceptance_id: str, org: str) -> RiskAcceptance:
    ra = service.get(s, acceptance_id, org) if _UUID.match(acceptance_id) else None
    if ra is None:
        raise HTTPException(404, "risk acceptance not found")
    return ra


def register_acceptance_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/risk-acceptance-policy",
        response_model=PolicyOut,
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def policy(
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> PolicyOut:
        return PolicyOut(
            max_days=st.settings.risk_acceptance_max_days,
            you=auth.actor,
            approvers=[Approver(**a) for a in service.approvers(s, org, excluding=auth.actor)],
            can_approve=auth.actor != service.SHARED,
        )

    @app.post(
        "/v2/projects/{project_id}/risk-acceptances",
        status_code=201,
        response_model=AcceptanceOut,
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def request_acceptance(
        project_id: str,
        body: RequestIn,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> AcceptanceOut:
        if not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None:
            raise HTTPException(404, "project not found")
        try:
            ra = service.request(
                s, org_id=org, asset_id=project_id, issue_ids=body.issue_ids,
                decision=body.decision, justification=body.justification, controls=body.controls,
                proof_links=body.proof_links, expires_at=body.expires_at,
                restart_sla=body.restart_sla, approver=body.approver, actor=auth.actor,
                max_days=st.settings.risk_acceptance_max_days,
            )  # fmt: skip
        except service.AcceptanceError as exc:
            s.rollback()
            raise _error(exc) from exc
        _notify(s, org, "requested", ra)
        return _out(s, ra, auth.actor, full=True)

    @app.get(
        "/v2/projects/{project_id}/risk-acceptances",
        response_model=list[AcceptanceOut],
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def project_acceptances(
        project_id: str,
        issue_id: str | None = Query(None),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> list[AcceptanceOut]:
        if not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None:
            raise HTTPException(404, "project not found")
        rows = service.list_for(s, org, asset_id=project_id, issue_id=issue_id)
        return [_out(s, r, auth.actor) for r in rows]

    @app.get(
        "/v2/risk-acceptances",
        response_model=list[AcceptanceOut],
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def all_acceptances(
        state_: list[str] | None = Query(None, alias="state"),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> list[AcceptanceOut]:
        return [_out(s, r, auth.actor) for r in service.list_for(s, org, states=state_)]

    @app.get(
        "/v2/risk-acceptances/{acceptance_id}",
        response_model=AcceptanceOut,
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def one(
        acceptance_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> AcceptanceOut:
        return _out(s, _get(s, acceptance_id, org), auth.actor, full=True)

    def _run(
        name: str, fn: Any, acceptance_id: str, body: Any, st: AppState, s: Session, org: str,
        auth: AuthContext,
    ) -> AcceptanceOut:  # fmt: skip
        ra = _get(s, acceptance_id, org)
        try:
            result = fn(s, ra, auth.actor, body, st)
        except service.AcceptanceError as exc:
            s.rollback()
            raise _error(exc) from exc
        if name in ("approve", "reject"):
            _notify(s, org, "approved" if name == "approve" else "rejected", result)
        elif name == "extend":
            _notify(s, org, "requested", result)
        return _out(s, result, auth.actor, full=True)

    def _act(name: str, fn: Any) -> None:
        @app.post(
            f"/v2/risk-acceptances/{{acceptance_id}}/{name}",
            response_model=AcceptanceOut,
            tags=["risk acceptance"],
            dependencies=[Depends(require_scope("scans:write"))],
            name=f"risk_acceptance_{name}",
        )
        def act(
            acceptance_id: str,
            body: NoteIn | None = None,
            st: AppState = Depends(state),
            s: Session = Depends(db),
            org: str = Depends(current_org),
            auth: AuthContext = Depends(require_auth),
        ) -> AcceptanceOut:
            return _run(name, fn, acceptance_id, body, st, s, org, auth)

    _act("approve", lambda s, ra, a, b, st: service.approve(s, ra, actor=a, note=b and b.note))
    _act("reject", lambda s, ra, a, b, st: service.reject(s, ra, actor=a, note=b and b.note))
    _act("withdraw", lambda s, ra, a, b, st: service.withdraw(s, ra, actor=a))
    _act("expire", lambda s, ra, a, b, st: service.expire_now(s, ra, actor=a))
    _act("reinstate", lambda s, ra, a, b, st: service.reinstate(s, ra, actor=a))

    @app.post(
        "/v2/risk-acceptances/{acceptance_id}/extend",
        response_model=AcceptanceOut,
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def extend(
        acceptance_id: str,
        body: ExtendIn,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> AcceptanceOut:
        def fn(s: Session, ra: RiskAcceptance, a: str, b: ExtendIn, st: AppState) -> Any:
            return service.extend(
                s, ra, expires_at=b.expires_at, justification=b.justification, actor=a,
                max_days=st.settings.risk_acceptance_max_days,
            )  # fmt: skip

        return _run("extend", fn, acceptance_id, body, st, s, org, auth)

    @app.post(
        "/v2/risk-acceptances/{acceptance_id}/attachments",
        status_code=201,
        response_model=ProofFile,
        tags=["risk acceptance"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    async def add_proof(
        acceptance_id: str,
        file: UploadFile = File(...),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> ProofFile:
        ra = _get(s, acceptance_id, org)
        if ra.state not in service.LIVE:
            raise HTTPException(409, f"this acceptance is {ra.state}; proof can no longer change")
        data = await file.read(attachments.MAX_BYTES + 1)
        try:
            row = attachments.store(
                s, acceptance=ra, data=data, file_name=file.filename,
                declared_type=file.content_type, created_by=auth.actor,
                openbao_addr=st.settings.openbao_addr, openbao_token=st.settings.openbao_token,
            )  # fmt: skip
        except attachments.AttachmentError as exc:
            s.rollback()
            raise HTTPException(422, str(exc)) from exc
        repo.append_audit_entry(
            s, actor=auth.actor, action="risk_acceptance.proof_added",
            target=f"risk_acceptance:{ra.id}",
            payload={"org_id": org, "attachment_id": row.id, "sha256": row.sha256},
        )  # fmt: skip
        return ProofFile(id=row.id, file_name=row.file_name, content_type=row.sniffed_type,
                         active_content=row.active_content, size_bytes=row.size_bytes,
                         created_at=row.created_at)  # fmt: skip


def _notify(s: Session, org: str, event: str, ra: RiskAcceptance) -> None:
    try:
        service.notify_integrations(s, org, event, ra)
    except Exception:  # noqa: BLE001 - a dying notification must not fail the request
        service.log.warning("risk acceptance notification failed", exc_info=True)
