"""Reports API (plan §48.3).

    GET    /v2/report-templates
    GET    /v2/reports                         POST (from a template or blocks)
    GET    /v2/reports/{id}                    PUT {version, ...}; DELETE
    POST   /v2/reports/{id}/summary/draft      the model drafts the executive summary
    POST   /v2/reports/{id}/summary/review     a person confirms it (as edited): {version, text}
    POST   /v2/reports/{id}/runs               generate the PDF (signed when a key is set up)
    GET    /v2/reports/{id}/runs
    GET    /v2/report-runs/{id}/pdf            GET /v2/report-runs/{id}/signature
    POST   /v2/report-runs/{id}/links {days}   a link that needs no sign-in; shown once
    GET    /v2/report-runs/{id}/links          DELETE /v2/report-links/{id} (revoke)
    GET    /r/{token}                          the PDF behind a link (no sign-in)
    GET    /r/{token}/signature                its cosign signature bundle

Reading needs `scans:read`; changing, generating and sharing need `scans:write`. Drafting and
confirming the summary need a personal token: the reviewer's name is printed in the report.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.llm import budget as llm_budget
from core.llm.limits import LimitExceeded
from core.persistence.models import ReportRun
from core.reports import service as svc
from core.reports import summary as drafting
from core.reports.blocks import Period, ReportError, collect
from core.tenancy import set_session_org

_NO_SUCH_LINK = "This link doesn't work: it may have expired or been revoked."


class ReportIn(BaseModel):
    """Checked field by field in `core.reports` (a 422 names the field), so loose here."""

    name: Any = None
    template: Any = None
    period_days: Any = None
    blocks: Any = None
    schedule: Any = None
    version: Any = None


class ReviewIn(BaseModel):
    version: Any = None
    text: Any = None


class LinkIn(BaseModel):
    days: Any = 14


def _fail(s: Session, exc: ReportError) -> HTTPException:
    s.rollback()
    return HTTPException(exc.status, {"field": exc.field, "message": exc.message})


def _person(auth: AuthContext) -> None:
    if not auth.actor.startswith("token:"):
        message = (
            "The shared token is nobody: sign in with a personal token to draft or confirm a "
            "summary."
        )
        raise HTTPException(409, {"field": "token", "message": message})


def _pdf(run: ReportRun, disposition: str) -> Response:
    assert run.pdf is not None
    name = f"{run.report_name[:60]}-{run.period_end.isoformat()}.pdf"
    safe = "".join(c if c.isalnum() or c in "-._ " else "_" for c in name).replace(" ", "-")
    return Response(run.pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'{disposition}; filename="{safe}"',
        "X-Report-SHA256": run.sha256, "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "X-Robots-Tag": "noindex, nofollow",
    })  # fmt: skip


def register_report_routes(app: FastAPI) -> None:
    read = [Depends(require_scope("scans:read"))]
    write = [Depends(require_scope("scans:write"))]

    @app.get("/v2/report-templates", tags=["reports"], dependencies=read)
    def report_templates() -> list[dict[str, Any]]:
        return svc.templates()

    @app.get("/v2/reports", tags=["reports"], dependencies=read)
    def list_reports(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[dict[str, Any]]:
        return [svc.view(r) for r in svc.listing(s, org)]

    @app.post("/v2/reports", tags=["reports"], dependencies=write, status_code=201)
    def create_report(
        body: ReportIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return svc.view(svc.create(s, org, auth.actor, body.model_dump(exclude_unset=True)))
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/reports/{report_id}", tags=["reports"], dependencies=read)
    def get_report(
        report_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        try:
            return svc.view(svc.get(s, org, report_id))
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.put("/v2/reports/{report_id}", tags=["reports"], dependencies=write)
    def save_report(
        report_id: str,
        body: ReportIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        raw = body.model_dump(exclude_unset=True)
        try:
            return svc.view(svc.update(s, org, auth.actor, report_id, raw))
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.delete("/v2/reports/{report_id}", tags=["reports"], dependencies=write, status_code=204)
    def delete_report(
        report_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        try:
            svc.delete(s, org, auth.actor, report_id)
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/reports/{report_id}/summary/draft", tags=["reports"], dependencies=write)
    def draft_summary(
        report_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        """The model drafts the summary from the report's own data. Sends that data (numbers, and
        a few Issue titles marked as untrusted) to the model provider."""
        _person(auth)
        if st.llm_report is None:
            message = "No model is set up for report summaries here; write the summary instead."
            raise HTTPException(409, {"field": "model", "message": message})
        try:
            r = svc.get(s, org, report_id)
            svc._summary_block(r)
            period = Period.last(r.period_days)
            collected = collect(s, org, r.blocks, period)
            st.limiter.acquire()
            llm_budget.check_org(s, org, st.llm_budget)
        except ReportError as exc:
            raise _fail(s, exc) from exc
        except LimitExceeded as exc:
            raise HTTPException(
                429, str(exc), headers={"Retry-After": str(exc.retry_after)}
            ) from exc
        except llm_budget.BudgetExceeded as exc:
            raise HTTPException(429, str(exc)) from exc
        d = drafting.draft(st.llm_report, collected, f"{period.start} to {period.end}")
        if d is None:
            raise HTTPException(502, {"field": "model", "message": "The model's draft could not "
                                      "be used. Try again, or write the summary."})  # fmt: skip
        llm_budget.record_org(s, org, d.tokens)
        r = svc.set_draft(s, org, auth.actor, r, d.text, d.model)
        return {**svc.view(r), "notes": d.notes}

    @app.post("/v2/reports/{report_id}/summary/review", tags=["reports"], dependencies=write)
    def review_summary(
        report_id: str,
        body: ReviewIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        _person(auth)
        try:
            raw = body.model_dump(exclude_unset=True)
            return svc.view(svc.review_summary(s, org, auth.actor, report_id, raw))
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/reports/{report_id}/runs", tags=["reports"], dependencies=write,
              status_code=202)  # fmt: skip
    def generate_report(
        report_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        """Queue the report; the worker renders it (GET .../runs shows it done or failed)."""
        try:
            run = svc.request_run(s, org, auth.actor, report_id)
            s.commit()
        except ReportError as exc:
            raise _fail(s, exc) from exc
        if st.enqueue_report is not None:
            st.enqueue_report(run.id, org)
        else:  # no worker (tests, a one-process setup): render here
            run = svc.render_run(s, org, run.id)
            s.commit()
        return svc.run_view(run, svc.people_of(s, org, {run.created_by}))

    @app.get("/v2/reports/{report_id}/runs", tags=["reports"], dependencies=read)
    def report_runs(
        report_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[dict[str, Any]]:
        try:
            found = svc.runs(s, org, report_id)
            people = svc.people_of(s, org, {r.created_by for r in found})
            return [svc.run_view(r, people) for r in found]
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/report-runs/{run_id}/pdf", tags=["reports"], dependencies=read)
    def run_pdf(run_id: str, s: Session = Depends(db), org: str = Depends(current_org)) -> Response:
        try:
            return _pdf(svc.done_run(s, org, run_id), "attachment")
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/report-runs/{run_id}/signature", tags=["reports"], dependencies=read)
    def run_signature(
        run_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> Response:
        try:
            run = svc.get_run(s, org, run_id)
        except ReportError as exc:
            raise _fail(s, exc) from exc
        if run.signature is None:
            raise HTTPException(404, "This report was not signed: no signing key is set up.")
        return Response(run.signature, media_type="application/json", headers={
            "Content-Disposition": 'attachment; filename="report.pdf.sig"'})  # fmt: skip

    @app.post("/v2/report-runs/{run_id}/links", tags=["reports"], dependencies=write,
              status_code=201)  # fmt: skip
    def create_link(
        run_id: str,
        body: LinkIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            link, token = svc.create_link(s, org, auth.actor, run_id, body.days)
        except ReportError as exc:
            raise _fail(s, exc) from exc
        return {**svc.link_view(link), "token": token, "path": f"/r/{token}",
                "url": svc.link_url(token)}  # fmt: skip

    @app.get("/v2/report-runs/{run_id}/links", tags=["reports"], dependencies=read)
    def run_links(
        run_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[dict[str, Any]]:
        try:
            found = svc.links(s, org, run_id)
            people = svc.people_of(s, org, {x.created_by for x in found})
            return [svc.link_view(x, people=people) for x in found]
        except ReportError as exc:
            raise _fail(s, exc) from exc

    @app.delete("/v2/report-links/{link_id}", tags=["reports"], dependencies=write)
    def revoke_link(
        link_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return svc.link_view(svc.revoke_link(s, org, auth.actor, link_id))
        except ReportError as exc:
            raise _fail(s, exc) from exc

    def _open(request: Request, token: str) -> tuple[Session, ReportRun]:
        s = state(request).sessions()
        link = svc.resolve_link(s, token)
        if link is None:
            s.close()
            raise HTTPException(404, _NO_SUCH_LINK)
        set_session_org(s, link.org_id)  # the PDF is read under RLS, as the link's organization
        run = s.get(ReportRun, link.run_id)
        if run is None or run.org_id != link.org_id:
            s.close()
            raise HTTPException(404, _NO_SUCH_LINK)
        svc.opened(s, link)
        return s, run

    @app.get("/r/{token}", tags=["reports"], include_in_schema=False)
    def open_link(token: str, request: Request) -> Response:
        s, run = _open(request, token)
        try:
            return _pdf(run, "inline")
        finally:
            s.close()

    @app.get("/r/{token}/signature", tags=["reports"], include_in_schema=False)
    def open_link_signature(token: str, request: Request) -> Response:
        s, run = _open(request, token)
        try:
            if run.signature is None:
                raise HTTPException(404, "This report was not signed.")
            return Response(run.signature, media_type="application/json", headers={
                "Content-Disposition": 'attachment; filename="report.pdf.sig"'})  # fmt: skip
        finally:
            s.close()
