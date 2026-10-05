"""The retest API (Week 64, plan §43.3).

    GET  /v2/issues/{id}/retest        the Issue's retest: status, who asked and decided, the note,
                                       whether a targeted retest is possible (and what it re-runs),
                                       and the latest targeted runs
    POST /v2/issues/{id}/retest        a step: request, confirm_fixed, reproduced (note required),
                                       cancel
    POST /v2/issues/{id}/retest/run    start a targeted retest: the one rule or DAST template,
                                       against the one location; 202, runs in the background

Reading is `scans:read`; each step is `scans:write` and audit-logged.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope, state
from core.collab.people import names
from core.persistence import repo
from core.persistence.models import IssueRow, RetestRun
from core.retest import service, targeted
from core.tenancy import scoped_sessions

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class OfferOut(BaseModel):
    available: bool
    kind: str | None = Field(description="rule or dast")
    tool: str | None
    rule: str | None
    location: str | None
    reason: str | None = Field(description="Why there is no targeted retest, when there is none.")


class RunOut(BaseModel):
    id: str
    kind: str
    tool: str
    rule: str
    location: str
    status: str = Field(description="queued, running, done or failed (the check could not run).")
    result: str | None = Field(description="still_present or gone, once done.")
    detail: str | None
    requested_by: str | None
    created_at: datetime
    finished_at: datetime | None


class RetestOut(BaseModel):
    issue_id: str
    state: str
    status: str | None = Field(description="requested, passed, failed, or null.")
    requested_at: datetime | None
    requested_by: str | None
    note: str | None
    decided_at: datetime | None
    decided_by: str | None
    targeted: OfferOut
    runs: list[RunOut]
    names: dict[str, str]


class StepIn(BaseModel):
    action: str = Field(description="request, confirm_fixed, reproduced, cancel")
    note: str | None = Field(default=None, max_length=5000)


def issue_for(s: Session, issue_id: str, org: str) -> IssueRow:
    issue = repo.get_issue(s, issue_id, org_id=org) if _UUID.match(issue_id) else None
    if issue is None:
        raise HTTPException(404, "issue not found")
    return issue


def _run_out(r: RetestRun) -> RunOut:
    return RunOut(
        id=r.id, kind=r.kind, tool=r.tool, rule=r.rule, location=r.location, status=r.status,
        result=r.result, detail=r.detail, requested_by=r.requested_by, created_at=r.created_at,
        finished_at=r.finished_at,
    )  # fmt: skip


def _out(s: Session, issue: IssueRow, org: str) -> RetestOut:
    o = targeted.offer(s, issue)
    t = o.target
    runs = targeted.runs(s, issue.id)
    actors = {a for a in (issue.retest_requested_by, issue.retest_decided_by) if a}
    actors |= {r.requested_by for r in runs if r.requested_by}
    return RetestOut(
        issue_id=issue.id,
        state=issue.state,
        **service.view(issue),
        targeted=OfferOut(
            available=t is not None,
            kind=t.kind if t else None,
            tool=t.tool if t else None,
            rule=t.rule if t else None,
            location=t.location if t else None,
            reason=o.reason,
        ),
        runs=[_run_out(r) for r in runs],
        names=names(s, org, actors),
    )


def _bad(exc: service.RetestError) -> HTTPException:
    status = 409 if exc.field == "action" else 422
    return HTTPException(status, {"field": exc.field, "message": str(exc)})


def _run_here(factory: Any, org: str, run_id: str) -> Callable[[], None]:
    def run() -> None:
        with scoped_sessions(factory, org)() as s:
            targeted.run(s, run_id)

    return run


def register_retest_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/issues/{issue_id}/retest",
        response_model=RetestOut,
        tags=["retests"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_retest(
        issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> RetestOut:
        return _out(s, issue_for(s, issue_id, org), org)

    @app.post(
        "/v2/issues/{issue_id}/retest",
        response_model=RetestOut,
        tags=["retests"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def step(
        issue_id: str,
        body: StepIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RetestOut:
        issue = issue_for(s, issue_id, org)
        try:
            service.act(s, issue, body.action, actor=auth.actor, note=body.note)
        except service.RetestError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return _out(s, issue, org)

    @app.post(
        "/v2/issues/{issue_id}/retest/run",
        response_model=RetestOut,
        status_code=202,
        tags=["retests"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def run_targeted(
        issue_id: str,
        request: Request,
        background: BackgroundTasks,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RetestOut:
        issue = issue_for(s, issue_id, org)
        try:
            run = targeted.start(s, issue, actor=auth.actor)
        except service.RetestError as exc:
            s.rollback()
            raise _bad(exc) from exc
        st = state(request)
        if st.enqueue_retest is not None:
            st.enqueue_retest(run.id, org)
        else:  # no worker: after the response, in this process
            background.add_task(_run_here(st.sessions, org, run.id))
        return _out(s, issue, org)
