"""Calendar API (plan §49): engagements, SLA due dates and expiring risk acceptances.

    GET /v2/calendar?from=2026-10-01&to=2026-10-31&project_id=&kinds=engagement,sla,acceptance

Dates are UTC days; a range is at most 100 days. Reading is `scans:read`.
"""

from __future__ import annotations

import re
from datetime import date

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import current_org, db, require_scope
from core import calendar
from core.persistence import repo

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class EntryOut(BaseModel):
    kind: str
    start: date
    end: date
    title: str
    project_id: str
    project: str
    link: str
    detail: str
    severity: str | None
    state: str | None


class CalendarOut(BaseModel):
    start: date
    end: date
    entries: list[EntryOut]
    counts: dict[str, int]
    truncated: list[str]


def register_calendar_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/calendar",
        response_model=CalendarOut,
        tags=["calendar"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_calendar(
        start: date = Query(alias="from"),
        end: date = Query(alias="to"),
        project_id: str | None = Query(default=None),
        kinds: str = Query(default=",".join(calendar.KINDS)),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> CalendarOut:
        if project_id is not None and (
            not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None
        ):
            raise HTTPException(404, "project not found")
        wanted = tuple(k.strip() for k in kinds.split(",") if k.strip())
        try:
            cal = calendar.build(s, org, start, end, project_id=project_id, kinds=wanted)
        except calendar.CalendarError as exc:
            raise HTTPException(422, {"field": exc.field, "message": str(exc)}) from exc
        counts = {k: sum(1 for e in cal.entries if e.kind == k) for k in calendar.KINDS}
        return CalendarOut(
            start=cal.start,
            end=cal.end,
            entries=[EntryOut(**e.to_dict()) for e in cal.entries],
            counts=counts,
            truncated=cal.truncated,
        )
