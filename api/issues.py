"""Issues across the organization (Week 73, plan §56): the query language, pages by cursor.

    GET /v2/issues?q=&sort=&after=&limit=     one page of matching Issues, the next page's cursor,
                                              and how many match (exact, or "more than
                                              10,000" when it can't be counted quickly)
    GET /v2/issues/parse?q=                   the query as filters and written back canonically,
                                              or the error with the span of text at fault
    GET /v2/issues/suggest?key=&prefix=       values to offer after `key:` (projects, people,
                                              tags, business units, sources)

    GET    /v2/issue-views                    mine, those shared with my role, the built-in ones
    POST   /v2/issue-views                    {name, query, sort?, columns?, shared_with?}
    GET    /v2/issue-views/{id}
    PUT    /v2/issue-views/{id}               {version, ...fields}; 409 if someone saved since
    DELETE /v2/issue-views/{id}
    POST   /v2/issue-views/{id}/copy          make a view I can see (or a built-in one) mine
    POST   /v2/issue-views/import             {views: [{name, query, sort?}]}: browser-saved views
    GET    /v2/me/tables/{table}              my columns and density for a table ("issues")
    PUT    /v2/me/tables/{table}              {columns?, density?}

    POST   /v2/issues/bulk/preview            {q, ids?, action, params}: what it would change, as
                                              counts, before anything is changed
    POST   /v2/issues/bulk                    the same and `expected_count` (the preview's): 409,
                                              changing nothing, if the list changed since
    POST   /v2/issue-batches/{id}/undo        within 10 seconds (core.search.bulk)

`q` uses core.search.language: `priority:P1 sla:breached project:payments-* -status:accepted`.
With no status in it, the list is the active queue (status:open). A query the parser cannot read is
a 422 with `{message, start, end}`, so the query bar can underline the part at fault.

All `scans:read`: this lists what the token can already read, one project at a time, across them;
a saved view or a table's columns are a way of looking at it. Changes to views are audit-logged.
Bulk changes (and their preview, which names people and tags) are `scans:write`, as a single
change to an Issue is.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core import dashboards
from core.search import bulk, views
from core.search import issues as search
from core.search.language import KEYS, QueryError, format_query, parse


class ViewIn(BaseModel):
    """Checked by `core.search.views` field by field (the field named in a 422), so loose here.
    On a save, `version` is the one the edit started from; fields left out stay as they are."""

    name: Any = None
    query: Any = None
    sort: Any = None
    columns: Any = None
    shared_with: Any = None
    version: Any = None


class ImportIn(BaseModel):
    views: Any = None


class BulkIn(BaseModel):
    """Checked by `core.search.bulk`. `ids` narrows the selection to Issues picked one by one;
    without it, every Issue matching `q` is selected."""

    q: Any = ""
    ids: Any = None
    action: Any = None
    params: Any = None
    expected_count: Any = None


def _viewer(s: Session, org: str, auth: AuthContext) -> dashboards.Viewer:
    return dashboards.Viewer(auth.actor, dashboards.role_of(s, org, auth.actor))


def _fail(s: Session, exc: views.ViewError | bulk.BulkError) -> HTTPException:
    s.rollback()
    return HTTPException(exc.status, exc.to_dict())


def _parse(q: str) -> Any:
    try:
        return parse(q)
    except QueryError as exc:
        raise HTTPException(422, exc.to_dict()) from exc


def register_issue_routes(app: FastAPI) -> None:
    read = [Depends(require_scope("scans:read"))]

    @app.get("/v2/issues", tags=["issues"], dependencies=read)
    def list_issues(
        q: str = Query(default="", max_length=2000),
        sort: str = Query(default="priority"),
        after: str | None = Query(default=None, max_length=500),
        limit: int = Query(default=50, ge=1, le=search.MAX_LIMIT),
        count: bool = Query(default=True, description="Leave out the count (paging on)."),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        query = _parse(q)
        ctx = search.Context(auth.actor, datetime.now(timezone.utc))
        try:
            page = search.search(
                s, org, query, ctx=ctx, sort=sort, after=after, limit=limit, with_count=count
            )
        except search.SearchError as exc:
            raise HTTPException(422, {"message": str(exc), "start": 0, "end": 0}) from exc
        page["query"] = format_query(query)
        return page

    @app.get("/v2/issues/parse", tags=["issues"], dependencies=read)
    def parse_query(q: str = Query(default="", max_length=2000)) -> dict[str, Any]:
        query = _parse(q)
        return {"filters": query.to_dict(), "query": format_query(query)}

    @app.get("/v2/issues/suggest", tags=["issues"], dependencies=read)
    def suggest(
        key: str = Query(..., max_length=40),
        prefix: str = Query(default="", max_length=200),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, Any]:
        k = key.lower()
        kind, allowed = KEYS.get(k, ("text", ()))
        if allowed:
            values = [v for v in allowed if v.lower().startswith(prefix.lower())]
        else:
            values = search.suggest(s, org, k, prefix)
        return {"key": k, "values": values}

    def _fields(body: ViewIn) -> dict[str, Any]:
        return body.model_dump(exclude_unset=True)

    @app.get("/v2/issue-views", tags=["issues"], dependencies=read)
    def list_views(
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> list[dict[str, Any]]:
        return views.listing(s, org, _viewer(s, org, auth))

    @app.post("/v2/issue-views", tags=["issues"], dependencies=read, status_code=201)
    def create_view(
        body: ViewIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        who = _viewer(s, org, auth)
        try:
            return views.view(views.create(s, org, who, _fields(body)), who)
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/issue-views/import", tags=["issues"], dependencies=read)
    def import_views(
        body: ImportIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return views.import_views(s, org, _viewer(s, org, auth), body.views)
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/issue-views/{view_id}", tags=["issues"], dependencies=read)
    def get_view(
        view_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return views.resolve(s, org, view_id, _viewer(s, org, auth))
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.put("/v2/issue-views/{view_id}", tags=["issues"], dependencies=read)
    def save_view(
        view_id: str,
        body: ViewIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        who = _viewer(s, org, auth)
        try:
            return views.view(views.update(s, org, who, view_id, _fields(body)), who)
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.delete("/v2/issue-views/{view_id}", tags=["issues"], dependencies=read, status_code=204)
    def delete_view(
        view_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        try:
            views.delete(s, org, _viewer(s, org, auth), view_id)
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/issue-views/{view_id}/copy", tags=["issues"], dependencies=read, status_code=201)
    def copy_view(
        view_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        who = _viewer(s, org, auth)
        try:
            return views.view(views.copy_of(s, org, who, view_id), who)
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/me/tables/{table}", tags=["issues"], dependencies=read)
    def get_table_prefs(
        table: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return {**views.prefs(s, org, auth.actor, table), "all_columns": list(views.COLUMNS)}
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    @app.put("/v2/me/tables/{table}", tags=["issues"], dependencies=read)
    def set_table_prefs(
        table: str,
        body: dict[str, Any],
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return {
                **views.set_prefs(s, org, auth.actor, table, body),
                "all_columns": list(views.COLUMNS),
            }
        except views.ViewError as exc:
            raise _fail(s, exc) from exc

    write = [Depends(require_scope("scans:write"))]

    def _ctx(auth: AuthContext) -> search.Context:
        return search.Context(auth.actor, datetime.now(timezone.utc))

    @app.post("/v2/issues/bulk/preview", tags=["issues"], dependencies=write)
    def preview_bulk(
        body: BulkIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            p = bulk.plan(s, org, body.action, body.params, body.q, body.ids, _ctx(auth))
            return bulk.preview(s, org, p)
        except bulk.BulkError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/issues/bulk", tags=["issues"], dependencies=write)
    def apply_bulk(
        body: BulkIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return bulk.apply(s, org, auth.actor, body.action, body.params, body.q, body.ids,
                              body.expected_count, _ctx(auth))  # fmt: skip
        except bulk.BulkError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/issue-batches/{batch_id}/undo", tags=["issues"], dependencies=write)
    def undo_bulk(
        batch_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            return bulk.undo(s, org, auth.actor, batch_id)
        except bulk.BulkError as exc:
            raise _fail(s, exc) from exc
