"""Issues across the organization (Week 73, plan §56): the query language, pages by cursor.

    GET /v2/issues?q=&sort=&after=&limit=     one page of matching Issues, the next page's cursor,
                                              and how many match (an estimate above 10,000)
    GET /v2/issues/parse?q=                   the query as filters and written back canonically,
                                              or the error with the span of text at fault
    GET /v2/issues/suggest?key=&prefix=       values to offer after `key:` (projects, people,
                                              tags, business units, sources)

`q` uses core.search.language: `priority:P1 sla:breached project:payments-* -status:accepted`.
With no status in it, the list is the active queue (status:open). A query the parser cannot read is
a 422 with `{message, start, end}`, so the query bar can underline the part at fault.

All `scans:read`: this lists what the token can already read, one project at a time, across them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core.search import issues as search
from core.search.language import KEYS, QueryError, format_query, parse


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
