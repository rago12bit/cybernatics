"""Issues across the organization, filtered by a query (core.search.language), a page at a time
(Week 73, plan §56).

- **Pages by cursor, not offset.** A page ends with an opaque cursor naming the last row's sort key
  and id; the next page starts strictly after it. Deep pages cost the same as the first, and a row
  that changes while someone pages cannot make another row appear twice or vanish.
- **Counts are exact while they are quick; past that, "more than 10,000".** Up to the cap the count
  is exact. Past it, the full count runs with a 200 ms limit: done in time, it is exact; not, the
  list says "more than 10,000", which is always true. Postgres's own row estimate was tried first
  and was off by 2 to 7 times on these filters (ADR-0056), so "about N" would mislead.
- **The org's projects as a list, not a join**, as in the metrics layer (ADR-0054): Postgres
  cannot estimate a join on `assets` under row-level security and walks every Issue of the org.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import ColumnElement, Select, and_, case, false, func, not_, or_, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from core.collab.people import names, people
from core.collab.tags import issue_clause as tag_clause
from core.persistence.models import SEVERITY_RANK, Asset, IssueRow, Portfolio
from core.search.language import Query, glob_match, glob_to_like
from core.sla import service as sla_service
from core.sla.policy import OPEN_STATES, Policy
from core.sla.service import status_of

COUNT_CAP = 10_000
COUNT_TIMEOUT_MS = 200
MAX_LIMIT = 200
SORTS = ("priority", "severity", "newest", "oldest", "last_seen")


class SearchError(ValueError):
    pass


@dataclass
class Context:
    """Who is asking (for `assignee:me`) and when (for ages and SLA states)."""

    actor: str | None
    now: datetime


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


# --- what the query means, as SQL -----------------------------------------------------------------


def _band() -> Any:
    return func.coalesce(IssueRow.priority_override, IssueRow.priority_band)


def _status(value: str, now: datetime) -> ColumnElement[bool]:
    live = IssueRow.state.in_(OPEN_STATES)
    if value == "fixed":
        return IssueRow.state == "fixed"
    if value == "not_a_risk":
        return and_(live, IssueRow.triage_status == "not_a_risk")
    accepted = and_(
        IssueRow.triage_status == "accepted",
        or_(IssueRow.triage_expires_at.is_(None), IssueRow.triage_expires_at > now),
    )
    if value == "accepted":
        return and_(live, accepted)
    # "open": the active queue -- untouched, or accepted with the acceptance run out.
    return and_(live, or_(IssueRow.triage_status == "open", and_(
        IssueRow.triage_status == "accepted", IssueRow.triage_expires_at <= now)))  # fmt: skip


def _any(values: list[str], one: Any) -> ColumnElement[bool]:
    parts = [one(v) for v in values]
    return or_(*parts) if parts else false()


def _policy_key(p: Policy) -> tuple[Any, ...]:
    return (p.enabled, p.basis, tuple(sorted((k, b.days, b.warn) for k, b in p.bands.items())))


def _sla(s: Session, assets: list[str], states: list[str], now: datetime) -> ColumnElement[bool]:
    """Each project has its own policy: group projects that share one, one clause per group."""
    groups: dict[tuple[Any, ...], tuple[Policy, list[str]]] = {}
    for asset_id, policy in sla_service.policies_for(s, assets).items():
        groups.setdefault(_policy_key(policy), (policy, []))[1].append(asset_id)
    parts = [
        and_(IssueRow.asset_id.in_(ids), sla_service.clause(policy, states, now))
        for policy, ids in groups.values()
        if policy.enabled
    ]
    return or_(*parts) if parts else false()


def _assignee(s: Session, org_id: str, value: str, ctx: Context) -> ColumnElement[bool]:
    v = value.lower()
    if v == "none":
        return IssueRow.assignee.is_(None)
    if v == "me":
        return IssueRow.assignee == ctx.actor if ctx.actor else false()
    if value.startswith("token:"):
        return IssueRow.assignee == value
    matches = [p.actor for p in people(s, org_id) if v in (p.handle, p.name.lower())]
    return IssueRow.assignee.in_(matches) if matches else false()


def _like(column: Any, pattern: str) -> ColumnElement[bool]:
    return func.lower(column).like(glob_to_like(pattern.lower()), escape="\\")


def _words(word: str) -> ColumnElement[bool]:
    return _like(IssueRow.title, f"*{word}*")


_DATE_COLUMNS = {"first_seen": IssueRow.first_seen_at, "last_seen": IssueRow.last_seen_at,
                 "fixed": IssueRow.fixed_at}  # fmt: skip


def _projects(s: Session, org_id: str, q: Query) -> list[str]:
    """The org's projects the query keeps (project and portfolio filters), as ids."""
    rows = list(
        s.execute(select(Asset.id, Asset.label, Asset.portfolio_id).where(Asset.org_id == org_id))
    )
    keep = {r[0] for r in rows}
    if "project" in q.clauses:
        c = q.clauses["project"]
        if c.include:
            keep &= {i for i, label, _ in rows if any(glob_match(p, label) for p in c.include)}
        keep -= {i for i, label, _ in rows if any(glob_match(p, label) for p in c.exclude)}
    if "portfolio" in q.clauses:
        c = q.clauses["portfolio"]
        units = list(
            s.execute(select(Portfolio.id, Portfolio.name).where(Portfolio.org_id == org_id))
        )

        def unit_ids(patterns: list[str]) -> set[str | None]:
            out: set[str | None] = {
                u for u, name in units if any(glob_match(p, name) for p in patterns)
            }
            if any(p.lower() == "none" for p in patterns):
                out.add(None)
            return out

        if c.include:
            wanted = unit_ids(c.include)
            keep &= {i for i, _, unit in rows if unit in wanted}
        unwanted = unit_ids(c.exclude)
        keep -= {i for i, _, unit in rows if unit in unwanted}
    return sorted(keep)


def conditions(
    s: Session, org_id: str, q: Query, ctx: Context
) -> tuple[list[ColumnElement[bool]], list[str]]:
    """The WHERE clause for a query, and the projects it covers."""
    assets = _projects(s, org_id, q)
    conds: list[ColumnElement[bool]] = [IssueRow.asset_id.in_(assets) if assets else false()]
    now = ctx.now
    for key, c in q.clauses.items():
        if key in ("project", "portfolio"):
            continue
        if key in _DATE_COLUMNS:
            col = _DATE_COLUMNS[key]
            for d in c.dates:
                op, at = d.bound(now)
                conds.append({">": col > at, ">=": col >= at, "<": col < at, "<=": col <= at}[op])
            continue
        one: Any
        if key == "status":
            one = lambda v: _status(v, now)  # noqa: E731
        elif key == "severity":
            one = lambda v: IssueRow.severity == v.upper()  # noqa: E731
        elif key == "priority":
            one = lambda v: _band().is_(None) if v == "none" else _band() == v  # noqa: E731
        elif key == "sla":
            if c.include:
                conds.append(_sla(s, assets, c.include, now))
            if c.exclude:
                conds.append(not_(_sla(s, assets, c.exclude, now)))
            continue
        elif key == "path":
            one = lambda v: _like(IssueRow.path, v)  # noqa: E731
        elif key == "category":
            one = lambda v: IssueRow.category == v  # noqa: E731
        elif key == "source":
            one = lambda v: func.lower(IssueRow.source) == v.lower()  # noqa: E731
        elif key == "assignee":
            one = lambda v: _assignee(s, org_id, v, ctx)  # noqa: E731
        elif key == "tag":
            if c.include:
                conds.append(tag_clause(c.include))
            if c.exclude:
                conds.append(not_(tag_clause(c.exclude)))
            continue
        elif key == "retest":
            one = lambda v: IssueRow.retest_status == v  # noqa: E731
        else:  # pragma: no cover - KEYS and this function are kept in step by the tests
            raise SearchError(f"unsupported filter {key}")
        if c.include:
            conds.append(_any(c.include, one))
        if c.exclude:
            conds.append(not_(_any(c.exclude, one)))
    if "status" not in q.clauses or not q.clauses["status"].include:
        conds.append(_status("open", now))  # no status asked for: the active queue
    conds.extend(_words(w) for w in q.text)
    return conds, assets


# --- order and cursor ---------------------------------------------------------------------------


def _sort_key(sort: str) -> tuple[Any, bool]:
    """The sort's key expression, and whether it runs descending. Ties break on the id, in the
    same direction, so one index on (key, id) serves the order both ways (migration 0045)."""
    if sort == "priority":
        return func.coalesce(IssueRow.priority_score, -1), True
    if sort == "severity":
        rank = case(*((IssueRow.severity == k, v) for k, v in SEVERITY_RANK.items()), else_=-1)
        return rank, True
    if sort == "newest":
        return IssueRow.first_seen_at, True
    if sort == "oldest":
        return IssueRow.first_seen_at, False
    if sort == "last_seen":
        return IssueRow.last_seen_at, True
    raise SearchError(f"sort is one of {', '.join(SORTS)}")


def _encode(sort: str, key: Any, issue_id: str) -> str:
    k = (
        key.replace(tzinfo=key.tzinfo or timezone.utc).isoformat()
        if isinstance(key, datetime)
        else key
    )
    raw = json.dumps({"s": sort, "k": k, "i": issue_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _decode(cursor: str, sort: str) -> tuple[Any, str]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if data["s"] != sort:
            raise SearchError("That page was for another order; start again from the first page.")
        key = data["k"]
        if sort in ("newest", "oldest", "last_seen") and key is not None:
            key = datetime.fromisoformat(key)
        return key, str(data["i"])
    except SearchError:
        raise
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise SearchError("That page link is not valid; start again from the first page.") from None


def _after(expr: Any, desc: bool, key: Any, issue_id: str) -> ColumnElement[bool]:
    if desc:
        return or_(expr < key, and_(expr == key, IssueRow.id < issue_id))
    return or_(expr > key, and_(expr == key, IssueRow.id > issue_id))


# --- counting -----------------------------------------------------------------------------------


def bounded(s: Session, stmt: Any, ms: int) -> Any:
    """Run a statement that must finish within `ms` milliseconds on Postgres; None if it did not.
    The time limit lives in a savepoint and is put back afterwards, so nothing else in the request
    is cut short by it."""
    if s.get_bind().dialect.name != "postgresql":
        return s.scalar(stmt)
    before = s.scalar(text("SHOW statement_timeout"))
    try:
        with s.begin_nested():
            s.execute(text(f"SET LOCAL statement_timeout = {int(ms)}"))
            value = s.scalar(stmt)
            s.execute(text("SELECT set_config('statement_timeout', :v, true)"), {"v": before})
            return value
    except OperationalError as exc:
        if getattr(exc.orig, "sqlstate", None) == "57014":  # query_canceled: out of time
            return None
        raise


def count(s: Session, conds: list[ColumnElement[bool]]) -> dict[str, Any]:
    """How many match: exact up to the cap; past it, exact if counting takes under
    COUNT_TIMEOUT_MS, else "more than 10,000" (a lower bound that is always true)."""
    capped = select(IssueRow.id).where(*conds).limit(COUNT_CAP + 1).subquery()
    n = s.scalar(select(func.count()).select_from(capped)) or 0
    if n <= COUNT_CAP:
        return {"value": n, "exact": True}
    full = select(func.count()).select_from(select(IssueRow.id).where(*conds).subquery())
    total = bounded(s, full, COUNT_TIMEOUT_MS)
    if total is not None:
        return {"value": int(total), "exact": True}
    return {"value": COUNT_CAP, "exact": False, "at_least": True}


# --- the page -----------------------------------------------------------------------------------


def status_of_row(r: IssueRow, now: datetime) -> str:
    if r.state == "fixed":
        return "fixed"
    if r.triage_status == "not_a_risk":
        return "not_a_risk"
    expires = _utc(r.triage_expires_at)
    if r.triage_status == "accepted" and (expires is None or expires > now):
        return "accepted"
    return "open"


def search(
    s: Session,
    org_id: str,
    q: Query,
    *,
    ctx: Context | None = None,
    sort: str = "priority",
    after: str | None = None,
    limit: int = 50,
    with_count: bool = True,
) -> dict[str, Any]:
    ctx = ctx or Context(None, _now())
    if sort not in SORTS:
        raise SearchError(f"sort is one of {', '.join(SORTS)}")
    limit = max(1, min(limit, MAX_LIMIT))
    conds, _ = conditions(s, org_id, q, ctx)
    expr, desc = _sort_key(sort)
    page_conds = list(conds)
    if after:
        key, last = _decode(after, sort)
        page_conds.append(_after(expr, desc, key, last))
    stmt: Select[Any] = (
        select(IssueRow, expr.label("k"))
        .where(*page_conds)
        .order_by(*((expr.desc(), IssueRow.id.desc()) if desc else (expr.asc(), IssueRow.id.asc())))
        .limit(limit + 1)
    )
    found = list(s.execute(stmt))
    more = len(found) > limit
    found = found[:limit]
    rows = _rows(s, org_id, [r for r, _ in found], ctx.now)
    nxt = _encode(sort, found[-1][1], found[-1][0].id) if more and found else None
    return {
        "rows": rows,
        "next": nxt,
        "count": count(s, conds) if with_count else None,
        "sort": sort,
    }


def ids(s: Session, org_id: str, q: Query, ctx: Context, cap: int) -> list[str]:
    """Every matching Issue's id, up to `cap` (bulk actions)."""
    conds, _ = conditions(s, org_id, q, ctx)
    return list(s.scalars(select(IssueRow.id).where(*conds).order_by(IssueRow.id).limit(cap)))


def _rows(s: Session, org_id: str, issues: list[IssueRow], now: datetime) -> list[dict[str, Any]]:
    if not issues:
        return []
    asset_ids = sorted({i.asset_id for i in issues})
    labels: dict[str, str] = {
        aid: label
        for aid, label in s.execute(
            select(Asset.id, Asset.label).where(Asset.org_id == org_id, Asset.id.in_(asset_ids))
        )
    }
    policies = sla_service.policies_for(s, asset_ids)
    who = names(s, org_id, {i.assignee for i in issues if i.assignee})
    out = []
    for i in issues:
        if i.asset_id not in labels:
            continue  # not this org's (row-level security already hides it on Postgres)
        sla = status_of(policies[i.asset_id], i, now)
        out.append(
            {
                "id": i.id,
                "project_id": i.asset_id,
                "project": labels[i.asset_id],
                "title": i.title,
                "severity": i.severity.lower(),
                "band": i.priority_override or i.priority_band,
                "score": i.priority_score,
                "status": status_of_row(i, now),
                "state": i.state,
                "accepted_until": (
                    _utc(i.triage_expires_at) if i.triage_status == "accepted" else None
                ),
                "sla": {"state": sla.state, "due_at": sla.due_at},
                "assignee": i.assignee,
                "assignee_name": who.get(i.assignee, i.assignee) if i.assignee else None,
                "path": i.path,
                "category": i.category,
                "source": i.source,
                "retest": i.retest_status,
                "first_seen_at": _utc(i.first_seen_at),
                "last_seen_at": _utc(i.last_seen_at),
                "fixed_at": _utc(i.fixed_at),
            }
        )
    return out


def suggest(s: Session, org_id: str, key: str, prefix: str = "", limit: int = 20) -> list[str]:
    """Values worth offering after `key:` in the query bar (projects, people, tags, ...)."""
    p = prefix.lower()
    pool: list[str]
    if key == "project":
        pool = list(
            s.scalars(select(Asset.label).where(Asset.org_id == org_id).order_by(Asset.label))
        )
    elif key == "portfolio":
        pool = list(
            s.scalars(
                select(Portfolio.name).where(Portfolio.org_id == org_id).order_by(Portfolio.name)
            )
        )  # noqa: E501
        pool.append("none")
    elif key == "assignee":
        pool = ["me", "none", *(person.handle for person in people(s, org_id))]
    elif key == "tag":
        from core.persistence.models import Tag

        pool = sorted(set(s.scalars(select(Tag.name).where(Tag.org_id == org_id))))
    elif key == "source":
        projects = list(s.scalars(select(Asset.id).where(Asset.org_id == org_id)))
        pool = (
            sorted(
                set(
                    s.scalars(
                        select(IssueRow.source).where(IssueRow.asset_id.in_(projects)).distinct()
                    )
                )
            )
            if projects
            else []
        )  # noqa: E501
    else:
        return []
    return [v for v in pool if not p or p in v.lower()][:limit]
