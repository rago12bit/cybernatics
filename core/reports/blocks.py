"""A report's blocks (plan §48.3): what each one holds, how its settings are checked, and the data
it shows, gathered at generation time from the same places the screens read -- the metrics'
summary tables (ADR-0054), Issues, risk acceptances, engagements and the compliance mappings
(ADR-0053).

    cover        title and subtitle; the organization, period and date are added
    summary      the executive summary: a person's text, or a model's draft a person has reviewed
    metric       any dashboard metric, with the widget filters (portfolio, project, tag, days)
    issues       a table of Issues: open, past SLA, first seen or fixed in the period, by priority,
                 with the same filters
    issue        one Issue in detail
    acceptances  risk acceptances: in force, awaiting a decision, or expiring soon
    compliance   one framework's controls with the evidence Bulwark holds for each
    engagement   a pen test or audit's scope, people and dates
    appendix     every metric's definition used above, and how to check the signature
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core import compliance
from core.dashboards import DashboardError, clean_filters
from core.metrics import query
from core.metrics.definitions import BY_ID
from core.persistence.models import (
    Asset,
    Engagement,
    FindingRow,
    IssueRow,
    RiskAcceptance,
    RiskAcceptanceIssue,
)

TYPES = ("cover", "summary", "metric", "issues", "issue", "acceptances", "compliance",
         "engagement", "appendix")  # fmt: skip
MAX_BLOCKS = 40
MAX_ISSUES = 200
_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_BLOCK_ID = re.compile(r"^[A-Za-z0-9_-]{1,36}$")


class ReportError(ValueError):
    def __init__(self, field: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.field, self.message, self.status = field, message, status


def _text(raw: Any, field: str, most: int, *, required: bool = False) -> str:
    value = raw.strip() if isinstance(raw, str) else ""
    if raw is not None and not isinstance(raw, str):
        raise ReportError(field, "Text, please.")
    if required and not value:
        raise ReportError(field, "This can't be empty.")
    if len(value) > most:
        raise ReportError(field, f"At most {most} characters.")
    return value


def _choice(raw: Any, field: str, options: tuple[str, ...], default: str) -> str:
    if raw in (None, ""):
        return default
    if raw not in options:
        raise ReportError(field, f"One of: {', '.join(options)}.")
    return str(raw)


def _uuid(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or not _ID.match(raw):
        raise ReportError(field, "Choose one.")
    return raw


def clean_block(raw: Any, n: int, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """One block's settings, checked. `previous` is the stored block with the same id: the
    summary's provenance (who drafted it, who reviewed it) is the server's, never the client's."""
    where = f"blocks[{n}]"
    if not isinstance(raw, dict):
        raise ReportError(where, "A block is an object.")
    bid = raw.get("id")
    if not isinstance(bid, str) or not _BLOCK_ID.match(bid):
        raise ReportError(f"{where}.id", "Each block needs its own short id.")
    kind = raw.get("type")
    if kind not in TYPES:
        raise ReportError(f"{where}.type", "Not a kind of block.")
    cfg = raw.get("config") or {}
    if not isinstance(cfg, dict):
        raise ReportError(f"{where}.config", "Settings are an object.")
    at = f"{where}.config"
    out: dict[str, Any]
    if kind == "cover":
        out = {"title": _text(cfg.get("title"), f"{at}.title", 120, required=True),
               "subtitle": _text(cfg.get("subtitle"), f"{at}.subtitle", 200)}  # fmt: skip
    elif kind == "summary":
        old = (
            (previous or {}).get("config", {}) if (previous or {}).get("type") == "summary" else {}
        )
        out = {
            "text": _text(cfg.get("text"), f"{at}.text", 8000),
            "source": old.get("source", "person"),
            "drafted_by_model": old.get("drafted_by_model"),
            "reviewed_by": old.get("reviewed_by"),
            "reviewed_at": old.get("reviewed_at"),
        }
    elif kind == "metric":
        if cfg.get("metric") not in BY_ID:
            raise ReportError(f"{at}.metric", "Not a metric in the catalogue.")
        try:
            filters = clean_filters(cfg.get("filters"), f"{at}.filters")
        except DashboardError as exc:
            raise ReportError(exc.field, exc.message) from exc
        out = {"metric": cfg["metric"], "filters": filters}
    elif kind == "issues":
        try:
            filters = clean_filters(cfg.get("filters"), f"{at}.filters")
        except DashboardError as exc:
            raise ReportError(exc.field, exc.message) from exc
        limit = cfg.get("limit", 50)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ISSUES:
            raise ReportError(f"{at}.limit", f"From 1 to {MAX_ISSUES} rows.")
        band = cfg.get("band") or None
        if band is not None and band not in query.BANDS:
            raise ReportError(f"{at}.band", f"One of: {', '.join(query.BANDS)}.")
        out = {"kind": _choice(cfg.get("kind"), f"{at}.kind", query.KINDS, "open"), "band": band,
               "filters": filters, "limit": limit,
               "title": _text(cfg.get("title"), f"{at}.title", 120)}  # fmt: skip
    elif kind == "issue":
        out = {"issue_id": _uuid(cfg.get("issue_id"), f"{at}.issue_id")}
    elif kind == "acceptances":
        states = ("approved", "requested", "expiring", "all")
        out = {"state": _choice(cfg.get("state"), f"{at}.state", states, "approved")}
    elif kind == "compliance":
        if compliance.get(str(cfg.get("framework") or "")) is None:
            raise ReportError(f"{at}.framework", "Not a framework Bulwark maps.")
        out = {"framework": cfg["framework"]}
    elif kind == "engagement":
        out = {"engagement_id": _uuid(cfg.get("engagement_id"), f"{at}.engagement_id")}
    else:
        out = {}
    return {"id": bid, "type": kind, "config": out}


def clean_blocks(raw: Any, previous: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ReportError("blocks", "Blocks are a list.")
    if len(raw) > MAX_BLOCKS:
        raise ReportError("blocks", f"At most {MAX_BLOCKS} blocks in a report.")
    old = {b["id"]: b for b in previous or []}
    out, seen = [], set()
    for n, b in enumerate(raw):
        block = clean_block(b, n, old.get(b.get("id")) if isinstance(b, dict) else None)
        if block["id"] in seen:
            raise ReportError(f"blocks[{n}].id", "Each block needs its own short id.")
        seen.add(block["id"])
        out.append(block)
    if sum(1 for b in out if b["type"] == "summary") > 1:
        raise ReportError("blocks", "One executive summary per report.")
    return out


# --- the data behind each block --------------------------------------------------------------


@dataclass(frozen=True)
class Period:
    start: date
    end: date

    @staticmethod
    def last(days: int, today: date | None = None) -> Period:
        end = today or datetime.now(timezone.utc).date()
        return Period(end - timedelta(days=days - 1), end)


def _filters(cfg: dict[str, Any], period: Period) -> query.Filters:
    f = cfg.get("filters") or {}
    start, end = period.start, period.end
    if f.get("days"):
        start = end - timedelta(days=int(f["days"]) - 1)
    return query.Filters(list(f.get("portfolios", [])), list(f.get("projects", [])), f.get("tag"),
                         start, end, f.get("group", "band"))  # fmt: skip


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _issue(s: Session, org_id: str, issue_id: str) -> dict[str, Any] | None:
    row = s.execute(
        select(IssueRow, Asset.label)
        .join(Asset, Asset.id == IssueRow.asset_id)
        .where(IssueRow.id == issue_id, Asset.org_id == org_id)
    ).first()
    if row is None:
        return None
    i, label = row
    found = s.scalar(
        select(FindingRow)
        .where(FindingRow.issue_id == i.id)
        .order_by(FindingRow.pk.desc())
        .limit(1)
    )
    data = (found.data or {}) if found is not None else {}
    tax = data.get("taxonomy") or {}
    return {
        "id": i.id, "title": i.title, "project": label, "severity": i.severity,
        "band": i.priority_override or i.priority_band, "state": i.state,
        "triage": i.triage_status, "path": i.path, "line": getattr(found, "start_line", None),
        "first_seen_at": _utc(i.first_seen_at), "fixed_at": _utc(i.fixed_at),
        "assignee": i.assignee, "cwe": list(tax.get("cwe") or [])[:5],
        "description": str(data.get("description") or "")[:4000],
    }  # fmt: skip


def _acceptances(s: Session, org_id: str, state: str, now: datetime) -> list[dict[str, Any]]:
    q = select(RiskAcceptance, Asset.label).join(Asset, Asset.id == RiskAcceptance.asset_id)
    q = q.where(RiskAcceptance.org_id == org_id)
    if state == "approved":
        q = q.where(RiskAcceptance.state == "approved")
    elif state == "requested":
        q = q.where(RiskAcceptance.state == "requested")
    elif state == "expiring":
        soon = now + timedelta(days=query.EXPIRING_DAYS)
        q = q.where(RiskAcceptance.state == "approved", RiskAcceptance.expires_at <= soon)
    rows = list(s.execute(q.order_by(RiskAcceptance.expires_at).limit(200)))
    counts: dict[str, int] = {}
    if rows:
        for aid, n in s.execute(
            select(RiskAcceptanceIssue.acceptance_id, func.count())
            .where(RiskAcceptanceIssue.acceptance_id.in_([ra.id for ra, _ in rows]))
            .group_by(RiskAcceptanceIssue.acceptance_id)
        ):
            counts[aid] = int(n)
    return [
        {"id": ra.id, "project": label, "decision": ra.decision, "state": ra.state,
         "issues": int(counts.get(ra.id, 0)), "justification": ra.justification,
         "controls": ra.controls, "expires_at": _utc(ra.expires_at),
         "requested_by": ra.requested_by, "decided_by": ra.decided_by}  # fmt: skip
        for ra, label in rows
    ]


def _engagement(s: Session, org_id: str, eid: str) -> dict[str, Any] | None:
    row = s.execute(
        select(Engagement, Asset.label)
        .join(Asset, Asset.id == Engagement.asset_id)
        .where(Engagement.id == eid, Engagement.org_id == org_id)
    ).first()
    if row is None:
        return None
    e, label = row
    return {"name": e.name, "project": label, "type": e.engagement_type, "status": e.status,
            "lead": e.lead, "testers": list(e.testers or []),
            "targets": list(e.scope_targets or []), "routes": list(e.scope_routes or []),
            "out_of_scope": e.out_of_scope, "started_at": _utc(e.started_at),
            "target_end_at": _utc(e.target_end_at), "closed_at": _utc(e.closed_at)}  # fmt: skip


def collect(
    s: Session, org_id: str, blocks: list[dict[str, Any]], period: Period,
    now: datetime | None = None,
) -> list[dict[str, Any]]:  # fmt: skip
    """Each block with the data it shows now. A block whose subject is gone (a deleted Issue or
    engagement) says so instead of failing the report."""
    now = now or datetime.now(timezone.utc)
    out = []
    for b in blocks:
        cfg, kind = b["config"], b["type"]
        data: dict[str, Any] = {}
        if kind == "metric":
            data = query.compute(s, org_id, cfg["metric"], _filters(cfg, period), now=now)
        elif kind == "issues":
            f = _filters(cfg, period)
            data = query.issues(s, org_id, f, kind=cfg["kind"], band=cfg.get("band"),
                                limit=cfg["limit"], now=now)  # fmt: skip
        elif kind == "issue":
            data = {"issue": _issue(s, org_id, cfg["issue_id"])}
        elif kind == "acceptances":
            data = {"rows": _acceptances(s, org_id, cfg["state"], now)}
        elif kind == "compliance":
            from core.evidence import pack

            ev = pack.collect(s, org_id, period.start, period.end, [cfg["framework"]])
            data = {"framework": ev["frameworks"][0], "disclaimer": compliance.DISCLAIMER}
        elif kind == "engagement":
            data = {"engagement": _engagement(s, org_id, cfg["engagement_id"])}
        out.append({**b, "data": data})
    return out
