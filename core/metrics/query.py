"""The metrics dashboards read (plan §48.1, §48.2), computed from the summary tables only.

Every metric takes the same filters -- portfolios, projects, a tag, a date range -- and returns its
value with the counts behind it (a percentage never comes without "x of y"), rows or a series, and
for each number a drill-down: the filter that lists the Issues behind it (`issues()`).

A tag selects what carries it, as tags inherit (`core.collab.tags`): projects tagged, projects in
portfolios tagged, and Issues tagged. Metrics read per Issue (open issues, open risk, backlog age,
past SLA) honour all three; metrics read per project and day honour the project and portfolio tags
only, and say so in `notes`.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.orm import Session

from core.metrics.definitions import BY_ID
from core.persistence.models import (
    AdvisoryImpact,
    AdvisoryState,
    Asset,
    Engagement,
    IssueRow,
    KevEntry,
    Library,
    MetricAssetStatus,
    MetricComponent,
    MetricDirty,
    MetricIssueDay,
    MetricOpenIssue,
    MetricSlaDay,
    Portfolio,
    RiskAcceptance,
    RiskAcceptanceIssue,
    Tag,
)

BANDS = ("P1", "P2", "P3", "P4", "none")
GROUPS = ("band", "portfolio", "project")
MAX_DAYS = 731
COVERAGE_DAYS = 30
EXPIRING_DAYS = 30


class MetricError(ValueError):
    pass


@dataclass
class Filters:
    portfolios: list[str] = field(default_factory=list)
    projects: list[str] = field(default_factory=list)
    tag: str | None = None
    start: date | None = None
    end: date | None = None
    group: str = "band"


@dataclass
class Scope:
    """What the filters select. `assets` None means every project; `issues` is the Issues a tag
    selects directly (only with a tag)."""

    assets: set[str] | None
    issues: set[str] = field(default_factory=set)
    tag_on_issues: bool = False
    base: set[str] | None = None  # the projects the project/portfolio filters allow


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def period(f: Filters, default_days: int = 90, today: date | None = None) -> tuple[date, date]:
    today = today or _now().date()
    end = f.end or today
    start = f.start or (end - timedelta(days=default_days - 1))
    if start > end:
        raise MetricError("the period ends before it starts")
    if (end - start).days + 1 > MAX_DAYS:
        raise MetricError(f"a period is at most {MAX_DAYS} days")
    return start, end


def scope(s: Session, org_id: str, f: Filters) -> Scope:
    assets: set[str] | None = None
    if f.projects or f.portfolios:
        q = select(Asset.id).where(Asset.org_id == org_id)
        conds = []
        if f.projects:
            conds.append(Asset.id.in_(f.projects))
        if f.portfolios:
            conds.append(Asset.portfolio_id.in_(f.portfolios))
        assets = set(s.scalars(q.where(and_(*conds))))
    if not f.tag:
        return Scope(assets)
    tagged = list(
        s.execute(
            select(Tag.target_type, Tag.target_id).where(Tag.org_id == org_id, Tag.name == f.tag)
        )
    )
    projects = {t for kind, t in tagged if kind == "project"}
    portfolios = {t for kind, t in tagged if kind == "portfolio"}
    issues = {t for kind, t in tagged if kind == "issue"}
    if portfolios:
        projects |= set(
            s.scalars(
                select(Asset.id).where(
                    Asset.org_id == org_id, Asset.portfolio_id.in_(sorted(portfolios))
                )
            )
        )
    base = assets
    if base is not None:
        projects &= base
    return Scope(projects, issues, bool(issues), base)


def _where(model: Any, org_id: str, sc: Scope, per_issue: bool = False) -> list[Any]:
    conds = [model.org_id == org_id]
    if sc.assets is None:
        return conds
    asset_cond = model.asset_id.in_(sorted(sc.assets)) if sc.assets else model.asset_id.is_(None)
    if per_issue and sc.issues:
        tagged = model.issue_id.in_(sorted(sc.issues))
        if sc.base is not None:
            tagged = and_(tagged, model.asset_id.in_(sorted(sc.base)))
        conds.append(or_(asset_cond, tagged))
    else:
        conds.append(asset_cond)
    return conds


def _pct(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def _week(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _names(s: Session, org_id: str, kind: str, ids: set[str]) -> dict[str, str]:
    if not ids:
        return {}
    model = Portfolio if kind == "portfolio" else Asset
    label = Portfolio.name if kind == "portfolio" else Asset.label
    return {i: n for i, n in s.execute(select(model.id, label).where(model.id.in_(sorted(ids))))}


def _notes(sc: Scope, per_issue: bool) -> list[str]:
    if sc.tag_on_issues and not per_issue:
        return [
            "The tag's Issue-level uses do not apply to this metric: only projects and "
            "portfolios carrying the tag are counted."
        ]
    return []


# --- metrics ---------------------------------------------------------------------------------


def _grouped(
    s: Session, org_id: str, sc: Scope, group: str, measure: Any
) -> list[dict[str, Any]]:  # noqa: E501
    col = {
        "band": MetricOpenIssue.band,
        "portfolio": MetricOpenIssue.portfolio_id,
        "project": MetricOpenIssue.asset_id,
    }[group]
    rows = s.execute(
        select(col, func.count(), measure)
        .where(*_where(MetricOpenIssue, org_id, sc, per_issue=True))
        .group_by(col)
    ).all()
    names = _names(s, org_id, group, {k for k, *_ in rows if k}) if group != "band" else {}
    out = [
        {
            "key": k or "none",
            "label": names.get(k, k) if k else "(none)",
            "count": n,
            "score": int(v or 0),
        }
        for k, n, v in rows
    ]
    if group == "band":
        order = {b: i for i, b in enumerate(BANDS)}
        return sorted(out, key=lambda r: order.get(r["key"], 9))
    return sorted(out, key=lambda r: (-r["score"], -r["count"], r["label"]))


def open_issues(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    rows = _grouped(s, org_id, sc, f.group, func.sum(MetricOpenIssue.priority_score))
    total = sum(r["count"] for r in rows)
    for r in rows:
        r["drill"] = {"kind": "open", f.group: r["key"]}
    return {"value": total, "counts": {"open": total}, "rows": rows}


def open_risk(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    rows = _grouped(s, org_id, sc, f.group, func.sum(MetricOpenIssue.priority_score))
    total = sum(r["score"] for r in rows)
    for r in rows:
        r["drill"] = {"kind": "open", f.group: r["key"]}
    start, end = period(f, today=now.date())
    per_day = s.execute(
        select(MetricIssueDay.day, func.sum(MetricIssueDay.risk_opened - MetricIssueDay.risk_fixed))
        .where(*_where(MetricIssueDay, org_id, sc), MetricIssueDay.day <= end)
        .group_by(MetricIssueDay.day)
        .order_by(MetricIssueDay.day)
    ).all()
    series = []
    running = 0
    i = 0
    week = _week(start)
    while week <= end:
        week_end = min(week + timedelta(days=6), end)
        while i < len(per_day) and per_day[i][0] <= week_end:
            running += int(per_day[i][1] or 0)
            i += 1
        series.append({"week": week.isoformat(), "risk": running})
        week += timedelta(days=7)
    return {
        "value": total,
        "counts": {"open": sum(r["count"] for r in rows)},
        "rows": rows,
        "series": series,
        "period": [start.isoformat(), end.isoformat()],
    }


def backlog_age(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    conds = _where(MetricOpenIssue, org_id, sc, per_issue=True)
    total = s.scalar(select(func.count()).select_from(MetricOpenIssue).where(*conds)) or 0
    median = None
    if total:
        mid = s.scalar(
            select(MetricOpenIssue.first_seen_at)
            .where(*conds)
            .order_by(MetricOpenIssue.first_seen_at.desc())
            .offset(total // 2)
            .limit(1)
        )
        median = max(0, (now - (_utc(mid) or now)).days)
    buckets = {}
    for days in (30, 90, 180):
        cut = now - timedelta(days=days)
        buckets[f"over_{days}"] = (
            s.scalar(
                select(func.count())
                .select_from(MetricOpenIssue)
                .where(*conds, MetricOpenIssue.first_seen_at < cut)
            )
            or 0
        )
    return {
        "value": median,
        "counts": {"open": total, **buckets},
        "rows": [
            {"key": k, "count": v, "drill": {"kind": "open", "older_than": int(k[5:])}}
            for k, v in buckets.items()
        ],
    }


def past_sla(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    conds = [*_where(MetricOpenIssue, org_id, sc, per_issue=True), MetricOpenIssue.due_at < now]
    total = s.scalar(select(func.count()).select_from(MetricOpenIssue).where(*conds)) or 0
    rows = []
    for m, title, label, assignee, portfolio in s.execute(
        select(MetricOpenIssue, IssueRow.title, Asset.label, IssueRow.assignee, Portfolio.name)
        .join(IssueRow, IssueRow.id == MetricOpenIssue.issue_id)
        .join(Asset, Asset.id == MetricOpenIssue.asset_id)
        .outerjoin(Portfolio, Portfolio.id == MetricOpenIssue.portfolio_id)
        .where(*conds)
        .order_by(MetricOpenIssue.due_at)
        .limit(10)
    ):
        due = _utc(m.due_at) or now
        rows.append(
            {
                "issue_id": m.issue_id,
                "project_id": m.asset_id,
                "project": label,
                "portfolio": portfolio,
                "title": title,
                "band": m.band,
                "severity": m.severity,
                "days_over": max(0, (now - due).days),
                "assignee": assignee,
            }
        )
    return {
        "value": total,
        "counts": {"past_sla": total},
        "rows": rows,
        "drill_all": {"kind": "past_sla"},
    }


def sla_adherence(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    start, end = period(f, today=now.date())
    today = now.date()
    last = min(end, today)
    rows = s.execute(
        select(
            MetricSlaDay.day,
            MetricSlaDay.band,
            func.sum(MetricSlaDay.met),
            func.sum(MetricSlaDay.missed),
            func.sum(MetricSlaDay.unfixed),
            func.sum(MetricSlaDay.exempt),
        )
        .where(
            *_where(MetricSlaDay, org_id, sc), MetricSlaDay.day >= start, MetricSlaDay.day <= last
        )  # noqa: E501
        .group_by(MetricSlaDay.day, MetricSlaDay.band)
    ).all()
    met = missed = past = exempt = 0
    weekly: dict[date, list[int]] = defaultdict(lambda: [0, 0])
    by_band: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for day, band, m, mi, u, e in rows:
        m, mi, e = int(m or 0), int(mi or 0), int(e or 0)
        u = int(u or 0) if day < today else 0  # due today and not fixed: not late yet
        met, missed, past, exempt = met + m, missed + mi, past + u, exempt + e
        weekly[_week(day)][0] += m
        weekly[_week(day)][1] += m + mi + u
        by_band[band][0] += m
        by_band[band][1] += m + mi + u
    due = met + missed + past
    series = [
        {"week": w.isoformat(), "met": v[0], "due": v[1], "rate": _pct(v[0], v[1])}
        for w, v in sorted(weekly.items())
    ]
    return {
        "value": _pct(met, due),
        "counts": {
            "met": met,
            "missed": missed,
            "open_past_deadline": past,
            "due": due,
            "exempt": exempt,
        },
        "rows": [
            {"key": b, "met": v[0], "due": v[1], "rate": _pct(v[0], v[1])}
            for b, v in sorted(by_band.items())
        ],
        "series": series,
        "period": [start.isoformat(), end.isoformat()],
    }


def mttr(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    start, end = period(f, today=now.date())
    conds = [
        *_where(MetricIssueDay, org_id, sc),
        MetricIssueDay.day >= start,
        MetricIssueDay.day <= end,
        MetricIssueDay.fixed > 0,
    ]
    by_band = s.execute(
        select(
            MetricIssueDay.band,
            func.sum(MetricIssueDay.fixed),
            func.sum(MetricIssueDay.fix_seconds),
        )
        .where(*conds)
        .group_by(MetricIssueDay.band)
    ).all()
    order = {b: i for i, b in enumerate(BANDS)}
    rows = [
        {
            "key": b,
            "fixed": int(n),
            "days": round(int(sec) / int(n) / 86400, 1),
            "drill": {"kind": "fixed", "band": b},
        }
        for b, n, sec in sorted(by_band, key=lambda r: order.get(r[0], 9))
        if n
    ]
    fixed = sum(r["fixed"] for r in rows)
    secs = sum(int(sec) for _b, n, sec in by_band if n)
    monthly: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for day, n, sec in s.execute(
        select(MetricIssueDay.day, MetricIssueDay.fixed, MetricIssueDay.fix_seconds).where(*conds)
    ):
        key = day.strftime("%Y-%m")
        monthly[key][0] += int(n)
        monthly[key][1] += int(sec)
    series = [
        {"month": k, "fixed": v[0], "days": round(v[1] / v[0] / 86400, 1)}
        for k, v in sorted(monthly.items())
        if v[0]
    ]
    return {
        "value": round(secs / fixed / 86400, 1) if fixed else None,
        "counts": {"fixed": fixed},
        "rows": rows,
        "series": series,
        "period": [start.isoformat(), end.isoformat()],
    }


def new_vs_fixed(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    start, end = period(f, today=now.date())
    weekly: dict[date, list[int]] = defaultdict(lambda: [0, 0])
    for day, opened, fixed in s.execute(
        select(MetricIssueDay.day, func.sum(MetricIssueDay.opened), func.sum(MetricIssueDay.fixed))
        .where(
            *_where(MetricIssueDay, org_id, sc),
            MetricIssueDay.day >= start,
            MetricIssueDay.day <= end,
        )
        .group_by(MetricIssueDay.day)
    ):
        weekly[_week(day)][0] += int(opened or 0)
        weekly[_week(day)][1] += int(fixed or 0)
    series: list[dict[str, Any]] = []
    week = _week(start)
    while week <= end:
        v = weekly.get(week, [0, 0])
        series.append({"week": week.isoformat(), "new": v[0], "fixed": v[1]})
        week += timedelta(days=7)
    new = sum(int(r["new"]) for r in series)
    fixed = sum(int(r["fixed"]) for r in series)
    return {
        "value": new - fixed,
        "counts": {"new": new, "fixed": fixed},
        "series": series,
        "period": [start.isoformat(), end.isoformat()],
        "drill": {"new": {"kind": "opened"}, "fixed": {"kind": "fixed"}},
    }


def scan_coverage(s: Session, org_id: str, f: Filters, sc: Scope, now: datetime) -> dict[str, Any]:
    cut = now - timedelta(days=COVERAGE_DAYS)
    rows = []
    for st, label, portfolio in s.execute(
        select(MetricAssetStatus, Asset.label, Portfolio.name)
        .join(Asset, Asset.id == MetricAssetStatus.asset_id)
        .outerjoin(Portfolio, Portfolio.id == MetricAssetStatus.portfolio_id)
        .where(*_where(MetricAssetStatus, org_id, sc), MetricAssetStatus.last_scan_at.is_not(None))
    ):
        last = _utc(st.last_scan_at)
        rows.append(
            {
                "project_id": st.asset_id,
                "project": label,
                "portfolio": portfolio,
                "last_scan_at": last,
                "days_since": (now - last).days if last else None,
                "recent": bool(last and last >= cut),
                "scanners_ok": st.scanners_ok,
                "scanners_applicable": st.scanners_applicable,
            }
        )
    rows.sort(
        key=lambda r: (
            r["recent"],
            r["scanners_ok"] - r["scanners_applicable"],
            -(r["days_since"] or 0),
            r["project"],
        )
    )
    covered = sum(r["recent"] for r in rows)
    return {
        "value": _pct(covered, len(rows)),
        "counts": {"scanned_recently": covered, "projects": len(rows)},
        "rows": rows,
        "days": COVERAGE_DAYS,
    }


def vulnerable_components(
    s: Session, org_id: str, f: Filters, sc: Scope, now: datetime
) -> dict[str, Any]:  # noqa: E501
    q = (
        select(
            MetricComponent.library_id,
            func.count(),
            func.max(MetricComponent.vulns),
            func.sum(case((MetricComponent.kev > 0, 1), else_=0)),
        )
        .where(*_where(MetricComponent, org_id, sc))
        .group_by(MetricComponent.library_id)
        .order_by(func.count().desc(), func.max(MetricComponent.vulns).desc())
        .limit(10)
    )
    top = s.execute(q).all()
    libs = {
        lib.id: lib for lib in s.scalars(select(Library).where(Library.id.in_([t[0] for t in top])))
    }  # noqa: E501
    rows = [
        {
            "library_id": lid,
            "library": libs[lid].name if lid in libs else lid,
            "ecosystem": libs[lid].ecosystem if lid in libs else "",
            "purl": libs[lid].purl if lid in libs else "",  # noqa: E501
            "projects": int(n),
            "vulns": int(v or 0),
            "kev_projects": int(k or 0),
        }
        for lid, n, v, k in top
    ]
    libraries = s.scalar(
        select(func.count(func.distinct(MetricComponent.library_id))).where(
            *_where(MetricComponent, org_id, sc)
        )
    )
    return {"value": libraries or 0, "counts": {"libraries": libraries or 0}, "rows": rows}


def expiring_acceptances(
    s: Session, org_id: str, f: Filters, sc: Scope, now: datetime
) -> dict[str, Any]:  # noqa: E501
    until = now + timedelta(days=EXPIRING_DAYS)
    conds = [
        RiskAcceptance.org_id == org_id,
        RiskAcceptance.state == "approved",
        RiskAcceptance.expires_at >= now,
        RiskAcceptance.expires_at < until,
    ]
    if sc.assets is not None:
        conds.append(RiskAcceptance.asset_id.in_(sorted(sc.assets)))
    rows = []
    for ra, label in s.execute(
        select(RiskAcceptance, Asset.label)
        .join(Asset, Asset.id == RiskAcceptance.asset_id)
        .where(*conds)
        .order_by(RiskAcceptance.expires_at)
        .limit(50)
    ):
        n = s.scalar(
            select(func.count())
            .select_from(RiskAcceptanceIssue)
            .where(RiskAcceptanceIssue.acceptance_id == ra.id)
        )
        exp = _utc(ra.expires_at) or now
        rows.append(
            {
                "id": ra.id,
                "project_id": ra.asset_id,
                "project": label,
                "decision": ra.decision,
                "issues": n,
                "expires_at": exp,
                "days_left": max(0, (exp - now).days),
                "approved_by": ra.decided_by,
            }
        )
    return {
        "value": len(rows),
        "counts": {"expiring": len(rows)},
        "rows": rows,
        "days": EXPIRING_DAYS,
    }


def engagement_status(
    s: Session, org_id: str, f: Filters, sc: Scope, now: datetime
) -> dict[str, Any]:  # noqa: E501
    conds = [
        Engagement.org_id == org_id,
        Engagement.engagement_type.in_(("pentest", "audit", "adhoc")),
    ]
    if sc.assets is not None:
        conds.append(Engagement.asset_id.in_(sorted(sc.assets)))
    counts: dict[str, int] = defaultdict(int)
    rows = []
    for e, label in s.execute(
        select(Engagement, Asset.label).join(Asset, Asset.id == Engagement.asset_id).where(*conds)
    ):
        counts[e.status] += 1
        if e.status == "active":
            due = _utc(e.target_end_at)
            rows.append(
                {
                    "id": e.id,
                    "name": e.name,
                    "type": e.engagement_type,
                    "project_id": e.asset_id,
                    "project": label,
                    "lead": e.lead,
                    "target_end_at": due,
                    "overdue": bool(due and due < now),
                }
            )
    rows.sort(key=lambda r: (r["target_end_at"] is None, r["target_end_at"] or now))
    return {"value": counts.get("active", 0), "counts": dict(counts), "rows": rows[:20]}


def advisory_impact(
    s: Session, org_id: str, f: Filters, sc: Scope, now: datetime
) -> dict[str, Any]:  # noqa: E501
    start, end = period(f, default_days=30, today=now.date())
    lo = datetime.combine(start, time.min, tzinfo=timezone.utc)
    hi = datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)
    states = {
        st.vuln_key: st
        for st in s.scalars(
            select(AdvisoryState).where(
                AdvisoryState.org_id == org_id,
                AdvisoryState.first_seen_at >= lo,
                AdvisoryState.first_seen_at < hi,
            )
        )
    }
    keys = sorted(states)
    projects: dict[str, int] = {}
    for k in range(0, len(keys), 500):
        q = (
            select(AdvisoryImpact.vuln_key, func.count(func.distinct(AdvisoryImpact.asset_id)))
            .where(
                AdvisoryImpact.org_id == org_id,
                AdvisoryImpact.resolved_at.is_(None),
                AdvisoryImpact.vuln_key.in_(keys[k : k + 500]),
            )
            .group_by(AdvisoryImpact.vuln_key)
        )
        if sc.assets is not None:
            q = q.where(AdvisoryImpact.asset_id.in_(sorted(sc.assets)))
        projects.update({v: int(n) for v, n in s.execute(q)})
    kev = set(s.scalars(select(KevEntry.cve).where(KevEntry.cve.in_(list(projects)))))
    rows: list[dict[str, Any]] = sorted(
        (
            {
                "vuln_key": v,
                "projects": n,
                "kev": v in kev,
                "state": states[v].state,
                "first_seen_at": _utc(states[v].first_seen_at),
            }
            for v, n in projects.items()
        ),
        key=lambda r: (not r["kev"], -int(r["projects"]), str(r["vuln_key"])),
    )
    return {
        "value": len(rows),
        "counts": {
            "new": len(rows),
            "kev": sum(r["kev"] for r in rows),
            "not_acted_on": sum(r["state"] == "new" for r in rows),
        },
        "rows": rows[:20],
        "period": [start.isoformat(), end.isoformat()],
    }


COMPUTE = {
    "open_issues": (open_issues, True),
    "open_risk": (open_risk, True),
    "backlog_age": (backlog_age, True),
    "past_sla": (past_sla, True),
    "sla_adherence": (sla_adherence, False),
    "mttr": (mttr, False),
    "new_vs_fixed": (new_vs_fixed, False),
    "scan_coverage": (scan_coverage, False),
    "vulnerable_components": (vulnerable_components, False),
    "expiring_acceptances": (expiring_acceptances, False),
    "engagement_status": (engagement_status, False),
    "advisory_impact": (advisory_impact, False),
}


def compute(
    s: Session, org_id: str, metric_id: str, f: Filters, now: datetime | None = None
) -> dict[str, Any]:
    metric = BY_ID.get(metric_id)
    if metric is None:
        raise MetricError(f"no metric {metric_id!r}")
    if f.group not in GROUPS:
        raise MetricError(f"group by one of {', '.join(GROUPS)}")
    now = now or _now()
    sc = scope(s, org_id, f)
    fn, per_issue = COMPUTE[metric_id]
    out = fn(s, org_id, f, sc, now)
    pending = s.scalar(
        select(func.count()).select_from(MetricDirty).where(MetricDirty.org_id == org_id)
    )
    return {
        "metric": metric_id,
        "name": metric.name,
        "definition": metric.definition,
        "unit": metric.unit,
        "generated_at": now,
        "pending_refresh": int(pending or 0),
        "notes": _notes(sc, per_issue),
        **out,
    }


# --- the Issues behind a number --------------------------------------------------------------

KINDS = ("open", "past_sla", "opened", "fixed")


def issues(
    s: Session,
    org_id: str,
    f: Filters,
    *,
    kind: str,
    band: str | None = None,
    portfolio: str | None = None,
    project: str | None = None,
    older_than: int | None = None,
    after: str | None = None,
    limit: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The Issues behind a number, a page at a time (`after` is the last id of the page before)."""
    if kind not in KINDS:
        raise MetricError(f"kind is one of {', '.join(KINDS)}")
    now = now or _now()
    sc = scope(s, org_id, f)
    q: Select[Any]
    if kind in ("open", "past_sla"):
        conds = _where(MetricOpenIssue, org_id, sc, per_issue=True)
        if kind == "past_sla":
            conds.append(MetricOpenIssue.due_at < now)
        if band:
            conds.append(MetricOpenIssue.band == band)
        if portfolio:
            conds.append(
                MetricOpenIssue.portfolio_id == (None if portfolio == "none" else portfolio)
            )  # noqa: E501
        if project:
            conds.append(MetricOpenIssue.asset_id == project)
        if older_than:
            conds.append(MetricOpenIssue.first_seen_at < now - timedelta(days=older_than))
        if after:
            conds.append(MetricOpenIssue.issue_id > after)
        q = select(MetricOpenIssue.issue_id).where(*conds).order_by(MetricOpenIssue.issue_id)
    else:
        start, end = period(f, today=now.date())
        lo = datetime.combine(start, time.min, tzinfo=timezone.utc)
        hi = datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)
        col = IssueRow.first_seen_at if kind == "opened" else IssueRow.fixed_at
        conds = [Asset.org_id == org_id, col >= lo, col < hi]
        if kind == "fixed":
            conds.append(IssueRow.state == "fixed")
        if sc.assets is not None:
            conds.append(IssueRow.asset_id.in_(sorted(sc.assets)))
        if band:
            conds.append(
                func.coalesce(IssueRow.priority_override, IssueRow.priority_band, "none") == band
            )  # noqa: E501
        if project:
            conds.append(IssueRow.asset_id == project)
        if after:
            conds.append(IssueRow.id > after)
        q = (
            select(IssueRow.id)
            .join(Asset, Asset.id == IssueRow.asset_id)
            .where(*conds)
            .order_by(IssueRow.id)
        )
    ids = list(s.scalars(q.limit(limit + 1)))
    more = len(ids) > limit
    ids = ids[:limit]
    rows = []
    for i, label in s.execute(
        select(IssueRow, Asset.label)
        .join(Asset, Asset.id == IssueRow.asset_id)
        .where(IssueRow.id.in_(ids))  # noqa: E501
    ):
        rows.append(
            {
                "id": i.id,
                "project_id": i.asset_id,
                "project": label,
                "title": i.title,
                "severity": i.severity,
                "band": i.priority_override or i.priority_band,
                "state": i.state,
                "first_seen_at": _utc(i.first_seen_at),
                "fixed_at": _utc(i.fixed_at),
                "assignee": i.assignee,
            }
        )
    rows.sort(key=lambda r: r["id"])
    return {"rows": rows, "next": rows[-1]["id"] if more and rows else None}
