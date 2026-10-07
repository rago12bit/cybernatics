"""The portfolio overview (plan §55.6): for one business unit, which projects need attention and
why, in a sentence, then every project sorted by need -- open P1s, Issues past SLA, the last full
scan, the scanners that ran of those that apply, and a trend. Read from the summary tables
(ADR-0054), like every dashboard number.

A project needs attention when it has Issues past their SLA, a vulnerability that first affected
it in the last week and that no one has acted on yet, or no successful full scan in the last
14 days (the quiet failure, §45). Projects without a portfolio are an overview of their own.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.persistence.models import (
    AdvisoryImpact,
    AdvisoryState,
    Asset,
    MetricAssetStatus,
    MetricIssueDay,
    MetricOpenIssue,
    Portfolio,
)

STALE_DAYS = 14
NEW_ADVISORY_DAYS = 7
TREND_WEEKS = 8
NONE = "none"


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _projects(s: Session, org_id: str, portfolio_id: str) -> list[tuple[str, str]]:
    q = select(Asset.id, Asset.label).where(Asset.org_id == org_id)
    q = q.where(
        Asset.portfolio_id.is_(None) if portfolio_id == NONE else Asset.portfolio_id == portfolio_id
    )
    return [(i, label) for i, label in s.execute(q.order_by(Asset.label))]


def _rows(s: Session, org_id: str, assets: list[str], now: datetime) -> list[dict[str, Any]]:
    if not assets:
        return []
    by: dict[str, dict[str, Any]] = {
        a: {"open": 0, "open_p1": 0, "past_sla": 0, "new_advisories": []} for a in assets
    }
    for a, band, n, late in s.execute(
        select(
            MetricOpenIssue.asset_id,
            MetricOpenIssue.band,
            func.count(),
            func.count(MetricOpenIssue.due_at).filter(MetricOpenIssue.due_at < now),
        )
        .where(MetricOpenIssue.org_id == org_id, MetricOpenIssue.asset_id.in_(assets))
        .group_by(MetricOpenIssue.asset_id, MetricOpenIssue.band)
    ):
        by[a]["open"] += int(n)
        by[a]["past_sla"] += int(late or 0)
        if band == "P1":
            by[a]["open_p1"] += int(n)
    status = {
        m.asset_id: m
        for m in s.scalars(
            select(MetricAssetStatus).where(
                MetricAssetStatus.org_id == org_id, MetricAssetStatus.asset_id.in_(assets)
            )
        )
    }
    since = now - timedelta(days=NEW_ADVISORY_DAYS)
    for a, key in s.execute(
        select(AdvisoryImpact.asset_id, AdvisoryImpact.vuln_key)
        .join(
            AdvisoryState,
            (AdvisoryState.org_id == AdvisoryImpact.org_id)
            & (AdvisoryState.vuln_key == AdvisoryImpact.vuln_key),
        )
        .where(
            AdvisoryImpact.org_id == org_id,
            AdvisoryImpact.asset_id.in_(assets),
            AdvisoryImpact.resolved_at.is_(None),
            AdvisoryImpact.first_seen_at >= since,
            AdvisoryState.state == "new",
        )
        .distinct()
    ):
        by[a]["new_advisories"].append(key)
    # Trend: Issues found and not yet fixed at the end of each of the last weeks.
    weeks = [now.date() - timedelta(days=7 * k) for k in range(TREND_WEEKS - 1, -1, -1)]
    deltas: dict[str, list[tuple[date, int]]] = defaultdict(list)
    for a, day, opened, fixed in s.execute(
        select(MetricIssueDay.asset_id, MetricIssueDay.day, func.sum(MetricIssueDay.opened),
               func.sum(MetricIssueDay.fixed))
        .where(MetricIssueDay.org_id == org_id, MetricIssueDay.asset_id.in_(assets))
        .group_by(MetricIssueDay.asset_id, MetricIssueDay.day)
    ):  # fmt: skip
        deltas[a].append((day, int(opened or 0) - int(fixed or 0)))
    out = []
    for a in assets:
        st = status.get(a)
        last = _utc(st.last_scan_at) if st else None
        trend = [sum(d for day, d in deltas[a] if day <= w) for w in weeks]
        out.append(
            {
                "asset": a,
                **by[a],
                "last_scan_at": last,
                "days_since_scan": (now - last).days if last else None,
                "scanners_ok": st.scanners_ok if st else 0,
                "scanners_applicable": st.scanners_applicable if st else 0,
                "trend": trend,
            }
        )
    return out


def _needs(r: dict[str, Any]) -> list[str]:
    out = []
    if r["past_sla"]:
        out.append("past_sla")
    if r["new_advisories"]:
        out.append("new_advisory")
    if r["days_since_scan"] is None or r["days_since_scan"] > STALE_DAYS:
        out.append("not_scanned")
    return out


def _need_order(r: dict[str, Any]) -> tuple[Any, ...]:
    """Most in need first: more reasons, more past SLA, more new advisories, longer unscanned
    (never scanned longest of all), more open P1s; then by name."""
    stale = r["days_since_scan"] if r["days_since_scan"] is not None else 10**6
    return (-len(r["needs"]), -r["past_sla"], -len(r["new_advisories"]), -stale, -r["open_p1"],
            r["label"].lower())  # fmt: skip


def verdict(projects: list[dict[str, Any]]) -> str:
    """The sentence: what needs attention, and why -- including the project nobody scans."""
    if not projects:
        return "No projects yet."
    attention = [p for p in projects if p["needs"]]
    if not attention:
        return (
            f"All {_plural(len(projects), 'project')} are on track: nothing past SLA, no new "
            f"advisories, and every one scanned in the last {STALE_DAYS} days."
            if len(projects) > 1
            else f"{projects[0]['label']} is on track."
        )
    parts = []
    late = sum(p["past_sla"] for p in attention)
    if late:
        parts.append(f"{_plural(late, 'issue')} {'is' if late == 1 else 'are'} past SLA")
    advised = [p["label"] for p in attention if "new_advisory" in p["needs"]]
    if advised:
        keys = {k for p in attention for k in p["new_advisories"]}
        lead = "a new advisory affects" if len(keys) == 1 else f"{len(keys)} new advisories affect"
        parts.append(f"{lead} {_join(advised)}")
    for p in attention:
        if "not_scanned" in p["needs"]:
            days = p["days_since_scan"]
            parts.append(
                f"{p['label']} has never had a full scan"
                if days is None
                else f"{p['label']} hasn't been scanned in {days} days"
            )
    head = (
        f"{_plural(len(attention), 'project')} {'needs' if len(attention) == 1 else 'need'} "
        f"attention: {_join(parts)}."
    )
    rest = len(projects) - len(attention)
    if rest == 1:
        head += " The other project is on track."
    elif rest:
        head += f" The other {rest} projects are on track."
    return head


def overview(
    s: Session, org_id: str, portfolio_id: str, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    if portfolio_id == NONE:
        name = "Projects without a portfolio"
    else:
        p = s.get(Portfolio, portfolio_id)
        if p is None or p.org_id != org_id:
            raise LookupError(portfolio_id)
        name = p.name
    projects = _projects(s, org_id, portfolio_id)
    labels = dict(projects)
    rows = _rows(s, org_id, [a for a, _ in projects], now)
    for r in rows:
        r["label"] = labels[r["asset"]]
        r["needs"] = _needs(r)
    rows.sort(key=_need_order)
    return {
        "id": portfolio_id,
        "name": name,
        "verdict": verdict(rows),
        "needs_attention": sum(1 for r in rows if r["needs"]),
        "projects": rows,
        "stale_days": STALE_DAYS,
        "trend_weeks": TREND_WEEKS,
        "generated_at": now,
    }


def overviews(s: Session, org_id: str, now: datetime | None = None) -> list[dict[str, Any]]:
    """Every business unit's sentence, the ones needing attention first."""
    now = now or datetime.now(timezone.utc)
    ids = [p for p in s.scalars(select(Portfolio.id).where(Portfolio.org_id == org_id))]
    if s.scalar(select(func.count()).select_from(Asset).where(
            Asset.org_id == org_id, Asset.portfolio_id.is_(None))):  # fmt: skip
        ids.append(NONE)
    out = []
    for pid in ids:
        o = overview(s, org_id, pid, now)
        out.append({k: o[k] for k in ("id", "name", "verdict", "needs_attention")}
                   | {"projects": len(o["projects"])})  # fmt: skip
    return sorted(out, key=lambda o: (-o["needs_attention"], o["name"].lower()))
