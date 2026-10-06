"""The calendar (plan §49): "a calendar of engagements, SLA due dates, and expiring risk
acceptances" -- one list of dated entries for a range, from data Bulwark already has.

- **Engagements:** each assessment (not the standing CI and import ones) from its start to its
  close, or its planned end, or just its start day.
- **SLA due dates:** each open Issue whose SLA falls due in the range, as its project's policy
  computes it today (the deadline is never stored, so this is the same date the issues table shows).
  Issues exempt from the SLA (accepted, not a risk) and ones without a deadline are left out.
- **Risk acceptances:** each approved acceptance whose date falls in the range, and each request
  still waiting whose date does (it lapses then).

Entries carry a link to what they are about. A range is at most 100 days.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from core.persistence.models import Asset, Engagement, IssueRow, RiskAcceptance
from core.sla.policy import OPEN_STATES

KINDS = ("engagement", "sla", "acceptance")
MAX_DAYS = 100
MAX_SLA_PER_PROJECT = 5000
STANDING = ("ci", "import")


class CalendarError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


@dataclass
class Entry:
    kind: str
    start: date
    end: date
    title: str
    project_id: str
    project: str
    link: str
    detail: str = ""
    severity: str | None = None
    state: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "title": self.title,
            "project_id": self.project_id,
            "project": self.project,
            "link": self.link,
            "detail": self.detail,
            "severity": self.severity,
            "state": self.state,
        }


@dataclass
class Calendar:
    start: date
    end: date
    entries: list[Entry] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)  # projects whose SLA list was cut short


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _day(dt: datetime) -> date:
    return _utc(dt).astimezone(timezone.utc).date()


def window(start: date, end: date) -> tuple[datetime, datetime]:
    if end < start:
        raise CalendarError("to", "The end comes before the start.")
    if (end - start).days + 1 > MAX_DAYS:
        raise CalendarError("to", f"At most {MAX_DAYS} days at a time.")
    lo = datetime.combine(start, time.min, tzinfo=timezone.utc)
    hi = datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)
    return lo, hi


def _assets(s: Session, org_id: str, project_id: str | None) -> list[Asset]:
    q = select(Asset).where(Asset.org_id == org_id)
    if project_id is not None:
        q = q.where(Asset.id == project_id)
    return list(s.scalars(q.order_by(Asset.label)))


def _engagements(
    s: Session, org_id: str, assets: dict[str, Asset], lo: datetime, hi: datetime
) -> list[Entry]:
    out = []
    for e in s.scalars(
        select(Engagement).where(
            Engagement.org_id == org_id,
            Engagement.engagement_type.not_in(STANDING),
            Engagement.asset_id.in_(list(assets)),
            Engagement.started_at < hi,
        )
    ):
        finish = e.closed_at or e.target_end_at or e.started_at
        if _utc(finish) < lo:
            continue
        a = assets[e.asset_id]
        status = e.status.replace("_", " ")
        out.append(
            Entry(
                "engagement",
                _day(e.started_at),
                max(_day(e.started_at), _day(finish)),
                e.name,
                a.id,
                a.label,
                f"/app/engagements/{e.id}",
                detail=f"{e.engagement_type}, {status}",
                state=e.status,
            )
        )
    return out


def _sla(
    s: Session, assets: dict[str, Asset], lo: datetime, hi: datetime, now: datetime
) -> tuple[list[Entry], list[str]]:
    from core.sla.service import policy_for, status_of

    out: list[Entry] = []
    truncated: list[str] = []
    for a in assets.values():
        policy = policy_for(s, a.id)
        days = [b.days for b in policy.bands.values() if b.days is not None]
        if not policy.enabled or not days:
            continue
        # Only Issues whose clock started early enough to fall due by the end, late enough to fall
        # due after the start: the SQL narrows by the longest and shortest deadline.
        start = IssueRow.sla_started_at
        first = IssueRow.first_seen_at
        lower, upper = lo - timedelta(days=max(days)), hi - timedelta(days=min(days))
        rows = list(
            s.scalars(
                select(IssueRow)
                .where(
                    IssueRow.asset_id == a.id,
                    IssueRow.state.in_(OPEN_STATES),
                    or_(
                        and_(start.is_not(None), start >= lower, start < upper),
                        and_(start.is_(None), first >= lower, first < upper),
                    ),
                )
                .order_by(IssueRow.first_seen_at)
                .limit(MAX_SLA_PER_PROJECT + 1)
            )
        )
        if len(rows) > MAX_SLA_PER_PROJECT:
            truncated.append(a.label)
            rows = rows[:MAX_SLA_PER_PROJECT]
        for issue in rows:
            st = status_of(policy, issue, now)
            if st.due_at is None or st.state in ("exempt", "none"):
                continue
            due = _utc(st.due_at)
            if not lo <= due < hi:
                continue
            band = issue.priority_override or issue.priority_band
            out.append(
                Entry(
                    "sla",
                    _day(due),
                    _day(due),
                    issue.title[:300],
                    a.id,
                    a.label,
                    f"/app/projects/{a.id}/issues/{issue.id}",
                    detail=f"{issue.severity.title()}{f', {band}' if band else ''}: SLA "
                    f"{'breached' if st.state == 'breached' else 'due'}",
                    severity=issue.severity.upper(),
                    state=st.state,
                )
            )
    return out, truncated


def _acceptances(
    s: Session, org_id: str, assets: dict[str, Asset], lo: datetime, hi: datetime
) -> list[Entry]:
    from core.acceptance.service import issue_ids_of

    out = []
    for ra in s.scalars(
        select(RiskAcceptance).where(
            RiskAcceptance.org_id == org_id,
            RiskAcceptance.asset_id.in_(list(assets)),
            RiskAcceptance.state.in_(("approved", "requested")),
            RiskAcceptance.expires_at >= lo,
            RiskAcceptance.expires_at < hi,
        )
    ):
        a = assets[ra.asset_id]
        n = len(issue_ids_of(s, ra.id))
        what = f"{ra.decision.title()}: {n} issue{'s' if n != 1 else ''}"
        detail = "expires" if ra.state == "approved" else "request lapses if not decided"
        out.append(
            Entry(
                "acceptance",
                _day(ra.expires_at),
                _day(ra.expires_at),
                what,
                a.id,
                a.label,
                f"/app/risk-acceptances/{ra.id}",
                detail=detail,
                state=ra.state,
            )
        )
    return out


def build(
    s: Session,
    org_id: str,
    start: date,
    end: date,
    *,
    project_id: str | None = None,
    kinds: tuple[str, ...] = KINDS,
    now: datetime | None = None,
) -> Calendar:
    bad = [k for k in kinds if k not in KINDS]
    if bad:
        raise CalendarError("kinds", f"Kinds are {', '.join(KINDS)}.")
    lo, hi = window(start, end)
    assets = {a.id: a for a in _assets(s, org_id, project_id)}
    cal = Calendar(start, end)
    if not assets:
        return cal
    if "engagement" in kinds:
        cal.entries += _engagements(s, org_id, assets, lo, hi)
    if "sla" in kinds:
        entries, cal.truncated = _sla(s, assets, lo, hi, now or datetime.now(timezone.utc))
        cal.entries += entries
    if "acceptance" in kinds:
        cal.entries += _acceptances(s, org_id, assets, lo, hi)
    order = {k: i for i, k in enumerate(KINDS)}
    cal.entries.sort(key=lambda e: (e.start, order[e.kind], e.project, e.title))
    return cal
