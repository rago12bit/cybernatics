"""Reports (plan §48.3): saving them, templates, generating the signed PDF, links that expire and
can be revoked, schedules that email a link, and the AI-drafted summary a person must review.

Rules:
- A report whose summary is an AI draft nobody has reviewed is not generated, by hand or on a
  schedule: "the draft is labelled as AI-written and edited before sending".
- Each generated PDF is kept as it was, with its SHA-256; it is signed with the deployment's cosign
  key when one is set up (`BULWARK_EVIDENCE_SIGNING_KEY`, as for evidence packs).
- A link is shown once; only its token's SHA-256 is stored. It works until it expires (at most 90
  days) or is revoked. Opening it is counted and audit-logged.
- A scheduled report emails each recipient a link, never the PDF itself.
Every change is audit-logged.
"""

from __future__ import annotations

import calendar
import copy
import hashlib
import os
import re
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.collab.people import names
from core.evidence.pack import KEY_ENV
from core.persistence import repo
from core.persistence.models import Organization, Report, ReportLink, ReportRun
from core.reports import blocks as B
from core.reports import pdf, render
from core.reports.blocks import ReportError

MAX_PERIOD_DAYS = 366
MAX_LINK_DAYS = 90
MAX_RECIPIENTS = 20
_EMAIL = re.compile(r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b(i: str, block_type: str, /, **cfg: Any) -> dict[str, Any]:
    return {"id": i, "type": block_type, "config": cfg}


TEMPLATES: dict[str, dict[str, Any]] = {
    "program-weekly": {
        "name": "Weekly program summary",
        "description": "For leads: SLA, what's open, new versus fixed, what's past SLA, new "
        "advisories and acceptances about to expire. Usually scheduled for Monday morning.",
        "period_days": 7,
        "blocks": [
            _b("cover", "cover", title="Weekly security program summary", subtitle=""),
            _b("summary", "summary", text=""),
            _b("sla", "metric", metric="sla_adherence", filters={}),
            _b("open", "metric", metric="open_issues", filters={}),
            _b("nvf", "metric", metric="new_vs_fixed", filters={}),
            _b("past", "metric", metric="past_sla", filters={}),
            _b("adv", "metric", metric="advisory_impact", filters={}),
            _b("exp", "acceptances", state="expiring"),
            _b("appendix", "appendix"),
        ],
    },
    "pentest": {
        "name": "Penetration test report",
        "description": "For a client or an auditor: the engagement's scope, the Issues found, "
        "each important one in detail, and the risks accepted. Choose the engagement and add "
        "Issue blocks for the findings you want in full.",
        "period_days": 90,
        "blocks": [
            _b("cover", "cover", title="Penetration test report", subtitle=""),
            _b("summary", "summary", text=""),
            _b("found", "issues", kind="open", band=None, filters={}, limit=100, title="Findings"),
            _b("accepted", "acceptances", state="approved"),
            _b("appendix", "appendix"),
        ],
    },
    "compliance": {
        "name": "Compliance summary",
        "description": "For an audit: one framework's controls with the evidence Bulwark holds, "
        "SLA adherence and scan coverage over the quarter, and the risks accepted.",
        "period_days": 90,
        "blocks": [
            _b("cover", "cover", title="Compliance summary", subtitle=""),
            _b("summary", "summary", text=""),
            _b("fw", "compliance", framework="owasp-top10-2021"),
            _b("sla", "metric", metric="sla_adherence", filters={}),
            _b("cov", "metric", metric="scan_coverage", filters={}),
            _b("accepted", "acceptances", state="approved"),
            _b("appendix", "appendix"),
        ],
    },
}


def templates() -> list[dict[str, Any]]:
    return [{"id": k, **copy.deepcopy(v)} for k, v in TEMPLATES.items()]


# --- saving ------------------------------------------------------------------------------------


def _name(raw: Any) -> str:
    return B._text(raw, "name", 120, required=True)


def _period(raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= MAX_PERIOD_DAYS:
        raise ReportError("period_days", f"A period of 1 to {MAX_PERIOD_DAYS} days.")
    return raw


def clean_schedule(raw: Any) -> dict[str, Any] | None:
    if raw in (None, {}):
        return None
    if not isinstance(raw, dict):
        raise ReportError("schedule", "A schedule is an object.")
    cadence = B._choice(raw.get("cadence"), "schedule.cadence", ("weekly", "monthly"), "weekly")

    def num(key: str, lo: int, hi: int, default: int) -> int:
        v = raw.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ReportError(f"schedule.{key}", f"A whole number from {lo} to {hi}.")
        return v

    recipients = raw.get("recipients") or []
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise ReportError("schedule.recipients", f"1 to {MAX_RECIPIENTS} email addresses.")
    clean = []
    for r in recipients:
        if not isinstance(r, str) or len(r) > 320 or not _EMAIL.match(r.strip()):
            raise ReportError("schedule.recipients", f"Not an email address: {str(r)[:60]}")
        clean.append(r.strip().lower())
    return {
        "cadence": cadence,
        "weekday": num("weekday", 0, 6, 0),  # Monday = 0
        "day": num("day", 1, 28, 1),
        "hour": num("hour", 0, 23, 8),  # UTC
        "recipients": sorted(set(clean)),
        "link_days": num("link_days", 1, MAX_LINK_DAYS, 14),
    }


def next_run(schedule: dict[str, Any] | None, after: datetime) -> datetime | None:
    """The first scheduled time strictly after `after` (UTC)."""
    if not schedule:
        return None
    base = after.replace(minute=0, second=0, microsecond=0, hour=schedule["hour"])
    if schedule["cadence"] == "weekly":
        t = base + timedelta(days=(schedule["weekday"] - base.weekday()) % 7)
        return t if t > after else t + timedelta(days=7)
    t = base.replace(day=schedule["day"])
    if t > after:
        return t
    month = t.month % 12 + 1
    year = t.year + (1 if month == 1 else 0)
    return t.replace(
        year=year, month=month, day=min(schedule["day"], calendar.monthrange(year, month)[1])
    )


def _audit(s: Session, actor: str, action: str, target: str, org_id: str, **payload: Any) -> None:
    repo.append_audit_entry(
        s, actor=actor, action=action, target=target, payload={"org_id": org_id, **payload}
    )


def view(r: Report) -> dict[str, Any]:
    summary = next((b for b in r.blocks if b["type"] == "summary"), None)
    pending = bool(
        summary
        and summary["config"].get("source") == "ai"
        and not summary["config"].get("reviewed_by")
    )
    return {
        "id": r.id,
        "name": r.name,
        "owner": r.owner,
        "period_days": r.period_days,
        "blocks": r.blocks,
        "schedule": r.schedule,
        "next_run_at": r.next_run_at,
        "version": r.version,
        "updated_at": r.updated_at,
        "updated_by": r.updated_by,
        "summary_needs_review": pending,
    }


def get(s: Session, org_id: str, report_id: str) -> Report:
    r = s.get(Report, report_id)
    if r is None or r.org_id != org_id:
        raise ReportError("id", "No such report.", 404)
    return r


def listing(s: Session, org_id: str) -> list[Report]:
    return list(s.scalars(select(Report).where(Report.org_id == org_id).order_by(Report.name)))


def _with_views(
    s: Session,
    org_id: str,
    actor: str,
    blocks: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """The blocks, once every saved view they name is one `actor` can see (core.search.views)."""
    from core.dashboards import Viewer, role_of
    from core.search import views

    who = Viewer(actor, role_of(s, org_id, actor))

    def can_see(view_id: str) -> bool:
        try:
            views.resolve(s, org_id, view_id, who)
        except views.ViewError:
            return False
        return True

    B.check_views(s, org_id, blocks, can_see, previous)
    return blocks


def create(s: Session, org_id: str, actor: str, raw: dict[str, Any]) -> Report:
    template = raw.get("template")
    base = TEMPLATES.get(str(template)) if template else None
    if template and base is None:
        raise ReportError("template", "No such template.")
    blocks_raw = raw.get("blocks", base["blocks"] if base else [])
    schedule = clean_schedule(raw.get("schedule"))
    now = _now()
    r = Report(
        org_id=org_id,
        name=_name(raw.get("name") or (base or {}).get("name")),
        owner=actor,
        period_days=_period(raw.get("period_days", (base or {}).get("period_days", 30))),
        blocks=_with_views(s, org_id, actor, B.clean_blocks(copy.deepcopy(blocks_raw))),
        schedule=schedule,
        next_run_at=next_run(schedule, now),
        version=1,
        created_at=now,
        updated_at=now,
        updated_by=actor,
    )
    s.add(r)
    s.flush()
    _audit(s, actor, "report.created", f"report:{r.id}", org_id, name=r.name, template=template)
    return r


def update(s: Session, org_id: str, actor: str, report_id: str, raw: dict[str, Any]) -> Report:
    r = get(s, org_id, report_id)
    if raw.get("version") != r.version:
        raise ReportError(
            "version",
            f"Someone saved this report since you opened it (now "
            f"version {r.version}). Reload it, then make your change again.",
            409,
        )
    if "name" in raw:
        r.name = _name(raw["name"])
    if "period_days" in raw:
        r.period_days = _period(raw["period_days"])
    if "blocks" in raw:
        r.blocks = _with_views(s, org_id, actor, B.clean_blocks(raw["blocks"], r.blocks), r.blocks)
    if "schedule" in raw:
        r.schedule = clean_schedule(raw["schedule"])
        r.next_run_at = next_run(r.schedule, _now())
    r.version += 1
    r.updated_at, r.updated_by = _now(), actor
    s.flush()
    _audit(
        s,
        actor,
        "report.saved",
        f"report:{r.id}",
        org_id,
        name=r.name,
        version=r.version,
        scheduled=bool(r.schedule),
        recipients=len((r.schedule or {}).get("recipients", [])),
    )
    return r


def delete(s: Session, org_id: str, actor: str, report_id: str) -> None:
    r = get(s, org_id, report_id)
    _audit(s, actor, "report.deleted", f"report:{r.id}", org_id, name=r.name)
    s.delete(r)
    s.commit()


# --- the executive summary ---------------------------------------------------------------------


def _summary_block(r: Report) -> dict[str, Any]:
    b = next((b for b in r.blocks if b["type"] == "summary"), None)
    if b is None:
        raise ReportError("blocks", "This report has no executive summary block.")
    return b


def set_draft(s: Session, org_id: str, actor: str, r: Report, text: str, model: str) -> Report:
    """Store a model's draft as the summary, unreviewed."""
    blocks = copy.deepcopy(r.blocks)
    b = next(x for x in blocks if x["type"] == "summary")
    b["config"] = {
        "text": text,
        "source": "ai",
        "drafted_by_model": model,
        "reviewed_by": None,
        "reviewed_at": None,
    }
    r.blocks, r.version, r.updated_at, r.updated_by = blocks, r.version + 1, _now(), actor
    s.flush()
    _audit(s, actor, "report.summary.drafted", f"report:{r.id}", org_id, model=model)
    return r


def review_summary(
    s: Session, org_id: str, actor: str, report_id: str, raw: dict[str, Any]
) -> Report:
    """A person accepts the summary as it now reads (edited or not)."""
    r = get(s, org_id, report_id)
    if raw.get("version") != r.version:
        raise ReportError(
            "version", "This report changed since you opened it. Reload it first.", 409
        )
    _summary_block(r)
    blocks = copy.deepcopy(r.blocks)
    b = next(x for x in blocks if x["type"] == "summary")
    text = B._text(raw.get("text", b["config"].get("text")), "text", 8000, required=True)
    b["config"] = {
        **b["config"],
        "text": text,
        "reviewed_by": actor,
        "reviewed_at": _now().isoformat(),
    }
    r.blocks, r.version, r.updated_at, r.updated_by = blocks, r.version + 1, _now(), actor
    s.flush()
    _audit(
        s,
        actor,
        "report.summary.reviewed",
        f"report:{r.id}",
        org_id,
        ai=b["config"].get("source") == "ai",
    )
    return r


# --- generating --------------------------------------------------------------------------------


def _people(s: Session, org_id: str, blocks: list[dict[str, Any]]) -> dict[str, str]:
    actors: set[str] = set()
    for b in blocks:
        cfg, data = b["config"], b.get("data") or {}
        actors.update(x for x in (cfg.get("reviewed_by"),) if x)
        for row in data.get("rows") or []:
            for k in ("assignee", "requested_by", "decided_by", "approved_by"):
                if isinstance(row, dict) and row.get(k):
                    actors.add(str(row[k]))
        if data.get("issue") and data["issue"].get("assignee"):
            actors.add(data["issue"]["assignee"])
    return names(s, org_id, actors)


def build_html(
    s: Session, org_id: str, r: Report, actor: str, now: datetime | None = None
) -> tuple[str, B.Period, list[dict[str, Any]]]:
    now = now or _now()
    period = B.Period.last(r.period_days, now.date())
    collected = B.collect(s, org_id, r.blocks, period, now, owner=r.owner)
    org = s.get(Organization, org_id)
    people = _people(s, org_id, collected)
    by = "a schedule" if actor == "schedule" else people.get(actor, actor)
    doc = render.html(
        r.name,
        collected,
        org=org.name if org else org_id,
        period=f"{period.start.isoformat()} to {period.end.isoformat()}",
        generated=now.strftime("%Y-%m-%d %H:%M UTC"),
        by=by,
        names=people,
    )
    return doc, period, collected


def _sign(data: bytes) -> bytes | None:
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        return None
    from core.attest.cosign import AttestError, sign_blob
    from core.config import scratch_dir

    with tempfile.TemporaryDirectory(prefix="bulwark-report-", dir=scratch_dir()) as tmp:
        work = Path(tmp)
        (work / "report.pdf").write_bytes(data)
        try:
            sign_blob(work / "report.pdf", Path(key), work / "report.pdf.sig")
        except AttestError as exc:
            raise ReportError("signing", f"Could not sign the report: {exc}", 502) from exc
        return (work / "report.pdf.sig").read_bytes()


def request_run(
    s: Session, org_id: str, actor: str, report_id: str, *, trigger: str = "manual"
) -> ReportRun:
    """Queue a report to be rendered: refused while its summary is an unreviewed AI draft. The
    worker renders it (`render_run`); only the worker may run containers."""
    r = get(s, org_id, report_id)
    summary = next((b for b in r.blocks if b["type"] == "summary"), None)
    ai = bool(summary and summary["config"].get("source") == "ai")
    if ai and not summary["config"].get("reviewed_by"):  # type: ignore[index]
        raise ReportError(
            "summary",
            "The executive summary is an AI draft nobody has reviewed yet. "
            "Read it, edit it if needed, and confirm it first.",
            409,
        )
    period = B.Period.last(r.period_days)
    run = ReportRun(
        org_id=org_id, report_id=r.id, report_name=r.name, trigger=trigger, status="queued",
        period_start=period.start, period_end=period.end, sha256="", signed=False, pdf=None,
        signature=None, ai_summary=ai, delivery=[], created_by=actor, created_at=_now(),
    )  # fmt: skip
    s.add(run)
    s.flush()
    _audit(s, actor, "report.requested", f"report-run:{run.id}", org_id, report=r.id,
           trigger=trigger, ai_summary=ai)  # fmt: skip
    return run


def render_run(s: Session, org_id: str, run_id: str) -> ReportRun:
    """Render a queued run: the report as it reads now, to PDF, signed when a key is set up. A
    failure is recorded on the run (and audit-logged), never raised to the worker."""
    run = get_run(s, org_id, run_id)
    if run.status != "queued":
        return run  # a redelivered job for a run already rendered does nothing
    try:
        r = get(s, org_id, run.report_id)
        doc, _, _ = build_html(s, org_id, r, run.created_by)
        try:
            data = pdf.to_pdf(doc)
        except pdf.RenderError as exc:
            raise ReportError("pdf", f"Could not make the PDF: {exc}.", 502) from exc
        signature = _sign(data)
    except ReportError as exc:
        s.rollback()
        run = get_run(s, org_id, run_id)
        run.status, run.error = "failed", exc.message[:500]
        s.flush()
        _audit(s, run.created_by, "report.failed", f"report-run:{run.id}", org_id,
               reason=run.error)  # fmt: skip
        return run
    run.status, run.error = "done", None
    run.pdf, run.sha256 = data, hashlib.sha256(data).hexdigest()
    run.signature, run.signed = signature, signature is not None
    s.flush()
    _audit(s, run.created_by, "report.generated", f"report-run:{run.id}", org_id,
           report=run.report_id, sha256=run.sha256, signed=run.signed, trigger=run.trigger,
           ai_summary=run.ai_summary)  # fmt: skip
    return run


def generate(
    s: Session, org_id: str, actor: str, report_id: str, *, trigger: str = "manual"
) -> ReportRun:
    """Queue and render at once: for the worker's schedules, and for tests."""
    run = request_run(s, org_id, actor, report_id, trigger=trigger)
    return render_run(s, org_id, run.id)


def runs(s: Session, org_id: str, report_id: str) -> list[ReportRun]:
    get(s, org_id, report_id)
    return list(
        s.scalars(
            select(ReportRun)
            .where(ReportRun.org_id == org_id, ReportRun.report_id == report_id)
            .order_by(ReportRun.created_at.desc())
            .limit(50)
        )
    )


def get_run(s: Session, org_id: str, run_id: str) -> ReportRun:
    run = s.get(ReportRun, run_id)
    if run is None or run.org_id != org_id:
        raise ReportError("id", "No such generated report.", 404)
    return run


def run_view(run: ReportRun, people: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "id": run.id,
        "report_id": run.report_id,
        "report_name": run.report_name,
        "trigger": run.trigger,
        "status": run.status,
        "error": run.error,
        "period": [run.period_start.isoformat(), run.period_end.isoformat()],
        "sha256": run.sha256,
        "signed": run.signed,
        "size": len(run.pdf or b""),
        "ai_summary": run.ai_summary,
        "delivery": run.delivery,
        "created_by": run.created_by,
        "created_by_name": (people or {}).get(run.created_by, run.created_by),
        "created_at": run.created_at,
    }


# --- links -------------------------------------------------------------------------------------


def people_of(s: Session, org_id: str, actors: set[str]) -> dict[str, str]:
    return names(s, org_id, {a for a in actors if a})


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def done_run(s: Session, org_id: str, run_id: str) -> ReportRun:
    run = get_run(s, org_id, run_id)
    if run.status != "done" or run.pdf is None:
        word = "failed" if run.status == "failed" else "is still being made"
        raise ReportError("id", f"This report {word}; there is no PDF to share.", 409)
    return run


def create_link(
    s: Session, org_id: str, actor: str, run_id: str, days: Any
) -> tuple[ReportLink, str]:
    run = done_run(s, org_id, run_id)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_LINK_DAYS:
        raise ReportError("days", f"A link lasts 1 to {MAX_LINK_DAYS} days.")
    token = secrets.token_urlsafe(32)
    link = ReportLink(
        org_id=org_id,
        run_id=run.id,
        token_hash=_hash(token),
        created_by=actor,
        created_at=_now(),
        expires_at=_now() + timedelta(days=days),
        opens=0,
    )
    s.add(link)
    s.flush()
    _audit(
        s,
        actor,
        "report.link.created",
        f"report-link:{link.id}",
        org_id,
        run=run.id,
        expires_at=link.expires_at.isoformat(),
    )
    return link, token


def links(s: Session, org_id: str, run_id: str) -> list[ReportLink]:
    get_run(s, org_id, run_id)
    return list(
        s.scalars(
            select(ReportLink)
            .where(ReportLink.org_id == org_id, ReportLink.run_id == run_id)
            .order_by(ReportLink.created_at.desc())
        )
    )


def link_view(
    link: ReportLink, now: datetime | None = None, people: dict[str, str] | None = None
) -> dict[str, Any]:
    now = now or _now()
    exp = (
        link.expires_at if link.expires_at.tzinfo else link.expires_at.replace(tzinfo=timezone.utc)
    )
    state = "revoked" if link.revoked_at else ("expired" if exp <= now else "active")
    return {
        "id": link.id,
        "run_id": link.run_id,
        "created_by": link.created_by,
        "created_by_name": (people or {}).get(link.created_by, link.created_by),
        "created_at": link.created_at,
        "expires_at": exp,
        "state": state,
        "revoked_by": link.revoked_by,
        "opens": link.opens,
        "last_opened_at": link.last_opened_at,
    }


def revoke_link(s: Session, org_id: str, actor: str, link_id: str) -> ReportLink:
    link = s.get(ReportLink, link_id)
    if link is None or link.org_id != org_id:  # no RLS on this table: the org check is the guard
        raise ReportError("id", "No such link.", 404)
    if link.revoked_at is None:
        link.revoked_at, link.revoked_by = _now(), actor
        s.flush()
        _audit(s, actor, "report.link.revoked", f"report-link:{link.id}", org_id, run=link.run_id)
    return link


def resolve_link(s: Session, token: str) -> ReportLink | None:
    """The link a token opens, if it is still good. Unscoped by design (see `ReportLink`)."""
    if not token or len(token) > 100:
        return None
    link = s.scalar(select(ReportLink).where(ReportLink.token_hash == _hash(token)))
    if link is None or link.revoked_at is not None:
        return None
    exp = (
        link.expires_at if link.expires_at.tzinfo else link.expires_at.replace(tzinfo=timezone.utc)
    )
    return link if exp > _now() else None


def opened(s: Session, link: ReportLink) -> None:
    link.opens += 1
    link.last_opened_at = _now()
    s.flush()
    _audit(s, "link", "report.link.opened", f"report-link:{link.id}", link.org_id, run=link.run_id)


# --- schedules ---------------------------------------------------------------------------------


def link_url(token: str) -> str | None:
    base = os.environ.get("BULWARK_API_PUBLIC_URL", "").strip().rstrip("/")
    return f"{base}/r/{token}" if base else None


def run_due(s: Session, org_id: str, now: datetime | None = None, send: Any = None) -> int:
    """Generate and email every report of the organization whose schedule is due. Returns how many
    ran. A failure is recorded and the report moves to its next time; it never stops the rest."""
    from core.notify import email

    now = now or _now()
    if send is None:
        cfg = email.SmtpConfig.from_env()
        if cfg is not None:
            send = lambda to, subject, body: email.send(cfg, to, subject, body)  # noqa: E731
    due = list(
        s.scalars(
            select(Report).where(
                Report.org_id == org_id, Report.next_run_at.is_not(None), Report.next_run_at <= now
            )
        )
    )
    for r in due:
        sched = r.schedule or {}
        r.next_run_at = next_run(sched, now)
        try:
            run = generate(s, org_id, "schedule", r.id, trigger="schedule")
        except ReportError as exc:
            s.rollback()
            r = get(s, org_id, r.id)
            r.next_run_at = next_run(sched, now)
            _audit(
                s,
                "schedule",
                "report.schedule.failed",
                f"report:{r.id}",
                org_id,
                reason=exc.message[:300],
            )
            s.commit()
            continue
        if run.status != "done":  # rendering failed: recorded on the run; nothing to send
            r = get(s, org_id, r.id)
            r.next_run_at = next_run(sched, now)
            _audit(s, "schedule", "report.schedule.failed", f"report:{r.id}", org_id,
                   reason=(run.error or "")[:300])  # fmt: skip
            s.commit()
            continue
        link, token = create_link(s, org_id, "schedule", run.id, sched.get("link_days", 14))
        url = link_url(token)
        summary = next(
            (b["config"].get("text", "") for b in r.blocks if b["type"] == "summary"), ""
        )
        delivery = []
        for to in sched.get("recipients", []):
            if send is None:
                delivery.append({"to": to, "status": "not sent", "reason": "no SMTP server set up"})
                continue
            if url is None:
                delivery.append(
                    {"to": to, "status": "not sent", "reason": "BULWARK_API_PUBLIC_URL is not set"}
                )
                continue
            body = (
                f"{r.name}, {run.period_start} to {run.period_end}.\n\n"
                + (f"{summary}\n\n" if summary else "")
                + f"Read it: {url}\nThe link works until {link.expires_at:%Y-%m-%d}.\n\n"
                f"SHA-256 of the PDF: {run.sha256}"
                + ("\nSigned with the deployment's cosign key." if run.signed else "")
                + "\n\nSent by Bulwark on a schedule."
            )
            try:
                send(to, f"{r.name}: {run.period_end}", body)
                delivery.append({"to": to, "status": "sent"})
            except Exception as exc:  # noqa: BLE001 - one bad address must not stop the rest
                delivery.append({"to": to, "status": "failed", "reason": type(exc).__name__})
        run.delivery = delivery
        s.flush()
        _audit(
            s,
            "schedule",
            "report.sent",
            f"report-run:{run.id}",
            org_id,
            sent=sum(d["status"] == "sent" for d in delivery),
            recipients=len(delivery),
        )
        s.commit()
    return len(due)
