"""Evidence packs (plan §47): for a period and the frameworks asked for, what an auditor needs --
SLA adherence, every risk acceptance with its approvals, scan coverage per project, open Issues by
priority, the component inventory, advisory monitoring, VEX, assessments, the policies in force,
how each framework's controls map to that evidence, and an extract of the tamper-evident audit log
with its hash-chain check and Rekor checkpoints.

One bundle (a zip): `evidence.pdf` to read, `evidence.json` and `audit-extract.json` to process,
`verify.py` (standard library only) to check the files and the audit chain without trusting
Bulwark, and `manifest.json` with every file's SHA-256 -- signed with the deployment's cosign key
when one is configured (`BULWARK_EVIDENCE_SIGNING_KEY`), and plainly marked unsigned when not.

Definitions (also printed in the PDF):
- SLA adherence: Issues whose SLA deadline fell in the period, under the SLA policy in force at the
  period's end; "met" if fixed by the deadline, "missed" if fixed after it, "open past deadline"
  if not fixed by the period's end; Issues a person marked not a risk or accepted are "exempt"
  (their triage as it stands now: triage history is in the audit log). Adherence is met / (met +
  missed + open past deadline).
- Open Issues: as of when the pack was generated, not as of the period's end.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from core import compliance
from core.compliance import asvs
from core.evidence import audit_extract, verifier
from core.export.sarif import _version
from core.inventory.search import exposures
from core.issues import LIVE_STATES
from core.persistence.models import (
    AdvisoryImpact,
    AdvisoryState,
    Asset,
    ComponentRow,
    Engagement,
    EvidencePack,
    FeedState,
    IssueRow,
    KevEntry,
    Organization,
    PriorityPolicy,
    RiskAcceptance,
    RiskAcceptanceIssue,
    Scan,
    SlaPolicy,
    VexStatement,
)
from core.sla.policy import evaluate, from_row

log = logging.getLogger(__name__)
FORMAT = "bulwark-evidence-pack/1"
ADVISORY_TOOL = "bulwark-advisories"
MAX_DAYS = 400
MAX_ROWS = 5000
KEY_ENV = "BULWARK_EVIDENCE_SIGNING_KEY"
PUB_ENV = "BULWARK_AUDIT_CHECKPOINT_PUB"
ROOT_ENV = "BULWARK_REKOR_TRUSTED_ROOT"


class PackError(ValueError):
    pass


class SigningError(RuntimeError):
    """A signing key is configured but signing failed: no pack is made, rather than an unsigned
    one passing for a signed one."""


def signing_configured() -> bool:
    return bool(os.environ.get(KEY_ENV, "").strip())


def window(start: date, end: date) -> tuple[datetime, datetime]:
    if end < start:
        raise PackError("the period ends before it starts")
    if (end - start).days + 1 > MAX_DAYS:
        raise PackError(f"a pack covers at most {MAX_DAYS} days")
    lo = datetime.combine(start, time.min, tzinfo=timezone.utc)
    return lo, datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    dt = _utc(dt)
    return dt.isoformat() if dt else None


def _assets(s: Session, org_id: str) -> list[Asset]:
    return list(s.scalars(select(Asset).where(Asset.org_id == org_id).order_by(Asset.label)))


# --- sections --------------------------------------------------------------------------------


def scan_coverage(
    s: Session, org_id: str, assets: list[Asset], lo: datetime, hi: datetime
) -> dict[str, Any]:
    exposure = exposures(s, [a.id for a in assets])
    rows = []
    for a in assets:
        scans = list(
            s.scalars(
                select(Scan).where(
                    Scan.org_id == org_id, Scan.asset_id == a.id, Scan.status == "completed",
                    Scan.finished_at >= lo, Scan.finished_at < hi,
                )
            )
        )  # fmt: skip
        last = s.scalar(
            select(func.max(Scan.finished_at)).where(
                Scan.asset_id == a.id, Scan.status == "completed", Scan.finished_at < hi,
                Scan.source_type != "import",
            )
        )  # fmt: skip
        # Bulwark's own bookkeeping (the Advisories Test re-imported as matching changes) is not a
        # scan of anything; other imported reports are counted, but apart from Bulwark's scans.
        scans = [x for x in scans if (x.tools or []) != [ADVISORY_TOOL]]
        imported = [x for x in scans if x.source_type == "import"]
        own = [x for x in scans if x.source_type != "import"]
        full = [x for x in own if x.ref is None]
        rows.append({
            "project_id": a.id, "project": a.label, "kind": a.source_type,
            "exposure": exposure.get(a.id, "unset"), "full_scans": len(full),
            "pull_request_scans": len(own) - len(full), "imported_reports": len(imported),
            "dast_scans": sum(1 for x in own if x.source_type == "web"),
            "tools": sorted({t for x in scans for t in (x.tools or [])}),
            "last_scan_at": _iso(last),
        })  # fmt: skip
    return {
        "projects": len(rows), "scanned": sum(1 for r in rows if r["full_scans"]),
        "not_scanned": [r["project"] for r in rows if not r["full_scans"]], "rows": rows,
    }  # fmt: skip


def _policy_at(s: Session, asset_id: str, hi: datetime) -> SlaPolicy | None:
    return s.scalar(
        select(SlaPolicy)
        .where(SlaPolicy.asset_id == asset_id, SlaPolicy.created_at < hi)
        .order_by(SlaPolicy.version.desc())
        .limit(1)
    )


def sla_adherence(s: Session, assets: list[Asset], lo: datetime, hi: datetime) -> dict[str, Any]:
    total: Counter[str] = Counter()
    per_band: dict[str, Counter[str]] = defaultdict(Counter)
    rows: list[dict[str, Any]] = []
    for a in assets:
        row = _policy_at(s, a.id, hi)
        if row is None or not row.enabled:
            rows.append({"project_id": a.id, "project": a.label, "policy": None})
            continue
        policy = from_row(row.enabled, row.basis, row.bands)
        counts: Counter[str] = Counter()
        for i in s.execute(
            select(
                IssueRow.severity, IssueRow.priority_override, IssueRow.priority_band,
                IssueRow.first_seen_at, IssueRow.sla_started_at, IssueRow.fixed_at,
                IssueRow.triage_status, IssueRow.triage_expires_at,
            ).where(IssueRow.asset_id == a.id, IssueRow.first_seen_at < hi)
        ):  # fmt: skip
            fixed_at = _utc(i.fixed_at)
            fixed_by_end = fixed_at is not None and fixed_at < hi
            st = evaluate(
                policy, severity=i.severity,
                priority_band=i.priority_override or i.priority_band,
                state="fixed" if fixed_by_end else "open", first_seen_at=i.first_seen_at,
                sla_started_at=i.sla_started_at, fixed_at=fixed_at if fixed_by_end else None,
                triage_status=i.triage_status, triage_expires_at=i.triage_expires_at, now=hi,
            )  # fmt: skip
            due = _utc(st.due_at)
            if due is None or not (lo <= due < hi):
                continue
            outcome = {"met": "met", "missed": "missed", "breached": "open_past_deadline",
                       "exempt": "exempt"}.get(st.state)  # fmt: skip
            if outcome is None:
                continue
            band = (
                (i.priority_override or i.priority_band or "none")
                if policy.basis == "priority"
                else i.severity
            )
            counts[outcome] += 1
            per_band[band][outcome] += 1
        total.update(counts)
        rows.append({"project_id": a.id, "project": a.label,
                     "policy": {"version": row.version, "basis": row.basis}, **counts})  # fmt: skip
    decided = total["met"] + total["missed"] + total["open_past_deadline"]
    return {
        "met": total["met"], "missed": total["missed"],
        "open_past_deadline": total["open_past_deadline"], "exempt": total["exempt"],
        "adherence": round(total["met"] / decided, 4) if decided else None,
        "by_band": {b: dict(c) for b, c in sorted(per_band.items())}, "rows": rows,
    }  # fmt: skip


def risk_acceptances(
    s: Session, org_id: str, assets: list[Asset], lo: datetime, hi: datetime
) -> dict[str, Any]:
    labels = {a.id: a.label for a in assets}
    q = (
        select(RiskAcceptance)
        .where(
            RiskAcceptance.org_id == org_id,
            or_(
                and_(RiskAcceptance.requested_at >= lo, RiskAcceptance.requested_at < hi),
                and_(RiskAcceptance.decided_at >= lo, RiskAcceptance.decided_at < hi),
                and_(
                    RiskAcceptance.decided_at < hi,
                    RiskAcceptance.state.in_(("approved", "expired", "extended")),
                    RiskAcceptance.expires_at >= lo,
                ),
            ),
        )
        .order_by(RiskAcceptance.requested_at)
        .limit(MAX_ROWS)
    )
    rows = []
    for ra in s.scalars(q):
        n = s.scalar(
            select(func.count())
            .select_from(RiskAcceptanceIssue)
            .where(RiskAcceptanceIssue.acceptance_id == ra.id)
        )
        rows.append({
            "id": ra.id, "project": labels.get(ra.asset_id, ra.asset_id), "decision": ra.decision,
            "state": ra.state, "issues": n, "justification": ra.justification,
            "controls": ra.controls, "requested_by": ra.requested_by,
            "requested_at": _iso(ra.requested_at), "decided_by": ra.decided_by,
            "decided_at": _iso(ra.decided_at), "expires_at": _iso(ra.expires_at),
            "ended_reason": ra.ended_reason, "legacy": ra.legacy,
            "second_person": bool(ra.decided_by) and ra.decided_by != ra.requested_by,
        })  # fmt: skip
    by_state = Counter(r["state"] for r in rows)
    return {"count": len(rows), "by_state": dict(by_state), "rows": rows,
            "truncated": len(rows) >= MAX_ROWS}  # fmt: skip


def open_issues(s: Session, assets: list[Asset]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    by_priority: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    rows = []
    for a in assets:
        mine: Counter[str] = Counter()
        for override, computed, severity, status, expires in s.execute(
            select(
                IssueRow.priority_override, IssueRow.priority_band, IssueRow.severity,
                IssueRow.triage_status, IssueRow.triage_expires_at,
            ).where(IssueRow.asset_id == a.id, IssueRow.state.in_(sorted(LIVE_STATES)))
        ):  # fmt: skip
            if not asvs._active_row(status, expires, now):
                continue
            band = override or computed or "none"
            mine[band] += 1
            by_priority[band] += 1
            by_severity[severity] += 1
        rows.append({"project_id": a.id, "project": a.label, **mine, "total": sum(mine.values())})
    return {"as_of": now.isoformat(), "by_priority": dict(sorted(by_priority.items())),
            "by_severity": dict(by_severity), "total": sum(by_priority.values()),
            "rows": rows}  # fmt: skip


def inventory(s: Session, org_id: str, assets: list[Asset]) -> dict[str, Any]:
    rows = []
    for a in assets:
        n = s.scalar(
            select(func.count())
            .select_from(ComponentRow)
            .where(ComponentRow.asset_id == a.id, ComponentRow.current.is_(True))
        )
        rows.append({"project_id": a.id, "project": a.label, "components": n or 0})
    libs = s.scalar(
        select(func.count(func.distinct(ComponentRow.library_id))).where(
            ComponentRow.org_id == org_id, ComponentRow.current.is_(True)
        )
    )
    return {"libraries": libs or 0, "with_sbom": sum(1 for r in rows if r["components"]),
            "rows": rows}  # fmt: skip


def advisories(s: Session, org_id: str, lo: datetime, hi: datetime) -> dict[str, Any]:
    feeds = [
        {"source": f.source, "last_success_at": _iso(f.last_success_at), "records": f.records,
         "last_error": f.last_error}  # fmt: skip
        for f in s.scalars(select(FeedState).order_by(FeedState.source))
    ]
    new = list(
        s.scalars(
            select(AdvisoryState.vuln_key).where(
                AdvisoryState.org_id == org_id,
                AdvisoryState.first_seen_at >= lo,
                AdvisoryState.first_seen_at < hi,
            )
        )
    )
    kev = (
        s.scalar(select(func.count()).select_from(KevEntry).where(KevEntry.cve.in_(new)))
        if new
        else 0
    )
    acted = s.scalar(
        select(func.count()).select_from(AdvisoryState).where(
            AdvisoryState.org_id == org_id, AdvisoryState.vuln_key.in_(new),
            AdvisoryState.state == "issues",
        )
    ) if new else 0  # fmt: skip
    open_now = s.scalar(
        select(func.count(func.distinct(AdvisoryImpact.vuln_key))).where(
            AdvisoryImpact.org_id == org_id, AdvisoryImpact.resolved_at.is_(None)
        )
    )
    return {"feeds": feeds, "new_in_period": len(new), "new_known_exploited": kev or 0,
            "new_with_issues": acted or 0, "affecting_now": open_now or 0}  # fmt: skip


def vex(s: Session, org_id: str, lo: datetime, hi: datetime) -> dict[str, Any]:
    decided = list(
        s.scalars(
            select(VexStatement).where(
                VexStatement.org_id == org_id,
                VexStatement.decided_at >= lo,
                VexStatement.decided_at < hi,
            )
        )
    )
    pending = s.scalar(
        select(func.count())
        .select_from(VexStatement)
        .where(VexStatement.org_id == org_id, VexStatement.state == "proposed")
    )
    dismissed = s.scalar(
        select(func.count()).select_from(IssueRow).join(Asset, Asset.id == IssueRow.asset_id).where(
            Asset.org_id == org_id, IssueRow.triage_justification.is_not(None),
            IssueRow.triaged_at >= lo, IssueRow.triaged_at < hi,
        )
    )  # fmt: skip
    return {
        "confirmed": sum(1 for v in decided if v.state in ("confirmed", "withdrawn")),
        "rejected": sum(1 for v in decided if v.state == "rejected"),
        "withdrawn_since": sum(1 for v in decided if v.state == "withdrawn"),
        "by_evidence": dict(Counter((v.evidence or {}).get("kind", "") for v in decided
                                    if v.state != "rejected")),
        "proposed_waiting": pending or 0, "issues_dismissed_with_justification": dismissed or 0,
    }  # fmt: skip


def engagements(
    s: Session, org_id: str, assets: list[Asset], lo: datetime, hi: datetime
) -> dict[str, Any]:
    labels = {a.id: a.label for a in assets}
    rows = [
        {"id": e.id, "name": e.name, "type": e.engagement_type, "status": e.status,
         "project": labels.get(e.asset_id, e.asset_id), "checklist": e.checklist,
         "started_at": _iso(e.started_at), "closed_at": _iso(e.closed_at),
         "report": e.report_generated_at is not None}  # fmt: skip
        for e in s.scalars(
            select(Engagement)
            .where(
                Engagement.org_id == org_id,
                Engagement.engagement_type.in_(("pentest", "audit", "adhoc")),
                Engagement.started_at < hi,
                or_(Engagement.closed_at.is_(None), Engagement.closed_at >= lo),
            )
            .order_by(Engagement.started_at)
        )
    ]
    return {"count": len(rows), "rows": rows}


def policies(s: Session, assets: list[Asset], hi: datetime) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for a in assets:
        sla = _policy_at(s, a.id, hi)
        pri = s.scalar(
            select(PriorityPolicy)
            .where(PriorityPolicy.asset_id == a.id, PriorityPolicy.created_at < hi)
            .order_by(PriorityPolicy.version.desc())
            .limit(1)
        )
        rows.append({
            "project": a.label,
            "sla": {"version": sla.version, "enabled": sla.enabled, "basis": sla.basis,
                    "bands": sla.bands} if sla else None,
            "priority": {"version": pri.version} if pri else None,
        })  # fmt: skip
    return {"with_sla": sum(1 for r in rows if r["sla"] and r["sla"]["enabled"]), "rows": rows}


def _issues_by_cwe(per_asset: dict[str, dict[str, list[str]]]) -> dict[str, int]:
    out: Counter[str] = Counter()
    for by_cwe in per_asset.values():
        for cwe, ids in by_cwe.items():
            out[cwe] += len(ids)
    return dict(out)


def mapping(
    s: Session, org_id: str, assets: list[Asset], ids: list[str], ev: dict[str, Any]
) -> list[dict[str, Any]]:
    per_asset = {a.id: asvs.open_issues_by_cwe(s, a.id) for a in assets} if ids else {}
    by_cwe = _issues_by_cwe(per_asset)
    have = {
        "scan_coverage": f"{ev['scan_coverage']['scanned']} of {ev['scan_coverage']['projects']} projects scanned in the period",  # noqa: E501
        "dast": f"{sum(r['dast_scans'] for r in ev['scan_coverage']['rows'])} web scans in the period",  # noqa: E501
        "sla_adherence": (
            f"{ev['sla']['met']} met, {ev['sla']['missed']} missed, "
            f"{ev['sla']['open_past_deadline']} open past deadline"
        ),
        "risk_acceptances": f"{ev['risk_acceptances']['count']} risk acceptances",
        "open_issues": f"{ev['open_issues']['total']} open Issues",
        "audit_log": f"{len(ev['audit']['entries'])} audit-log entries checked",
        "component_inventory": f"{ev['inventory']['libraries']} libraries in {ev['inventory']['with_sbom']} projects' SBOMs",  # noqa: E501
        "advisory_monitoring": f"{len(ev['advisories']['feeds'])} advisory sources; {ev['advisories']['new_in_period']} new vulnerabilities affecting projects",  # noqa: E501
        "vex": f"{ev['vex']['confirmed']} VEX statements confirmed",
        "engagements": f"{ev['engagements']['count']} assessments",
        "policies": f"{ev['policies']['with_sla']} projects with an SLA policy",
    }
    out = []
    for fid in ids:
        fw = compliance.get(fid)
        if fw is None:
            continue
        controls = []
        for c in fw.controls:
            evidence = [{"kind": k, "label": compliance.EVIDENCE[k], "here": have.get(k, "")}
                        for k in c.evidence if k != "issues_by_cwe"]  # fmt: skip
            if "issues_by_cwe" in c.evidence:
                n = sum(by_cwe.get(w, 0) for w in c.cwes)
                evidence.append(
                    {
                        "kind": "issues_by_cwe",
                        "label": compliance.EVIDENCE["issues_by_cwe"],
                        "here": f"{n} open Issues of {len(c.cwes)} mapped CWEs",
                    }
                )
            controls.append({"id": c.id, "title": c.title, "group": c.group, "level": c.level,
                             "evidence": evidence, "note": c.note})  # fmt: skip
        entry: dict[str, Any] = {**fw.summary(), "controls": controls}
        if fid == asvs.FRAMEWORK:
            entry["projects"] = [
                {
                    "project": a.label,
                    **asvs.benchmark(s, org_id, a.id, level=2, by_cwe=per_asset[a.id])["counts"],
                }
                for a in assets
            ]
        out.append(entry)
    return out


# --- the pack --------------------------------------------------------------------------------


def collect(
    s: Session, org_id: str, start: date, end: date, frameworks: list[str]
) -> dict[str, Any]:
    lo, hi = window(start, end)
    unknown = [f for f in frameworks if compliance.get(f) is None]
    if unknown:
        raise PackError(f"unknown frameworks: {', '.join(unknown)}")
    org = s.get(Organization, org_id)
    assets = _assets(s, org_id)
    ev: dict[str, Any] = {
        "format": FORMAT, "organization": {"id": org_id, "name": org.name if org else ""},
        "period": {"start": start.isoformat(), "end": end.isoformat(),
                   "from": lo.isoformat(), "until": hi.isoformat()},
        "generated_at": datetime.now(timezone.utc).isoformat(), "bulwark_version": _version(),
        "disclaimer": compliance.DISCLAIMER,
        "scan_coverage": scan_coverage(s, org_id, assets, lo, hi),
        "sla": sla_adherence(s, assets, lo, hi),
        "risk_acceptances": risk_acceptances(s, org_id, assets, lo, hi),
        "open_issues": open_issues(s, assets),
        "inventory": inventory(s, org_id, assets),
        "advisories": advisories(s, org_id, lo, hi),
        "vex": vex(s, org_id, lo, hi),
        "engagements": engagements(s, org_id, assets, lo, hi),
        "policies": policies(s, assets, hi),
        "audit": audit_extract.extract(s, org_id, lo, hi),
    }  # fmt: skip
    ev["audit_check"] = verifier.verify_extract(ev["audit"])
    ev["frameworks"] = mapping(s, org_id, assets, frameworks, ev)
    return ev


def summary(ev: dict[str, Any]) -> dict[str, Any]:
    a = ev["audit_check"]
    return {
        "projects": ev["scan_coverage"]["projects"],
        "scanned": ev["scan_coverage"]["scanned"],
        "sla": {
            k: ev["sla"][k] for k in ("met", "missed", "open_past_deadline", "exempt", "adherence")
        },  # noqa: E501
        "risk_acceptances": ev["risk_acceptances"]["count"],
        "open_issues": ev["open_issues"]["total"],
        "vex_confirmed": ev["vex"]["confirmed"],
        "engagements": ev["engagements"]["count"],
        "audit": {"entries": a["entries"], "disclosed": a["disclosed"], "ok": a["ok"],
                  "anchored_at": a["anchored_at"], "linked_only": a["linked_only"]},  # fmt: skip
        "frameworks": [f["id"] for f in ev["frameworks"]],
    }


@dataclass
class Built:
    bundle: bytes
    sha256: str
    signed: bool
    summary: dict[str, Any]


def _sign(manifest: bytes) -> bytes | None:
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        return None
    from core.attest.cosign import AttestError, sign_blob
    from core.config import scratch_dir

    with tempfile.TemporaryDirectory(prefix="bulwark-evidence-", dir=scratch_dir()) as tmp:
        work = Path(tmp)
        (work / "manifest.json").write_bytes(manifest)
        try:
            sign_blob(work / "manifest.json", Path(key), work / "manifest.json.sig")
        except AttestError as exc:
            raise SigningError(f"could not sign the evidence pack: {exc}") from exc
        return (work / "manifest.json.sig").read_bytes()


README = """Bulwark evidence pack
=====================

{org} -- {start} to {end}. Generated {generated} by {by}.

{disclaimer}

Files
  evidence.pdf          the pack, to read
  evidence.json         the same evidence, machine-readable
  audit-extract.json    the audit-log extract: this organization's entries in the period in full,
                        every other entry as hashes only
  checkpoints/          each Rekor checkpoint's Sigstore bundle
  audit.pub             the checkpoint key's public half, when the deployment provides it
  trusted-root.json     a private Rekor's trusted root, when the deployment uses one
  verify.py             checks every file against manifest.json and recomputes the audit chain
                        (Python 3, standard library only)
  manifest.json         every file's SHA-256
  manifest.json.sig     cosign's signature over manifest.json {signed}

Check it:   python3 verify.py
"""


def build(
    s: Session, org_id: str, start: date, end: date, frameworks: list[str], *, actor: str
) -> Built:
    from core.evidence.render import to_pdf

    ev = collect(s, org_id, start, end, frameworks)
    files: dict[str, bytes] = {
        "evidence.json": json.dumps(ev, indent=2, sort_keys=True, default=str).encode(),
        "audit-extract.json": json.dumps(ev["audit"], indent=2, sort_keys=True).encode(),
        "verify.py": Path(verifier.__file__).read_bytes(),
    }
    for cp in ev["audit"]["checkpoints"]:
        files[f"checkpoints/{cp['seq_end']}.bundle"] = (cp["bundle"] or "").encode()
    # What checks the checkpoints, when the deployment says: the checkpoint key's public half and,
    # for a private Rekor, its trusted root. An auditor should still get the public key from the
    # organization itself, not only from the pack it is meant to check.
    for env_name, name in ((PUB_ENV, "audit.pub"), (ROOT_ENV, "trusted-root.json")):
        path = os.environ.get(env_name, "").strip()
        if path and Path(path).is_file():
            files[name] = Path(path).read_bytes()
    files["evidence.pdf"] = to_pdf(ev, signed=signing_configured())
    files["README.txt"] = README.format(
        org=ev["organization"]["name"] or org_id, start=start, end=end,
        generated=ev["generated_at"], by=actor, disclaimer=compliance.DISCLAIMER,
        signed="(present only when the deployment has a signing key)",
    ).encode()  # fmt: skip
    manifest = json.dumps(
        {"format": FORMAT, "organization": org_id, "period": ev["period"],
         "generated_at": ev["generated_at"], "generated_by": actor,
         "files": {n: hashlib.sha256(b).hexdigest() for n, b in sorted(files.items())}},
        indent=2, sort_keys=True,
    ).encode()  # fmt: skip
    files["manifest.json"] = manifest
    sig = _sign(manifest)
    if sig is not None:
        files["manifest.json.sig"] = sig
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    bundle = buf.getvalue()
    return Built(bundle, hashlib.sha256(bundle).hexdigest(), sig is not None, summary(ev))


def create(
    s: Session, org_id: str, start: date, end: date, frameworks: list[str], *, actor: str
) -> EvidencePack:
    from core.persistence import repo

    built = build(s, org_id, start, end, frameworks, actor=actor)
    row = EvidencePack(
        org_id=org_id, period_start=start, period_end=end, frameworks=frameworks,
        summary=built.summary, sha256=built.sha256, signed=built.signed, bundle=built.bundle,
        created_by=actor,
    )  # fmt: skip
    s.add(row)
    s.flush()
    repo.append_audit_entry(  # commits, with the pack
        s, actor=actor, action="evidence_pack.created", target=f"evidence_pack:{row.id}",
        org_id=org_id,
        payload={"period": [start.isoformat(), end.isoformat()], "frameworks": frameworks,
                 "sha256": built.sha256, "signed": built.signed},
    )  # fmt: skip
    return row
