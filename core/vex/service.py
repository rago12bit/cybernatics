"""VEX statements: drafted with evidence, confirmed by a person (plan §46.3, §55.5).

"Draft VEX for the others" on an advisory's impact view proposes `not_affected` /
`vulnerable_code_not_in_execute_path` for each open use where `core.vex.evidence` finds evidence,
and nothing for the rest. A proposal is only a proposal: it is exported nowhere until a person
confirms it -- with a personal token, not the shared one -- and confirming marks the matching
Issue, if there is one, not a risk with the same justification. Reopening that Issue withdraws the
statement. Every step is in the audit log.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import (
    Advisory,
    AdvisoryImpact,
    ComponentRow,
    IssueRow,
    Library,
    VexStatement,
)
from core.reachability.golang import GoUsage
from core.vex.evidence import Assessment, assess, go_usage

SHARED = "shared-token"
LIVE = ("proposed", "confirmed")
JUSTIFICATION = "vulnerable_code_not_in_execute_path"


class VexError(ValueError):
    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue_fingerprint(ecosystem: str, name: str, version: str, vuln_key: str) -> str:
    """The fingerprint a dependency Issue for this has (`core.correlation.engine.fingerprint`)."""
    raw = f"{ecosystem}|{name}|{version}|{vuln_key.upper()}"
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def issues_for(
    s: Session, asset_id: str, lib: Library, version: str, vuln_key: str
) -> list[IssueRow]:
    fp = issue_fingerprint(lib.ecosystem, lib.name, version, vuln_key)
    return list(
        s.scalars(
            select(IssueRow).where(
                IssueRow.asset_id == asset_id,
                IssueRow.category.in_(("sca", "container")),
                IssueRow.fingerprint == fp,
            )
        )
    )


@dataclass
class Use:
    impact: AdvisoryImpact
    library: Library
    component: ComponentRow | None
    assessment: Assessment
    statement: VexStatement | None
    scan_id: str | None


def _malicious(s: Session, advisory_ids: list[str]) -> bool:
    if any(a.startswith("MAL-") for a in advisory_ids):
        return True
    return any(
        any(x.startswith("MAL-") for x in aliases or [])
        for aliases in s.scalars(select(Advisory.aliases).where(Advisory.id.in_(advisory_ids)))
    )


def uses(s: Session, org_id: str, vuln_key: str) -> list[Use]:
    """Every open use of the vulnerability, with its evidence and its live or last statement."""
    rows = s.execute(
        select(AdvisoryImpact, Library)
        .join(Library, Library.id == AdvisoryImpact.library_id)
        .where(
            AdvisoryImpact.org_id == org_id,
            AdvisoryImpact.vuln_key == vuln_key,
            AdvisoryImpact.resolved_at.is_(None),
        )
    ).all()
    if not rows:
        return []
    assets = sorted({imp.asset_id for imp, _l in rows})
    comps: dict[tuple[str, str, str], ComponentRow] = {}
    for c in s.scalars(
        select(ComponentRow).where(
            ComponentRow.asset_id.in_(assets),
            ComponentRow.library_id.in_(sorted({lib.id for _i, lib in rows})),
            ComponentRow.current.is_(True),
        )
    ):
        comps.setdefault((c.asset_id, c.library_id, c.version), c)
    statements: dict[tuple[str, str, str], VexStatement] = {}
    for st in s.scalars(
        select(VexStatement)
        .where(VexStatement.org_id == org_id, VexStatement.vuln_key == vuln_key)
        .order_by(VexStatement.proposed_at)
    ):
        statements[(st.asset_id, st.library_id, st.version)] = st  # the latest wins
    usage: dict[str, tuple[GoUsage | None, str | None]] = {}
    malicious = _malicious(s, sorted({a for imp, _l in rows for a in imp.advisory_ids}))
    out = []
    for imp, lib in rows:
        if imp.asset_id not in usage:
            usage[imp.asset_id] = go_usage(s, imp.asset_id)
        g, usage_scan = usage[imp.asset_id]
        comp = comps.get((imp.asset_id, lib.id, imp.version))
        a = assess(
            s, lib=lib, version=imp.version, advisory_ids=imp.advisory_ids, component=comp,
            usage=g, certain=imp.certain, malicious=malicious,
        )  # fmt: skip
        scan = usage_scan if lib.ecosystem == "go" else (comp.scan_id if comp else None)
        out.append(
            Use(imp, lib, comp, a, statements.get((imp.asset_id, lib.id, imp.version)), scan)
        )
    return out


@dataclass
class Drafted:
    proposed: int = 0
    already: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    ids: list[str] = field(default_factory=list)


def draft(s: Session, org_id: str, vuln_key: str, *, actor: str) -> Drafted:
    out = Drafted()
    why: Counter[str] = Counter()
    for u in uses(s, org_id, vuln_key):
        st = u.statement
        if st is not None and (
            st.state in LIVE or (st.state == "rejected" and st.scan_id == u.scan_id)
        ):
            out.already += 1
            continue
        if not u.assessment.proposable:
            why[u.assessment.summary.split(":")[0].split(" (")[0][:80]] += 1
            continue
        row = VexStatement(
            org_id=org_id, asset_id=u.impact.asset_id, library_id=u.library.id,
            version=u.impact.version, vuln_key=vuln_key, status="not_affected",
            justification=JUSTIFICATION, impact_statement=u.assessment.summary,
            evidence=u.assessment.evidence(), state="proposed", scan_id=u.scan_id,
            proposed_by=actor, proposed_at=_now(),
        )  # fmt: skip
        s.add(row)
        s.flush()
        out.proposed += 1
        out.ids.append(row.id)
    out.skipped = dict(why)
    repo.append_audit_entry(  # commits, with the proposals
        s, actor=actor, action="vex.drafted", target=vuln_key, org_id=org_id,
        payload={"proposed": out.ids, "skipped": out.skipped},
    )  # fmt: skip
    return out


def get(s: Session, org_id: str, statement_id: str) -> VexStatement:
    st = s.get(VexStatement, statement_id)
    if st is None or st.org_id != org_id:
        raise VexError("VEX statement not found", 404)
    return st


def _person(actor: str) -> None:
    if actor == SHARED:
        raise VexError("deciding needs a personal API token: the shared token could be anyone", 403)


def confirm(
    s: Session, org_id: str, statement_id: str, *, actor: str, note: str | None = None
) -> VexStatement:
    st = get(s, org_id, statement_id)
    _person(actor)
    if st.state != "proposed":
        raise VexError(f"this statement is {st.state}, not proposed", 409)
    st.state, st.decided_by, st.decided_at = "confirmed", actor, _now()
    st.decision_note = (note or "").strip()[:2000] or None
    lib = s.get(Library, st.library_id)
    issues = issues_for(s, st.asset_id, lib, st.version, st.vuln_key) if lib else []
    triaged = []
    for issue in issues:
        if issue.triage_status == "not_a_risk":
            continue
        repo.triage_issue(
            s, issue.id, org_id=org_id, action="not_a_risk", actor=actor,
            reason=f"VEX: {st.impact_statement}"[:4000], justification=st.justification,
        )  # fmt: skip
        triaged.append(issue.id)
    repo.append_audit_entry(
        s, actor=actor, action="vex.confirmed", target=f"vex:{st.id}", org_id=org_id,
        payload={"vuln_key": st.vuln_key, "asset_id": st.asset_id, "version": st.version,
                 "justification": st.justification, "issues": triaged},
    )  # fmt: skip
    return st


def reject(
    s: Session, org_id: str, statement_id: str, *, actor: str, note: str | None = None
) -> VexStatement:
    st = get(s, org_id, statement_id)
    _person(actor)
    if st.state != "proposed":
        raise VexError(f"this statement is {st.state}, not proposed", 409)
    st.state, st.decided_by, st.decided_at = "rejected", actor, _now()
    st.decision_note = (note or "").strip()[:2000] or None
    repo.append_audit_entry(
        s, actor=actor, action="vex.rejected", target=f"vex:{st.id}", org_id=org_id,
        payload={"vuln_key": st.vuln_key, "asset_id": st.asset_id, "note": st.decision_note},
    )  # fmt: skip
    return st


def withdraw(
    s: Session, org_id: str, statement_id: str, *, actor: str, reason: str = "withdrawn"
) -> VexStatement:
    st = get(s, org_id, statement_id)
    if st.state != "confirmed":
        raise VexError(f"this statement is {st.state}, not confirmed", 409)
    st.state = "withdrawn"
    st.decision_note = reason[:2000]
    repo.append_audit_entry(
        s, actor=actor, action="vex.withdrawn", target=f"vex:{st.id}", org_id=org_id,
        payload={"vuln_key": st.vuln_key, "asset_id": st.asset_id, "reason": reason},
    )  # fmt: skip
    return st


def on_issue_reopened(s: Session, org_id: str, issue: IssueRow, *, actor: str) -> int:
    """A confirmed statement whose Issue a person reopened no longer stands."""
    n = 0
    for st in s.scalars(
        select(VexStatement).where(
            VexStatement.org_id == org_id,
            VexStatement.asset_id == issue.asset_id,
            VexStatement.state == "confirmed",
        )
    ):
        lib = s.get(Library, st.library_id)
        if lib is None or issue.fingerprint != issue_fingerprint(
            lib.ecosystem, lib.name, st.version, st.vuln_key
        ):
            continue
        withdraw(s, org_id, st.id, actor=actor, reason=f"its Issue {issue.id} was reopened")
        n += 1
    return n


def view(st: VexStatement, lib: Library | None = None) -> dict[str, Any]:
    return {
        "id": st.id, "asset_id": st.asset_id, "vuln_key": st.vuln_key,
        "library": lib.name if lib else None, "ecosystem": lib.ecosystem if lib else None,
        "version": st.version, "status": st.status, "justification": st.justification,
        "impact_statement": st.impact_statement, "evidence": st.evidence, "state": st.state,
        "proposed_by": st.proposed_by, "proposed_at": st.proposed_at,
        "decided_by": st.decided_by, "decided_at": st.decided_at, "note": st.decision_note,
    }  # fmt: skip


def annotate(s: Session, org_id: str, vuln_key: str, impact: dict[str, Any]) -> None:
    """Add each open use's VEX evidence and statement to an impact view (`view.impact`), and how
    many uses a draft would propose for."""
    by_use = {
        (u.impact.asset_id, u.library.purl, u.impact.version): u for u in uses(s, org_id, vuln_key)
    }
    draftable = 0
    for use in impact["uses"]:
        u = by_use.get((use["project_id"], use["purl"], use["version"]))
        if u is None:
            continue
        st = u.statement
        live = st is not None and (
            st.state in LIVE or (st.state == "rejected" and st.scan_id == u.scan_id)
        )
        can = u.assessment.proposable and not live
        draftable += can
        use["vex"] = {
            "draftable": can, "evidence": u.assessment.evidence() if u.assessment.kind else None,
            "summary": u.assessment.summary, "uses_code": u.assessment.reachable,
            "where": u.assessment.where, "statement": view(st, u.library) if st else None,
        }  # fmt: skip
    impact["summary_counts"]["vex_draftable"] = draftable
