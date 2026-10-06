"""Issues from an advisory, in one click (plan §46.2: "one-click creation of Issues grouped by
advisory"; §55.5).

Creating Issues for a vulnerability marks it adopted for the organization. Each affected project
then holds an "Advisories" Test whose content is, at every moment, one finding per adopted
vulnerability per affected library version in its current SBOM -- imported through the ordinary
import path (ADR-0040), so the Issues behave like any other: deduplicated with osv-scanner's
findings for the same package and CVE, reopened, and closed when a later SBOM no longer has an
affected version (a scan's evidence, never a ticket's). Whenever matching changes an adopted
vulnerability's impacts in a project, that project's Test is re-imported.

Within each project the Issues of one vulnerability form an issue group named after it, so a
project with ticket settings gets one ticket for it; the project's owner is assigned.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.advisories.view import representative, severity_of
from core.collab import assign
from core.imports import service as imports
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Taxonomy,
)
from core.persistence import repo
from core.persistence.models import (
    Advisory,
    AdvisoryImpact,
    AdvisoryState,
    Asset,
    ComponentRow,
    FindingRow,
    KevEntry,
    Library,
)
from core.tickets import groups
from core.tickets import sync as tickets

log = logging.getLogger(__name__)
TEST_NAME = "Advisories"
PARSER = "bulwark-advisories"
TOOL = "bulwark-advisories"


@dataclass
class Created:
    projects: int = 0
    issues: int = 0
    tickets: int = 0
    ticket_errors: list[str] = field(default_factory=list)
    issue_ids: dict[str, list[str]] = field(default_factory=dict)  # project -> Issue ids


def _now() -> datetime:
    return datetime.now(timezone.utc)


def adopted(s: Session, org_id: str) -> set[str]:
    return set(
        s.scalars(
            select(AdvisoryState.vuln_key).where(
                AdvisoryState.org_id == org_id, AdvisoryState.state == "issues"
            )
        )
    )


def _findings(s: Session, org_id: str, asset_id: str, vulns: set[str]) -> list[Finding]:
    if not vulns:
        return []
    rows = s.execute(
        select(AdvisoryImpact, Library)
        .join(Library, Library.id == AdvisoryImpact.library_id)
        .where(
            AdvisoryImpact.org_id == org_id,
            AdvisoryImpact.asset_id == asset_id,
            AdvisoryImpact.vuln_key.in_(sorted(vulns)),
            AdvisoryImpact.resolved_at.is_(None),
            AdvisoryImpact.certain.is_(True),
        )
    ).all()
    out = []
    for impact, lib in rows:
        records = list(s.scalars(select(Advisory).where(Advisory.id.in_(impact.advisory_ids))))
        if not records:
            continue
        rep = representative(records)
        comp = s.scalars(
            select(ComponentRow).where(
                ComponentRow.asset_id == asset_id,
                ComponentRow.library_id == lib.id,
                ComponentRow.version == impact.version,
                ComponentRow.current.is_(True),
            )
        ).first()
        path = (comp.paths[0] if comp and comp.paths else "") or "sbom"
        aliases = sorted({a for r in records for a in (r.id, *r.aliases)})
        cves = tuple(a for a in aliases if a.startswith("CVE-"))
        kev = (
            bool(cves) and s.scalar(select(KevEntry.cve).where(KevEntry.cve.in_(cves))) is not None
        )
        sev, score = severity_of(records)
        malicious = any(a.startswith("MAL-") for a in aliases)
        text = f"{lib.name}@{impact.version}"
        title = (
            f"Malicious package: {lib.name} {impact.version} ({impact.vuln_key})"
            if malicious
            else f"{lib.name} {impact.version}: {rep.summary or impact.vuln_key}"
        )
        fix = (
            f"Remove {lib.name} {impact.version}; it is a reported malicious package."
            if malicious
            else (
                f"Upgrade {lib.name} to {impact.fixed_version} or later."
                if impact.fixed_version
                else f"No fixed version of {lib.name} is listed; consider mitigations."
            )
        )
        f = Finding(
            id=f"{TOOL}:{impact.vuln_key}:{path}:{text}",
            title=title[:300],
            description=(rep.details or rep.summary or impact.vuln_key)[:4000],
            location=Location(path, 1, 1, text, Location.hash_snippet(text)),
            taxonomy=Taxonomy(
                Category.SCA,
                cwe=tuple(sorted({c for r in records for c in r.cwe}))[:10],
                cve=cves,
                aliases=tuple(aliases),
            ),
            scoring=Scoring(
                native_severity={TOOL: rep.db_severity or (f"{score}" if score else "")},
                normalized_severity=sev,
                cvss_v3_1=score,
                in_cisa_kev=kev,
                reachable=comp.reachable if comp else None,
                confidence=1.0 if malicious else 0.9,
            ),
            evidence=Evidence(reported_by=[TOOL], rule_ids={TOOL: [impact.vuln_key]}),
            remediation=Remediation(summary=fix, references=[f"https://osv.dev/{rep.id}"]),
            package=Package(lib.name, impact.version, lib.ecosystem),
        )
        out.append(f)
    return sorted(out, key=lambda f: f.id)


def sync_asset(s: Session, org_id: str, asset_id: str, *, actor: str = TOOL) -> dict[str, str]:
    """Re-import the project's Advisories Test with its current findings. Returns each finding id's
    Issue id."""
    findings = _findings(s, org_id, asset_id, adopted(s, org_id))
    engagement = repo.get_or_create_import_engagement(s, asset_id=asset_id, org_id=org_id)
    test = repo.get_or_create_engagement_test(
        s, org_id=org_id, engagement_id=engagement.id, name=TEST_NAME, parser=PARSER
    )
    digest = hashlib.sha256(
        json.dumps([[f.id, f.title, f.remediation.summary] for f in findings]).encode()
    ).hexdigest()
    result = imports.apply_import(
        s, org_id=org_id, test_id=test.id, findings=findings, parser=PARSER, file_digest=digest,
        file_name="advisory matches", close_missing=True, scope="test", created_by=actor,
    )  # fmt: skip
    scan_id = result.record.scan_id
    if scan_id is None:
        return {}
    return {
        fid: iid
        for fid, iid in s.execute(
            select(FindingRow.finding_id, FindingRow.issue_id).where(FindingRow.scan_id == scan_id)
        )
        if iid
    }


def create(
    s: Session, org_id: str, vuln_key: str, *, actor: str, project_ids: list[str] | None = None
) -> Created:
    """Adopt the vulnerability and create (or bring up to date) its Issues in every affected
    project, or the ones named: grouped by vulnerability, assigned to each project's owner, and
    filed where the project has ticket settings."""
    state = s.scalars(
        select(AdvisoryState).where(
            AdvisoryState.org_id == org_id, AdvisoryState.vuln_key == vuln_key
        )
    ).first()
    if state is None:
        raise LookupError(vuln_key)
    state.state, state.updated_at, state.updated_by = "issues", _now(), actor
    s.commit()
    assets = sorted(
        set(
            s.scalars(
                select(AdvisoryImpact.asset_id).where(
                    AdvisoryImpact.org_id == org_id,
                    AdvisoryImpact.vuln_key == vuln_key,
                    AdvisoryImpact.resolved_at.is_(None),
                    AdvisoryImpact.certain.is_(True),
                )
            )
        )
    )
    if project_ids is not None:
        assets = [a for a in assets if a in set(project_ids)]
    out = Created()
    prefix = f"{TOOL}:{vuln_key}:"
    for asset_id in assets:
        issue_of = sync_asset(s, org_id, asset_id, actor=actor)
        ids = sorted({iid for fid, iid in issue_of.items() if fid.startswith(prefix)})
        if not ids:
            continue
        out.projects += 1
        out.issues += len(ids)
        out.issue_ids[asset_id] = ids
        asset = s.get(Asset, asset_id)
        group = groups.get_or_create(s, org_id, asset_id, vuln_key, actor=actor)
        issues = [i for i in (repo.get_issue(s, iid) for iid in ids) if i is not None]
        for issue in issues:
            if issue.group_id != group.id:
                groups.set_group(s, org_id, issue, group, actor=actor)
            if asset is not None and asset.owner and not issue.assignee:
                try:
                    handle = _handle_of(s, org_id, asset.owner)
                    if handle:
                        assign.assign(s, issue, handle, actor=actor)
                except assign.AssignError:
                    log.info("advisories: the owner of %s is no longer a person", asset_id)
        if issues:
            try:
                tickets.file(s, org_id, issues[0], actor=actor)
                out.tickets += 1
            except tickets.TicketError as exc:
                if "no ticket settings" not in str(exc):
                    out.ticket_errors.append(f"{asset.label if asset else asset_id}: {exc}")
            except Exception as exc:  # noqa: BLE001 - one project's tracker must not stop the rest
                s.rollback()
                out.ticket_errors.append(f"{asset.label if asset else asset_id}: {exc}")
    s.commit()
    return out


def _handle_of(s: Session, org_id: str, actor: str) -> str | None:
    from core.collab.people import people

    return next((p.handle for p in people(s, org_id) if p.actor == actor), None)


def sync_changed(s: Session, org_id: str, changed: Mapping[str, set[str]]) -> int:
    """After matching: re-import the Advisories Test of each project whose impacts changed for an
    adopted vulnerability. Returns how many projects."""
    wanted = adopted(s, org_id)
    assets: dict[str, None] = {}
    for vuln, touched in changed.items():
        if vuln in wanted:
            assets.update(dict.fromkeys(touched))
    for asset_id in assets:
        try:
            sync_asset(s, org_id, asset_id)
        except Exception:  # noqa: BLE001 - one project must not stop the rest
            s.rollback()
            log.exception("advisories: could not bring %s's Issues up to date", asset_id)
    return len(assets)
