"""Recording a manual finding (plan §43.2, ADR-0044).

A manual finding is one more ingest source (`manual`, ADR-0040): it is built into a canonical
Finding and applied through `core.imports.service.apply_import` into a Test (by default "Manual
review" in the project's standing import engagement), so it becomes an ordinary Issue -- with SLA,
triage, tickets and deduplication like any other -- and the import that created it can be undone.
`close_missing` is always off: recording one finding never says anything about the others.

What the canonical Finding has no field for (the CVSS 4.0 vector, the steps as written, the
location kind, the automated finding it matched) is kept in a `ManualFinding` row beside the Issue.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.imports import service as imports
from core.imports.prepare import prepare
from core.manual import cvss4
from core.manual import cwe as cwe_catalogue
from core.manual.routes import find_route, latest_routes, related_automated_finding
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)
from core.persistence import repo
from core.persistence.models import Engagement, FindingRow, ManualFinding

SOURCE = "manual"
DEFAULT_TEST = "Manual review"
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
MAX_TEXT = 20_000
MAX_REFERENCES = 20


class ManualFindingError(ValueError):
    """The finding cannot be recorded as given; the message names the field."""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name


@dataclass
class ManualFindingIn:
    title: str
    cwe: str | None = None
    cvss_vector: str | None = None
    severity: str | None = None  # only when no vector is given
    location_kind: str = "route"  # route | file
    method: str | None = None
    route: str | None = None
    host: str | None = None
    path: str | None = None
    line: int | None = None
    steps: str = ""
    impact: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    engagement_id: str | None = None
    test_name: str | None = None


@dataclass(frozen=True)
class Recorded:
    manual: ManualFinding
    issue_id: str
    import_id: str
    created: bool  # False: the same finding was already the Test's latest record


def validate(body: ManualFindingIn) -> tuple[ManualFindingIn, cvss4.Cvss4Score | None]:
    """Every field checked, each error naming its field (the form shows it next to that field)."""
    title = " ".join((body.title or "").split())
    if not title:
        raise ManualFindingError("title", "Give the finding a title.")
    if len(title) > 300:
        raise ManualFindingError("title", "The title is at most 300 characters.")
    cwe = None
    if body.cwe and body.cwe.strip():
        cwe = cwe_catalogue.normalize(body.cwe)
        if cwe is None:
            raise ManualFindingError("cwe", "A CWE is a number, like CWE-89.")
    score = None
    if body.cvss_vector and body.cvss_vector.strip():
        try:
            score = cvss4.score(body.cvss_vector)
        except cvss4.CvssError as exc:
            raise ManualFindingError(
                "cvss_vector", f"Not a complete CVSS 4.0 vector: {exc}"
            ) from None
    elif not body.severity or body.severity.upper() not in Severity.__members__:
        raise ManualFindingError(
            "cvss_vector", "Score the finding with CVSS 4.0, or choose a severity."
        )
    kind = body.location_kind
    method = (body.method or "").strip().upper() or None
    route = (body.route or "").strip() or None
    path = (body.path or "").strip() or None
    if kind == "route":
        if not route or not route.startswith("/") or len(route) > 500:
            raise ManualFindingError("route", "Pick a route, or type one that starts with '/'.")
        if method is not None and method not in METHODS:
            raise ManualFindingError("method", f"The method is one of {', '.join(METHODS)}.")
    elif kind == "file":
        if not path or len(path) > 1000 or path.startswith("/") or ".." in path.split("/"):
            raise ManualFindingError(
                "path", "Give the file's path within the project, like app/views.py."
            )
        if body.line is not None and not 1 <= body.line <= 10_000_000:
            raise ManualFindingError("line", "The line is a positive number.")
    else:
        raise ManualFindingError("location_kind", "Say where it is: a route, or a file.")
    for name in ("steps", "impact", "recommendation"):
        if len(getattr(body, name) or "") > MAX_TEXT:
            raise ManualFindingError(name, f"This is at most {MAX_TEXT} characters.")
    refs = [r.strip() for r in body.references or [] if r and r.strip()]
    if len(refs) > MAX_REFERENCES or any(not r.startswith(("https://", "http://")) or len(r) > 2000
                                         for r in refs):  # fmt: skip
        raise ManualFindingError(
            "references", "References are web links (https://...), at most 20."
        )
    clean = replace(
        body, title=title, cwe=cwe, method=method, route=route, path=path, references=refs,
        severity=(body.severity or "").upper() or None,
        host=(body.host or "").strip() or None,
    )  # fmt: skip
    return clean, score


def _description(b: ManualFindingIn) -> str:
    parts = []
    if b.steps.strip():
        parts.append("Steps to reproduce\n" + b.steps.strip())
    if b.impact.strip():
        parts.append("Impact\n" + b.impact.strip())
    return "\n\n".join(parts) or b.title


def build_finding(
    b: ManualFindingIn, score: cvss4.Cvss4Score | None, handler: tuple[str, int] | None
) -> Finding:
    """The canonical Finding for a validated manual finding. Its rule id is derived from what it
    says and where, so recording the same finding twice is one Issue, and two different findings
    on one handler are two."""
    severity = score.severity if score else Severity(b.severity or "INFO")
    where = (
        f"{b.method or ''} {b.route}" if b.location_kind == "route" else f"{b.path}:{b.line or 1}"
    )
    rule = (
        "manual-" + hashlib.sha256(f"{b.title.lower()}|{where}|{b.cwe}".encode()).hexdigest()[:12]
    )
    native = {SOURCE: f"CVSS 4.0 {score.score}" if score else severity.value}
    if b.location_kind == "route":
        path, line = handler if handler else ("", 0)
        location = Location(path, line, line, route=b.route or "/", host=b.host or "")
        category = Category.DAST
    else:
        location = Location(b.path or "", b.line or 1, b.line or 1)
        category = Category.SAST
    return Finding(
        id=f"{SOURCE}:{rule}",
        title=b.title,
        description=_description(b),
        location=location,
        taxonomy=Taxonomy(category, cwe=(b.cwe,) if b.cwe else ()),
        scoring=Scoring(native_severity=native, normalized_severity=severity, confidence=0.9),
        evidence=Evidence(reported_by=[SOURCE], rule_ids={SOURCE: [rule]}),
        remediation=Remediation(summary=b.recommendation.strip(), references=list(b.references)),
    )


def _test_for(s: Session, org_id: str, asset_id: str, b: ManualFindingIn) -> str:
    if b.engagement_id:
        eng = repo.get_engagement(s, b.engagement_id, org_id)
        if eng is None or eng.asset_id != asset_id:
            raise ManualFindingError("engagement_id", "That engagement is not in this project.")
    else:
        eng = repo.get_or_create_import_engagement(s, asset_id=asset_id, org_id=org_id)
    name = " ".join((b.test_name or DEFAULT_TEST).split())[:200] or DEFAULT_TEST
    return repo.get_or_create_engagement_test(
        s, org_id=org_id, engagement_id=eng.id, name=name, parser=SOURCE
    ).id


def record(
    s: Session, *, org_id: str, asset_id: str, body: ManualFindingIn, created_by: str | None
) -> Recorded:
    b, score = validate(body)
    test_id = _test_for(s, org_id, asset_id, b)

    source = latest_routes(s, asset_id, org_id)
    handler = None
    if b.location_kind == "route":
        picked = find_route(source.routes, b.method or "", b.route or "")
        handler = (picked.path, picked.line) if picked else None
    finding = build_finding(b, score, handler)
    related = related_automated_finding(
        s, asset_id=asset_id, scan_id=source.scan_id, manual=finding, handlers=source.routes
    )
    findings = prepare([finding])
    if related is not None and related.finding.taint_path:
        # After `prepare`: correlation rebuilds each finding and does not carry a taint path (a
        # scan attaches its own afterwards, in `finalize`), so one copied in earlier would be lost.
        findings = [replace(findings[0], taint_path=related.finding.taint_path)]
    canonical = json.dumps([f.to_dict() for f in findings], sort_keys=True).encode()
    result = imports.apply_import(
        s,
        org_id=org_id,
        test_id=test_id,
        findings=findings,
        parser=SOURCE,
        file_digest=hashlib.sha256(canonical).hexdigest(),
        file_name=f"Manual: {b.title}"[:300],
        size_bytes=0,
        close_missing=False,  # one finding says nothing about any other
        created_by=created_by,
    )
    record_row = result.record
    if not result.created:
        existing = s.scalars(
            select(ManualFinding).where(
                ManualFinding.import_id == record_row.id, ManualFinding.org_id == org_id
            )
        ).first()
        if existing is not None:
            return Recorded(existing, existing.issue_id, record_row.id, created=False)
    issue_id = s.scalar(
        select(FindingRow.issue_id).where(FindingRow.scan_id == record_row.scan_id).limit(1)
    )
    if issue_id is None:  # pragma: no cover - apply_import always stores the finding it was given
        raise RuntimeError("the manual finding was imported but has no Issue")
    row = ManualFinding(
        org_id=org_id,
        asset_id=asset_id,
        test_id=test_id,
        issue_id=issue_id,
        import_id=record_row.id,
        title=b.title,
        cwe=b.cwe,
        severity=findings[0].scoring.normalized_severity.value,
        cvss_vector=score.vector if score else None,
        cvss_score=score.score if score else None,
        location_kind=b.location_kind,
        method=b.method,
        route=b.route,
        host=b.host,
        path=handler[0] if handler else b.path,
        line=handler[1] if handler else b.line,
        steps=b.steps.strip(),
        impact=b.impact.strip(),
        recommendation=b.recommendation.strip(),
        references=list(b.references),
        related_issue_id=related.issue_id if related else None,
        related_source=related.source if related else None,
        created_by=created_by,
    )
    s.add(row)
    s.commit()
    return Recorded(row, issue_id, record_row.id, created=True)


def get(s: Session, manual_id: str, org_id: str) -> ManualFinding | None:
    return s.scalars(
        select(ManualFinding).where(ManualFinding.id == manual_id, ManualFinding.org_id == org_id)
    ).one_or_none()


def for_issue(s: Session, issue_id: str, org_id: str) -> list[ManualFinding]:
    return list(
        s.scalars(
            select(ManualFinding)
            .where(ManualFinding.issue_id == issue_id, ManualFinding.org_id == org_id)
            .order_by(ManualFinding.created_at)
        )
    )


def for_project(s: Session, asset_id: str, org_id: str) -> list[ManualFinding]:
    return list(
        s.scalars(
            select(ManualFinding)
            .where(ManualFinding.asset_id == asset_id, ManualFinding.org_id == org_id)
            .order_by(ManualFinding.created_at.desc())
        )
    )


def engagement_of(s: Session, row: ManualFinding) -> Engagement | None:
    test = repo.get_engagement_test(s, row.test_id, row.org_id)
    return repo.get_engagement(s, test.engagement_id, row.org_id) if test else None


__all__ = [
    "DEFAULT_TEST",
    "ManualFindingError",
    "ManualFindingIn",
    "Recorded",
    "build_finding",
    "for_issue",
    "for_project",
    "get",
    "record",
    "validate",
]
