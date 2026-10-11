"""The documents a rule's condition reads (`input.issue`, `input.project`, `input.event`).

Built in batches: one query each for the Issues, their latest occurrences and their tags, however
many Issues an event stream brings, and each project's document once. Every field comes from data
Bulwark already has; a field with no value is left out, never filled with a guess, so a condition
like `input.issue.reachable == false` never matches an Issue nobody has analysed.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.collab.people import handle_of
from core.persistence.models import ApiToken, Asset, IssueRow, Portfolio, Tag
from core.policy.input import issue_document


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def effective_band(issue: IssueRow) -> str | None:
    return issue.priority_override or issue.priority_band


class Builder:
    """Caches per-project documents and the organization's handles across one batch."""

    def __init__(self, s: Session, org_id: str, now: datetime | None = None) -> None:
        self.s, self.org_id, self.now = s, org_id, now or _now()
        self._projects: dict[str, dict[str, Any]] = {}
        self._assets: dict[str, Asset | None] = {}
        self._project_tags: dict[str, list[str]] = {}
        self._handles: dict[str, str] | None = None

    # --- people -----------------------------------------------------------------------------------

    def handles(self) -> dict[str, str]:
        """actor -> @handle, for every token of the organization (revoked ones too, so an Issue
        assigned to someone who has since left still says who)."""
        if self._handles is None:
            rows = self.s.execute(
                select(ApiToken.display_prefix, ApiToken.name).where(ApiToken.org_id == self.org_id)
            )
            self._handles = {f"token:{p}": handle_of(n) for p, n in rows}
        return self._handles

    # --- projects ---------------------------------------------------------------------------------

    def asset(self, asset_id: str) -> Asset | None:
        """Held for the batch: the session's identity map keeps rows only while something refers
        to them, so without this every candidate fetched its project again (2,200 queries in one
        500-event batch, a fifth of its time, in scripts/bench-rules.py)."""
        if asset_id not in self._assets:
            self._assets[asset_id] = self.s.get(Asset, asset_id)
        return self._assets[asset_id]

    def project(self, asset: Asset) -> dict[str, Any]:
        if asset.id in self._projects:
            return self._projects[asset.id]
        from core.priority.service import current as current_priority

        portfolio = self.s.get(Portfolio, asset.portfolio_id) if asset.portfolio_id else None
        own = list(self.s.scalars(select(Tag.name).where(
            Tag.target_type == "project", Tag.target_id == asset.id)))  # fmt: skip
        inherited = (
            list(self.s.scalars(select(Tag.name).where(
                Tag.target_type == "portfolio", Tag.target_id == portfolio.id)))  # fmt: skip
            if portfolio
            else []
        )
        tags = sorted({*own, *inherited})
        self._project_tags[asset.id] = tags
        doc: dict[str, Any] = {"id": asset.id, "name": asset.label, "tags": tags}
        if portfolio is not None:
            doc["portfolio"] = portfolio.name
        policy = current_priority(self.s, asset.id)
        for key, value in ((policy.context or {}) if policy else {}).items():
            if key in ("internet_facing", "data_sensitivity", "criticality") and value is not None:
                doc[key] = value
        self._projects[asset.id] = doc
        return doc

    # --- issues -----------------------------------------------------------------------------------

    def issues(self, issue_ids: Iterable[str]) -> dict[str, tuple[IssueRow, dict[str, Any]]]:
        """Issue id -> (row, `input.issue`). Ids of another organization, or gone, are absent."""
        from core.priority.service import latest_occurrences
        from core.sla.service import policy_for, status_of

        ids = list(dict.fromkeys(issue_ids))
        if not ids:
            return {}
        rows = list(
            self.s.scalars(
                select(IssueRow)
                .join(Asset, Asset.id == IssueRow.asset_id)
                .where(IssueRow.id.in_(ids), Asset.org_id == self.org_id)
            )
        )
        occurrences = latest_occurrences(self.s, [r.id for r in rows])
        own_tags: dict[str, set[str]] = {}
        for target_id, name in self.s.execute(
            select(Tag.target_id, Tag.name).where(
                Tag.target_type == "issue", Tag.target_id.in_([r.id for r in rows])
            )
        ):
            own_tags.setdefault(target_id, set()).add(name)
        policies: dict[str, Any] = {}
        out: dict[str, tuple[IssueRow, dict[str, Any]]] = {}
        for row in rows:
            asset = self.asset(row.asset_id)
            assert asset is not None
            self.project(asset)
            if row.asset_id not in policies:
                policies[row.asset_id] = policy_for(self.s, row.asset_id)
            finding = occurrences.get(row.id) or {}
            doc = issue_document(finding) if finding else {}
            doc.pop("id", None)
            doc.pop("fingerprint", None)
            evidence = finding.get("evidence") or {}
            reported_by = evidence.get("reported_by") or []
            rule_ids = evidence.get("rule_ids") or {}
            doc.update({
                "id": row.id,
                "title": row.title,
                "severity": (row.severity or "").upper(),
                "category": row.category,
                "state": row.state,
                "triage_status": row.triage_status,
                "path": row.path,
                "source": row.source,
                "tags": sorted({*own_tags.get(row.id, set()), *self._project_tags[row.asset_id]}),
                "age_days": max(0, (self.now - _aware(row.first_seen_at)).days),
                "first_seen_at": _aware(row.first_seen_at).isoformat(),
            })  # fmt: skip
            if reported_by:
                doc["tool"] = reported_by[0]
            first_rules: list[str] = next((v for v in rule_ids.values() if v), [])
            if first_rules:
                doc["rule_id"] = first_rules[0]
            band = effective_band(row)
            if band:
                doc["priority_band"] = band
            if row.priority_score is not None:
                doc["priority_score"] = row.priority_score
            if row.assignee:
                doc["assignee"] = self.handles().get(row.assignee, row.assignee)
            if row.retest_status:
                doc["retest_status"] = row.retest_status
            if doc.get("risk_score") is None:
                doc.pop("risk_score", None)
            if not doc.get("entrypoint"):
                doc.pop("entrypoint", None)
            sla = status_of(policies[row.asset_id], row, self.now)
            doc["sla"] = {"state": sla.state}
            if sla.due_at is not None:
                doc["sla"]["due_at"] = sla.due_at.isoformat()
            out[row.id] = (row, doc)
        return out


def event_doc(event_type: str, payload: dict[str, Any], at: datetime | None) -> dict[str, Any]:
    doc: dict[str, Any] = {"type": event_type}
    if at is not None:
        doc["at"] = _aware(at).isoformat()
    for key in ("source", "by", "decision", "reason", "due_at"):
        if payload.get(key) is not None:
            doc[key] = payload[key]
    return doc
