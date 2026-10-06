"""A project's VEX, as OpenVEX v0.2.0 or CycloneDX 1.6 (plan §46.3).

One statement per vulnerability at each library version in the project's current SBOM, from what
the organization has decided, in this order:

1. a confirmed VEX statement: `not_affected`, its justification, and its evidence in the impact
   statement -- unless the evidence no longer holds today (a later scan found the code using it),
   when it is exported as `under_investigation` and says so;
2. the matching Issue marked not a risk: `not_affected`, with its justification if it has one and
   its reason as the impact statement;
3. otherwise `affected` -- with the fix as the action statement -- or `under_investigation` when
   the version could not be compared with the advisory.

Only vulnerabilities the advisory engine knows (PyPI, npm, Go and Maven, Week 68) are included.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.advisories.view import representative, severity_of
from core.export.sarif import _version
from core.persistence.models import Advisory, AdvisoryImpact, Asset, Organization
from core.vex import vocab
from core.vex.service import issues_for, uses

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_NS = uuid.UUID("6f1c8f43-5b8e-4c47-9f0e-2a1d6b9b0c69")


def _iso(dt: datetime | None) -> str:
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _version_purl(base: str, ecosystem: str, version: str) -> str:
    return f"{base}@{('v' + version.removeprefix('v')) if ecosystem == 'go' else version}"


def product_id(asset: Asset) -> str:
    """The repository URL for a git project, else a stable `urn:uuid:` for it."""
    if asset.source_type == "git" and asset.key.startswith("https://"):
        return asset.key
    return f"urn:uuid:{asset.id}"


def _evidence_text(ev: dict[str, Any], decided_by: str | None, decided_at: datetime | None) -> str:
    parts = [ev.get("summary", "").strip()]
    if ev.get("caveats"):
        parts.append("Limits: " + " ".join(ev["caveats"]))
    if decided_by:
        parts.append(f"Confirmed by {decided_by} on {_iso(decided_at)[:10]}.")
    return " ".join(p for p in parts if p)


def statements(s: Session, org_id: str, asset: Asset) -> list[dict[str, Any]]:
    """The neutral form both formats are written from."""
    vulns = sorted(
        set(
            s.scalars(
                select(AdvisoryImpact.vuln_key).where(
                    AdvisoryImpact.org_id == org_id,
                    AdvisoryImpact.asset_id == asset.id,
                    AdvisoryImpact.resolved_at.is_(None),
                )
            )
        )
    )
    out: list[dict[str, Any]] = []
    for vuln_key in vulns:
        mine = [u for u in uses(s, org_id, vuln_key) if u.impact.asset_id == asset.id]
        if not mine:
            continue
        ids = sorted({a for u in mine for a in u.impact.advisory_ids})
        records = list(s.scalars(select(Advisory).where(Advisory.id.in_(ids))))
        rep = representative(records) if records else None
        aliases = sorted({a for r in records for a in (r.id, *r.aliases)} - {vuln_key})
        sev, cvss = severity_of(records) if records else (None, None)
        severity = sev.value.lower() if sev is not None else "unknown"
        for u in sorted(mine, key=lambda u: (u.library.name, u.impact.version)):
            st = (
                u.statement
                if u.statement is not None and u.statement.state == "confirmed"
                else None
            )
            item: dict[str, Any] = {
                "vuln_key": vuln_key, "aliases": aliases,
                "summary": (rep.summary if rep else "") or vuln_key,
                "source_id": rep.id if rep else vuln_key, "severity": severity, "cvss": cvss,
                "library": u.library.name, "ecosystem": u.library.ecosystem,
                "purl": _version_purl(u.library.purl, u.library.ecosystem, u.impact.version),
                "version": u.impact.version, "fixed_version": u.impact.fixed_version,
                "justification": None, "impact_statement": None, "action_statement": None,
                "evidence": None, "timestamp": None, "basis": "",
            }  # fmt: skip
            issues = issues_for(s, asset.id, u.library, u.impact.version, vuln_key)
            dismissed = next((i for i in issues if i.triage_status == "not_a_risk"), None)
            if st is not None and u.assessment.reachable is not True:
                item.update(
                    status="not_affected", justification=st.justification, basis="vex",
                    impact_statement=_evidence_text(st.evidence, st.decided_by, st.decided_at),
                    evidence=st.evidence, timestamp=st.decided_at,
                )  # fmt: skip
            elif st is not None:
                item.update(
                    status="under_investigation", basis="vex-stale", timestamp=st.decided_at,
                    impact_statement=(
                        "A confirmed not-affected statement no longer matches the latest scan: "
                        f"{u.assessment.summary}"
                    ),
                )  # fmt: skip
            elif dismissed is not None:
                item.update(
                    status="not_affected", justification=dismissed.triage_justification,
                    impact_statement=dismissed.triage_reason or "Marked not a risk.",
                    basis="issue", timestamp=dismissed.triaged_at,
                )  # fmt: skip
            elif not u.impact.certain:
                item.update(
                    status="under_investigation",
                    basis="uncertain",
                    impact_statement="The version could not be compared with the advisory.",
                )
            else:
                fix = u.impact.fixed_version
                item.update(
                    status="affected", basis="match",
                    action_statement=(
                        f"Upgrade {u.library.name} to {fix} or later." if fix
                        else "No fixed version is listed; apply a mitigation or remove the package."
                    ),
                )  # fmt: skip
            out.append(item)
    return out


def _doc_id(asset: Asset, items: list[dict[str, Any]]) -> uuid.UUID:
    digest = hashlib.sha256(
        json.dumps([asset.id, [[i["vuln_key"], i["purl"], i["status"]] for i in items]],
                   default=str).encode()  # fmt: skip
    ).hexdigest()
    return uuid.uuid5(_NS, digest)


def openvex(
    s: Session, org_id: str, asset: Asset, *, now: datetime | None = None
) -> dict[str, Any]:
    items = statements(s, org_id, asset)
    org = s.get(Organization, org_id)
    product = product_id(asset)
    stmts = []
    for i in items:
        st: dict[str, Any] = {
            "vulnerability": {"name": i["vuln_key"], "description": i["summary"][:500]},
            "products": [{"@id": product, "subcomponents": [{"@id": i["purl"]}]}],
            "status": i["status"],
        }
        if i["aliases"]:
            st["vulnerability"]["aliases"] = i["aliases"]
        if i["timestamp"]:
            st["timestamp"] = _iso(i["timestamp"])
        if i["status"] == "not_affected":
            if i["justification"]:
                st["justification"] = i["justification"]
            st["impact_statement"] = i["impact_statement"]  # always: the evidence, or the reason
        elif i["status"] == "affected":
            st["action_statement"] = i["action_statement"]
        elif i["impact_statement"]:
            st["status_notes"] = i["impact_statement"]
        stmts.append(st)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{_doc_id(asset, items)}",
        "author": (org.name if org else "") or "Bulwark",
        "role": "Document Creator",
        "timestamp": _iso(now),
        "version": 1,
        "tooling": f"Bulwark {_version()}",
        "statements": stmts,
    }


def _cdx_component(i: dict[str, Any]) -> dict[str, Any]:
    group, _, name = (
        i["library"].rpartition(":") if i["ecosystem"] == "maven" else ("", "", i["library"])
    )
    comp = {"type": "library", "bom-ref": i["purl"], "name": name, "version": i["version"],
            "purl": i["purl"]}  # fmt: skip
    if group:
        comp["group"] = group
    return comp


def cyclonedx(
    s: Session, org_id: str, asset: Asset, *, now: datetime | None = None
) -> dict[str, Any]:
    items = statements(s, org_id, asset)
    components: dict[str, dict[str, Any]] = {}
    vulns = []
    for i in items:
        components.setdefault(i["purl"], _cdx_component(i))
        analysis: dict[str, Any] = {"state": vocab.CDX_STATE[i["status"]]}
        if i["status"] == "not_affected" and i["justification"]:
            analysis["justification"] = vocab.CDX_JUSTIFICATION[i["justification"]]
        if i["status"] == "affected" and i["fixed_version"]:
            analysis["response"] = ["update"]
        detail = i["impact_statement"] or i["action_statement"]
        if detail:
            analysis["detail"] = detail
        if i["timestamp"]:
            analysis["lastUpdated"] = _iso(i["timestamp"])
        status = {"not_affected": "unaffected", "affected": "affected",
                  "fixed": "unaffected"}.get(i["status"], "unknown")  # fmt: skip
        v: dict[str, Any] = {
            "id": i["vuln_key"],
            "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{i['source_id']}"},
            "description": i["summary"][:2000],
            "analysis": analysis,
            "affects": [
                {"ref": i["purl"], "versions": [{"version": i["version"], "status": status}]}
            ],
        }
        if i["aliases"]:
            v["references"] = [
                {"id": a, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a}"}}
                for a in i["aliases"]
            ]
        if i["cvss"] is not None:
            v["ratings"] = [{"score": i["cvss"], "severity": i["severity"], "method": "other"}]
        props = [{"name": "bulwark:vex:status", "value": i["status"]},
                 {"name": "bulwark:vex:basis", "value": i["basis"]}]  # fmt: skip
        if i["justification"]:
            props.append({"name": "bulwark:openvex:justification", "value": i["justification"]})
        if i["evidence"]:
            props.append({"name": "bulwark:evidence:kind", "value": i["evidence"].get("kind", "")})
            props.append(
                {
                    "name": "bulwark:evidence",
                    "value": json.dumps(i["evidence"], sort_keys=True)[:8000],
                }
            )
        v["properties"] = props
        vulns.append(v)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{_doc_id(asset, items)}",
        "version": 1,
        "metadata": {
            "timestamp": _iso(now),
            "tools": {
                "components": [{"type": "application", "name": "Bulwark", "version": _version()}]
            },
            "component": {"type": "application", "bom-ref": product_id(asset), "name": asset.label},
        },
        "components": list(components.values()),
        "vulnerabilities": vulns,
    }
