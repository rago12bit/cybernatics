"""Compliance mappings as versioned data (plan §47).

Each framework is a file in `frameworks/` that cites its source, its version and the terms it is
used under, and maps each control to the kinds of evidence Bulwark holds for it (`EVIDENCE`).
OWASP's Top 10 and ASVS are read from the data Bulwark already ships (`core/taxonomy`,
`core/engagements/checklists`), so their mapped CWEs are OWASP's own. The PCI DSS, ISO 27001 and
SOC 2 files give requirement numbers and Bulwark's short paraphrases only: those standards are
copyrighted and their text is not reproduced.

A mapping shows where evidence supports a control. It is not a certification, an audit opinion or
a statement of compliance, and nothing in Bulwark says it is (`DISCLAIMER`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from core.engagements import checklists

_DIR = Path(__file__).parent / "frameworks"

DISCLAIMER = (
    "This shows where evidence held in Bulwark supports each control. It is not a certification, "
    "an audit opinion or a statement of compliance."
)

#: What each kind of evidence is, as the evidence pack and the docs describe it.
EVIDENCE = {
    "scan_coverage": "Scans of each project in the period, by tool",
    "dast": "Web (DAST) scans of each web target in the period",
    "sla_adherence": "Issues whose SLA deadline fell in the period: met, missed or still open",
    "risk_acceptances": "Risk acceptances, each with its requester, approver and expiry",
    "open_issues": "Open Issues by priority and severity",
    "issues_by_cwe": "Open Issues of the control's weaknesses (CWEs)",
    "audit_log": "The tamper-evident audit-log extract, its hash-chain check and Rekor checkpoints",
    "component_inventory": "Libraries and versions in each project's current SBOM",
    "advisory_monitoring": "Advisory sources monitored; vulnerabilities found affecting projects",
    "vex": "VEX statements: vulnerabilities shown not to affect a project, with evidence",
    "engagements": "Penetration tests and assessments in the period",
    "policies": "SLA and priority policies in force, and the policy gate",
}


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    evidence: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    group: str = ""
    level: int | None = None
    note: str = ""


@dataclass(frozen=True)
class Framework:
    id: str
    name: str
    framework_version: str
    source: dict[str, str]
    mapping_version: int
    mapping_date: str
    controls: tuple[Control, ...] = field(default_factory=tuple)

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "framework_version": self.framework_version,
                "source": self.source, "mapping_version": self.mapping_version,
                "mapping_date": self.mapping_date, "controls": len(self.controls)}  # fmt: skip


def _top10() -> tuple[Control, ...]:
    from core.taxonomy import _load

    return tuple(
        Control(cat, str(entry["name"]), ("issues_by_cwe",),
                tuple(f"CWE-{c}" for c in entry["cwes"]))  # type: ignore[attr-defined]
        for cat, entry in sorted(_load().items())
    )  # fmt: skip


def _asvs() -> tuple[Control, ...]:
    c = checklists.get("asvs-4.0.3-l3")
    assert c is not None
    return tuple(
        Control(i.id, i.title, ("issues_by_cwe",) if i.cwe else (), (i.cwe,) if i.cwe else (),
                i.group, i.level)  # fmt: skip
        for i in c.items
    )


@cache
def frameworks() -> dict[str, Framework]:
    out = {}
    for path in sorted(_DIR.glob("*.json")):
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        source = raw.get("controls_from")
        if source == "owasp-top10-2021":
            controls = _top10()
        elif source == "asvs-4.0.3":
            controls = _asvs()
        else:
            controls = tuple(
                Control(c["id"], c["title"], tuple(c.get("evidence", [])),
                        tuple(c.get("cwes", [])), note=c.get("note", ""))  # fmt: skip
                for c in raw["controls"]
            )
        for c in controls:
            unknown = set(c.evidence) - set(EVIDENCE)
            if unknown:
                raise ValueError(f"{path.name}: {c.id} names unknown evidence {sorted(unknown)}")
        out[raw["id"]] = Framework(
            raw["id"], raw["name"], raw["framework_version"], raw["source"],
            int(raw["mapping_version"]), raw["mapping_date"], controls,
        )  # fmt: skip
    return out


def get(framework_id: str) -> Framework | None:
    return frameworks().get(framework_id)
