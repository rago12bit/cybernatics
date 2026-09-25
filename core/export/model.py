"""Data every exporter renders. Built from stored findings (plain dicts), never from live objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
TOP_N = 10


@dataclass
class ReportData:
    scan_id: str
    source_label: str
    status: str
    finished_at: str | None
    tool_status: dict[str, dict[str, Any]]
    raw_findings: int
    unique_findings: int
    dedup_rate: float
    severity_counts: dict[str, int]
    findings: list[dict[str, Any]] = field(default_factory=list)  # canonical Finding dicts

    def by_risk(self) -> list[dict[str, Any]]:
        return sorted(self.findings, key=lambda f: -(f["scoring"].get("risk_score") or -1))

    def by_severity(self) -> list[dict[str, Any]]:
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(
            self.findings,
            key=lambda f: (
                rank.get(f["scoring"]["normalized_severity"], 9),
                -(f["scoring"].get("risk_score") or -1),
                f["location"]["path"],
                f["location"]["start_line"],
            ),
        )

    def top(self) -> list[dict[str, Any]]:
        return self.by_risk()[:TOP_N]


def loc_label(f: dict[str, Any]) -> str:
    loc = f["location"]
    a, b = loc["start_line"], loc["end_line"]
    return f"{loc['path']}:{a}-{b}" if b > a else f"{loc['path']}:{a}"
