"""What did this change introduce? Compare a head scan with a baseline scan by fingerprint.

Fingerprints are the stable defect identity from correlation (`core.correlation.fingerprint`), so a finding
that merely moved lines or was reported by a different tool set still counts as the same one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_SCAN_BYTES = 200 * 1024 * 1024


@dataclass
class Scan:
    findings: list[dict[str, Any]]
    tool_status: dict[str, dict[str, Any]]
    raw_findings: int = 0
    unique_findings: int = 0
    dedup_rate: float = 0.0
    ignored: int = 0


@dataclass
class Comparison:
    head: Scan
    new: list[dict[str, Any]] = field(default_factory=list)
    existing: int = 0
    fixed: int = 0
    baseline_available: bool = False
    baseline_incomplete: bool = False  # a base scan was given but a scanner failed in it

    def gate_set(self) -> list[dict[str, Any]]:
        """Findings the failure threshold applies to: what the change introduced, or everything if
        there is no baseline to compare with."""
        return self.new if self.baseline_available else self.head.findings


def load_scan(path: Path) -> Scan:
    """Read `bulwark scan --format json` output. Raises ValueError with a readable message."""
    if path.stat().st_size > MAX_SCAN_BYTES:
        raise ValueError(f"{path.name} is too large")
    try:
        doc = json.loads(path.read_text("utf-8"))
        findings = doc["findings"]
        if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
            raise TypeError("findings must be a list of objects")
        stats = doc.get("stats") or {}
        return Scan(
            findings=findings,
            tool_status=doc.get("tool_status") or {},
            raw_findings=int(stats.get("raw_findings", len(findings))),
            unique_findings=int(stats.get("unique_findings", len(findings))),
            dedup_rate=float(stats.get("dedup_rate", 0.0)),
            ignored=int(stats.get("ignored_findings", 0)),
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"{path.name} is not valid Bulwark scan output: {exc}") from exc


def _key(f: dict[str, Any]) -> str:
    return str(f.get("fingerprint") or f.get("id"))


def compare(head: Scan, base: Scan | None) -> Comparison:
    if base is None:
        return Comparison(head=head)
    if _incomplete(base):
        # A baseline where a scanner failed would make its findings look "new". Do not trust it.
        return Comparison(head=head, baseline_incomplete=True)
    base_keys = {_key(f) for f in base.findings}
    head_keys = {_key(f) for f in head.findings}
    new = [f for f in head.findings if _key(f) not in base_keys]
    return Comparison(
        head=head,
        new=new,
        existing=len(head.findings) - len(new),
        fixed=len(base_keys - head_keys),
        baseline_available=True,
    )


def _incomplete(scan: Scan) -> bool:
    return any(s.get("status") not in ("ok", "skipped") for s in scan.tool_status.values())
