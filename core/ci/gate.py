from __future__ import annotations

from typing import Any

THRESHOLDS = ("none", "low", "medium", "high", "critical")
_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def breaches(findings: list[dict[str, Any]], fail_on: str) -> list[dict[str, Any]]:
    """Findings at or above the threshold. `none` never fails. Unknown thresholds are an error."""
    if fail_on not in THRESHOLDS:
        raise ValueError(f"fail-on must be one of: {', '.join(THRESHOLDS)}")
    if fail_on == "none":
        return []
    floor = _RANK[fail_on.upper()]
    return [
        f
        for f in findings
        if _RANK.get(str(f.get("scoring", {}).get("normalized_severity", "")).upper(), -1) >= floor
    ]
