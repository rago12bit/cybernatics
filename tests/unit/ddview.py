"""Reading our parsers' output the way DefectDojo's tests read theirs (plan §60 "Ported parsers":
"issues produced and field-level agreement with DefectDojo's expected results").

DefectDojo's parsers fold related records into one finding -- a ZAP alert hit at fifty URLs is one
finding with fifty endpoints, a Nuclei template matching one host twice is one finding with two
locations. Ours keep one finding per place, because each place is a separate thing to fix and
fixing one must not close the rest (`core.dast.mapping`). So before comparing, our findings are
regrouped by the key each DefectDojo parser folds on; what is compared is then like for like, and the
number of groups is "the findings DefectDojo would have made".
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.models import Finding

GOLDEN = Path(__file__).resolve().parent.parent / "golden" / "ingest" / "defectdojo"


def manifest(tool: str) -> dict[str, Any]:
    out: dict[str, Any] = json.loads((GOLDEN / tool / "MANIFEST.json").read_text())
    return out


def rule_of(f: Finding) -> str:
    return next(iter(f.evidence.rule_ids.values()))[0]


def _hostname(host: str) -> str:
    return urlsplit(host if "://" in host else "//" + host).hostname or host


def group_zap(findings: list[Finding]) -> list[list[Finding]]:
    """One DefectDojo finding per `<alertitem>`; its instances are consecutive in our output."""
    groups: list[list[Finding]] = []
    last: tuple[str, str] | None = None
    for f in findings:
        key = (rule_of(f), f.title)
        if key != last:
            groups.append([])
            last = key
        groups[-1].append(f)
    return groups


def group_nuclei(findings: list[Finding]) -> list[list[Finding]]:
    """DefectDojo folds on template, type, matcher and *hostname* (a port is not part of it)."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((rule_of(f), _hostname(f.location.host)), []).append(f)
    return list(groups.values())


GROUPERS: dict[str, Callable[[list[Finding]], list[list[Finding]]]] = {
    "zap": group_zap,
    "nuclei": group_nuclei,
}


def distinct_places(group: list[Finding]) -> int:
    return len({(f.location.host, f.location.route) for f in group})


# How many "locations" DefectDojo reports for a finding: ZAP appends one per instance (duplicates
# included), Nuclei one per distinct matched URL.
LOCATIONS: dict[str, Callable[[list[Finding]], int]] = {
    "zap": len,
    "nuclei": distinct_places,
}


def view(tool: str, group: list[Finding]) -> dict[str, Any]:
    """One DefectDojo-shaped finding, from the group of ours it corresponds to."""
    first = group[0]
    cwe = first.taxonomy.cwe[0] if first.taxonomy.cwe else None
    return {
        "title": first.title,
        "severity": first.scoring.normalized_severity.value.title(),
        "vuln_id_from_tool": rule_of(first).split(":")[0] if tool == "nuclei" else rule_of(first),
        # DefectDojo stores "no CWE" as 0 (and its tests assert either 0 or None): both mean none.
        "cwe": int(cwe.removeprefix("CWE-")) if cwe else 0,
        "cvssv3_score": first.scoring.cvss_v3_1,
        "locations": LOCATIONS[tool](group),
    }
