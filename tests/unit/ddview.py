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


def group_zap(findings: list[Finding], name: str = "") -> list[list[Finding]]:
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


def group_nuclei(findings: list[Finding], name: str = "") -> list[list[Finding]]:
    """DefectDojo folds on template, type, matcher and *hostname* (a port is not part of it)."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((rule_of(f), _hostname(f.location.host)), []).append(f)
    return list(groups.values())


def _fold(findings: list[Finding], key: Callable[[Finding], Any]) -> list[list[Finding]]:
    groups: dict[Any, list[Finding]] = {}
    for f in findings:
        groups.setdefault(key(f), []).append(f)
    return list(groups.values())


def _severity(f: Finding) -> str:
    return f.scoring.normalized_severity.value


def group_burp(findings: list[Finding], name: str = "") -> list[list[Finding]]:
    """DefectDojo folds Burp issues on `(type, title)`; extension issues share one type id, which
    is why our rule id carries the title too."""
    return _fold(findings, lambda f: (rule_of(f).split(":")[0], f.title))


def group_nessus(findings: list[Finding], name: str = "") -> list[list[Finding]]:
    """The XML parser folds on severity and title across *every host*; the CSV parser on severity,
    title, host and port (one finding per plugin per place)."""
    if name.endswith(".csv"):
        return _fold(findings, lambda f: (_severity(f), f.title, f.location.host, f.location.route))
    return _fold(findings, lambda f: (_severity(f), f.title))


def group_openvas(findings: list[Finding], name: str = "") -> list[list[Finding]]:
    """DefectDojo folds on location, title, NVT and severity."""
    return _fold(
        findings,
        lambda f: (f.location.host, f.location.route, f.title, rule_of(f), _severity(f)),
    )


def group_grype(findings: list[Finding], name: str = "") -> list[list[Finding]]:
    """DefectDojo folds Grype matches on vulnerability, package and version (its default mode; path
    only matters under a setting)."""
    return _fold(
        findings,
        lambda f: ((rule_of(f), f.package.name, f.package.version) if f.package else f.id),
    )


def group_each(findings: list[Finding], name: str = "") -> list[list[Finding]]:
    """The Trivy and Snyk parsers fold nothing: one DefectDojo finding per entry."""
    return [[f] for f in findings]


GROUPERS: dict[str, Callable[[list[Finding], str], list[list[Finding]]]] = {
    "grype": group_grype,
    "trivy": group_each,
    "snyk": group_each,
    "zap": group_zap,
    "nuclei": group_nuclei,
    "burp": group_burp,
    "nessus": group_nessus,
    "openvas": group_openvas,
}


def distinct_places(group: list[Finding]) -> int:
    return len({(f.location.host, f.location.route) for f in group})


# How many "locations" DefectDojo reports for a finding: ZAP appends one per instance (duplicates
# included), Nuclei one per distinct matched URL.
LOCATIONS: dict[str, Callable[[list[Finding]], int]] = {
    "zap": len,
    "nuclei": distinct_places,
    "burp": len,  # one per folded issue
    "nessus": len,  # one per ReportItem or row
    "openvas": distinct_places,  # only identical places fold, so this is 1
    "grype": len,
    "trivy": len,
    "snyk": len,
}


SKIPPED_FIELDS = "component_name/component_version outside SCA (see view)"


def dd_title(tool: str, f: Finding) -> str:
    """DefectDojo's title for an SCA finding, rebuilt from the fields ours carries (ours reads
    `<package> <version>: <title>`, which says what is affected before what is wrong). The ZAP-style
    tools' titles are the same on both sides."""
    if not f.package and tool != "trivy":
        return f.title
    if tool == "grype":
        return f"{rule_of(f)} in {f.package.name}:{f.package.version}"
    if tool == "trivy" and f.taxonomy.category.value == "secrets":
        return f"Secret detected in {f.location.path} - {f.title}"
    if tool == "trivy" and not f.package:
        return f"{rule_of(f)} - {f.title}"  # DefectDojo prefixes a misconfiguration with its rule
    if tool == "trivy" and f.title.startswith(f"{f.package.name} {f.package.version}: "):
        return f"{rule_of(f)} {f.package.name} {f.package.version}"
    if tool == "snyk":
        # DefectDojo prefixes the root project (the first element of Snyk's `from` chain); it is
        # the first element of the "Vulnerable path" line in our description.
        path = next(
            (ln for ln in f.description.splitlines() if ln.startswith("Vulnerable path: ")), ""
        )
        root = path.removeprefix("Vulnerable path: ").split(" > ")[0]
        return f"{root}: {f.title.removeprefix(f'{f.package.name} {f.package.version}: ')}"
    return f.title


def view(tool: str, group: list[Finding]) -> dict[str, Any]:
    """One DefectDojo-shaped finding, from the group of ours it corresponds to."""
    first = group[0]
    sca = first.package is not None
    cwe = first.taxonomy.cwe[0] if first.taxonomy.cwe else None
    return {
        "title": dd_title(tool, first),
        # DefectDojo's component_* are an SCA package; for a web or network finding they hold
        # something else (a Nuclei matcher, a CPE product) that has no field here, so they are not
        # compared -- see SKIPPED_FIELDS.
        **(
            {"component_name": first.package.name, "component_version": first.package.version}
            if sca and first.package
            else {}
        ),
        "severity": first.scoring.normalized_severity.value.title(),
        "vuln_id_from_tool": rule_of(first).split(":")[0],
        # DefectDojo stores "no CWE" as 0 (and its tests assert either 0 or None): both mean none.
        "cwe": int(cwe.removeprefix("CWE-")) if cwe else 0,
        "cvssv3_score": first.scoring.cvss_v3_1,
        "locations": LOCATIONS[tool](group),
    }
