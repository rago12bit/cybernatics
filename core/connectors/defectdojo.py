"""DefectDojo, in both directions (plan §42.5: "import findings from an instance (a migration path
in), and export to one through its import API as SARIF (a migration path out, and proof of
interoperability)").

**In.** `GET /api/v2/findings/?product=<id>&active=true&duplicate=false`, following DefectDojo's
own `next` links (on the same host only). Each finding keeps DefectDojo's id as its rule id, so a
finding is the same Issue on every pull, and DefectDojo's own deduplication decides what is one
finding. Only active, non-duplicate findings are pulled: one closed or marked false positive in
DefectDojo leaves the list, and reimport closes it here.

**Out.** The project's open Issues as SARIF (the exporter every scan report uses), posted to
`/api/v2/import-scan/` the first time and `/api/v2/reimport-scan/` into the same Test after that,
with `close_old_findings` so DefectDojo closes what Bulwark no longer has open. Issues that came
*from* DefectDojo are left out, or the two would echo each other's findings forever.

The token is a DefectDojo API v2 key (`Authorization: Token ...`). DefectDojo's user should have
only what the direction needs: read on the product to pull, add-findings on its engagement to push.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from core.connectors.base import MAX_PAGES, PER_PAGE, Fetched, same_origin
from core.connectors.http import ConnectorError, Transport, expect_ok
from core.dast.mapping import clip, plain_text
from core.export.model import ReportData
from core.export.sarif import to_sarif
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)

SOURCE = "defectdojo"
_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}
_URL = re.compile(r"https?://[^\s<>\"')\]]+")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "User-Agent": "bulwark-connector",
    }


def dd_finding(d: dict[str, Any]) -> Finding | None:
    fid = d.get("id")
    title = " ".join(str(d.get("title") or "").split())[:300]
    if fid is None or not title:
        return None
    rule = f"dd-{fid}"
    word = str(d.get("severity") or "").strip().lower()
    severity = _SEVERITY.get(word, Severity.INFO)
    cwe_n = d.get("cwe")
    cwes = (f"CWE-{int(cwe_n)}",) if isinstance(cwe_n, int) and cwe_n > 0 else ()
    ids = [
        str(v.get("vulnerability_id"))
        for v in d.get("vulnerability_ids") or []
        if isinstance(v, dict) and v.get("vulnerability_id")
    ]
    if d.get("cve"):
        ids.append(str(d["cve"]))
    ids = list(dict.fromkeys(ids))
    cves = tuple(i.upper() for i in ids if _CVE.match(i))
    refs = list(dict.fromkeys(_URL.findall(str(d.get("references") or ""))))[:20]
    description = (
        "\n\n".join(p for p in (plain_text(d.get("description")), plain_text(d.get("impact"))) if p)
        or title
    )
    score = d.get("cvssv3_score")
    scoring = Scoring(
        native_severity={SOURCE: word.upper()},
        normalized_severity=severity,
        cvss_v3_1=float(score) if isinstance(score, (int, float)) else None,
        confidence=0.7,
    )
    evidence = Evidence(reported_by=[SOURCE], rule_ids={SOURCE: [rule]})
    remediation = Remediation(summary=clip(plain_text(d.get("mitigation")), 4000), references=refs)
    component = str(d.get("component_name") or "")
    path = str(d.get("file_path") or "")
    if component and (cves or not path):
        version = str(d.get("component_version") or "")
        snippet = f"{component}@{version}"
        return Finding(
            id=f"{SOURCE}:{rule}",
            title=title,
            description=description,
            location=Location(path or "unknown", 1, 1, snippet, Location.hash_snippet(snippet)),
            taxonomy=Taxonomy(Category.SCA, cwe=cwes, cve=cves, aliases=tuple(ids)),
            scoring=scoring,
            evidence=evidence,
            remediation=remediation,
            package=Package(component, version, "unknown"),
        )
    if d.get("dynamic_finding") and not d.get("static_finding") and not path:
        # DefectDojo keeps a dynamic finding's URLs as separate Endpoint objects; without them the
        # finding is placed on no route, and its DefectDojo id keeps it distinct.
        return Finding(
            id=f"{SOURCE}:{rule}",
            title=title,
            description=description,
            location=Location("", 0, 0, route="/", host=""),
            taxonomy=Taxonomy(Category.DAST, cwe=cwes, cve=cves, aliases=tuple(ids)),
            scoring=scoring,
            evidence=evidence,
            remediation=remediation,
        )
    raw_line = d.get("line")
    line = raw_line if isinstance(raw_line, int) and raw_line > 0 else 1
    return Finding(
        id=f"{SOURCE}:{rule}",
        title=title,
        description=description,
        location=Location(path or "unknown", line, line),
        taxonomy=Taxonomy(Category.SAST, cwe=cwes, cve=cves, aliases=tuple(ids)),
        scoring=scoring,
        evidence=evidence,
        remediation=remediation,
    )


def fetch(transport: Transport, base_url: str, token: str, product_id: int) -> Fetched:
    base = base_url.rstrip("/")
    url: str | None = (
        f"{base}/api/v2/findings/?product={product_id}&active=true&duplicate=false"
        f"&limit={PER_PAGE}&offset=0"
    )
    out = Fetched([], 0)
    skipped = 0
    n = 0
    while url:
        n += 1
        if n > MAX_PAGES:
            raise ConnectorError(
                f"DefectDojo: more than {MAX_PAGES * PER_PAGE} findings; refusing a " "partial pull"
            )
        if not same_origin(base, url):
            # DefectDojo builds `next` from its own idea of its host; behind a proxy, that differs.
            raise ConnectorError(
                f"DefectDojo: the next page is on another host ({url.split('/')[2]});"
                " set the base URL to the address DefectDojo itself reports"
            )
        page = expect_ok(transport("GET", url, _headers(token), None), "DefectDojo")
        out.requests = n
        if not isinstance(page, dict) or not isinstance(page.get("results"), list):
            raise ConnectorError("DefectDojo: the response is not a findings list")
        for d in page["results"]:
            if not isinstance(d, dict):
                continue
            out.items += 1
            f = dd_finding(d)
            if f is None:
                skipped += 1
            else:
                out.findings.append(f)
        nxt = page.get("next")
        url = str(nxt) if nxt else None
    if skipped:
        out.warnings.append(f"{skipped} finding(s) had no id or title and were skipped")
    return out


# --- export ---------------------------------------------------------------------------------------


def sarif_for(findings: list[dict[str, Any]], label: str) -> bytes:
    """Open Issues (their latest occurrence, as Finding dicts) as SARIF. A web finding has no file;
    SARIF needs a location, so its host and route stand in."""
    shaped = []
    for f in findings:
        loc = dict(f["location"])
        if not loc.get("path"):
            loc["path"] = f"{loc.get('host') or ''}{loc.get('route') or ''}" or "unknown"
            loc["start_line"] = loc["end_line"] = max(int(loc.get("start_line") or 1), 1)
        shaped.append({**f, "location": loc})
    report = ReportData(
        scan_id="defectdojo-export",
        source_label=label,
        status="completed",
        finished_at=None,
        tool_status={},
        raw_findings=len(shaped),
        unique_findings=len(shaped),
        dedup_rate=0.0,
        severity_counts={},
        findings=shaped,
    )
    return json.dumps(to_sarif(report)).encode()


def push(
    transport: Transport,
    base_url: str,
    token: str,
    sarif: bytes,
    *,
    test_id: int | None,
    engagement_id: int | None,
    product_name: str | None,
    engagement_name: str | None,
) -> int:
    """Import (first time) or reimport (into `test_id`) a SARIF file. Returns DefectDojo's Test id,
    which the next push reimports into."""
    base = base_url.rstrip("/")
    fields: dict[str, str] = {
        "scan_type": "SARIF",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
        "close_old_findings": "true",
    }
    if test_id is not None:
        endpoint = "reimport-scan"
        fields["test"] = str(test_id)
    elif engagement_id is not None:
        endpoint = "import-scan"
        fields["engagement"] = str(engagement_id)
    elif product_name and engagement_name:
        endpoint = "import-scan"
        fields.update(
            product_name=product_name, engagement_name=engagement_name, auto_create_context="true"
        )
    else:
        raise ConnectorError(
            "DefectDojo export needs an engagement id, or a product and engagement name"
        )
    request = httpx.Request(
        "POST",
        f"{base}/api/v2/{endpoint}/",
        data=fields,
        files={"file": ("bulwark.sarif", sarif, "application/json")},
    )
    body = request.read()
    headers = {**_headers(token), "Content-Type": request.headers["content-type"]}
    result = expect_ok(transport("POST", f"{base}/api/v2/{endpoint}/", headers, body), "DefectDojo")
    if not isinstance(result, dict):
        raise ConnectorError("DefectDojo: the import response is not JSON")
    test = result.get("test", result.get("test_id"))
    if not isinstance(test, int):
        raise ConnectorError("DefectDojo: the import response names no test")
    return test
