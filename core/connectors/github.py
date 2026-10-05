"""GitHub code scanning and Dependabot alerts through the GitHub App (plan §42.5: "GitHub
code-scanning and Dependabot alerts, through the GitHub App from v2").

No credential is stored for these: each pull mints a one-hour installation token from the App
(`core.github_app.installation_token`), which can only see what the installation was granted. The
App needs two read permissions for this -- "Code scanning alerts: read" and "Dependabot alerts:
read" -- and nothing that writes. The installation must belong to the connector's organization.

Only open alerts are fetched: the pull is the source's current list, and reimport closes what is no
longer on it (a fixed or dismissed alert), so an alert dismissed in GitHub closes here too -- with
the dismissal visible in GitHub, where it was made.
"""

from __future__ import annotations

import re
from typing import Any

from core.connectors.base import PER_PAGE, Fetched, link_pages
from core.connectors.http import Transport
from core.dast.mapping import clip, plain_text
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

API = "https://api.github.com"
REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_CWE_TAG = re.compile(r"^external/cwe/cwe-0*(\d{1,6})$", re.IGNORECASE)
_SECURITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}
_RULE = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "bulwark-connector",
    }


def code_scanning_finding(alert: dict[str, Any]) -> Finding | None:
    rule = alert.get("rule") or {}
    tool = (alert.get("tool") or {}).get("name") or "code-scanning"
    inst = alert.get("most_recent_instance") or {}
    loc = inst.get("location") or {}
    path = str(loc.get("path") or "")
    if not path:
        return None
    start = max(int(loc.get("start_line") or 1), 1)
    end = max(int(loc.get("end_line") or start), start)
    word = str(rule.get("security_severity_level") or "").lower()
    severity = _SECURITY.get(word) or _RULE.get(
        str(rule.get("severity") or "").lower(), Severity.INFO
    )
    native = word or str(rule.get("severity") or "")
    cwes = tuple(
        dict.fromkeys(
            f"CWE-{int(m.group(1))}"
            for t in rule.get("tags") or []
            if (m := _CWE_TAG.match(str(t)))
        )
    )
    source = str(tool).strip().lower().replace(" ", "-")[:40] or "code-scanning"
    rule_id = str(rule.get("id") or rule.get("name") or "unknown")[:200]
    message = plain_text(((inst.get("message") or {}).get("text")) or "")
    title = str(rule.get("description") or rule.get("name") or rule_id)[:300]
    secret = "secret" in rule_id.lower() and "secret" in str(rule.get("tags") or "").lower()
    return Finding(
        id=f"github-code-scanning:{alert.get('number')}",
        title=title,
        description=message or title,
        location=Location(path, start, end),
        taxonomy=Taxonomy(Category.SECRETS if secret else Category.SAST, cwe=cwes),
        scoring=Scoring(
            native_severity={source: native.upper()}, normalized_severity=severity, confidence=0.7
        ),
        evidence=Evidence(reported_by=[source], rule_ids={source: [rule_id]}),
        remediation=Remediation(
            references=[u for u in [alert.get("html_url")] if isinstance(u, str)]
        ),
    )


def dependabot_finding(alert: dict[str, Any]) -> Finding | None:
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    adv = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    name = str(pkg.get("name") or "")
    if not name:
        return None
    eco = Package.normalize_ecosystem(str(pkg.get("ecosystem") or "unknown"))
    cve = str(adv.get("cve_id") or "").upper()
    ghsa = str(adv.get("ghsa_id") or "")
    key = cve or ghsa or f"dependabot-{alert.get('number')}"
    word = str(adv.get("severity") or vuln.get("severity") or "").lower()
    cvss = adv.get("cvss") or {}
    score = cvss.get("score") if str(cvss.get("vector_string") or "").startswith("CVSS:3") else None
    patched = ((vuln.get("first_patched_version") or {}).get("identifier")) or ""
    vrange = str(vuln.get("vulnerable_version_range") or "")
    manifest = str(dep.get("manifest_path") or "unknown")
    # Dependabot does not say which version is installed, only the vulnerable range. The range
    # stands in for the version so the identity is stable across pulls; it is shown as a range.
    snippet = f"{name}@{vrange}" if vrange else name
    summary = str(adv.get("summary") or key)
    refs = [r["url"] for r in adv.get("references") or [] if isinstance(r, dict) and r.get("url")]
    if isinstance(alert.get("html_url"), str):
        refs.insert(0, alert["html_url"])
    return Finding(
        id=f"dependabot:{key}:{manifest}:{name}",
        title=f"{key}: {summary}"[:300],
        description=clip(plain_text(adv.get("description") or summary), 4000),
        location=Location(manifest, 1, 1, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(
            Category.SCA,
            cwe=tuple(
                str(c["cwe_id"])
                for c in adv.get("cwes") or []
                if isinstance(c, dict) and c.get("cwe_id")
            ),
            cve=(cve,) if cve else (),
            aliases=tuple(a for a in (cve, ghsa) if a),
        ),
        scoring=Scoring(
            native_severity={"dependabot": word.upper()},
            normalized_severity=_SECURITY.get(word, Severity.INFO),
            cvss_v3_1=float(score) if isinstance(score, (int, float)) else None,
            confidence=0.9,
        ),
        evidence=Evidence(reported_by=["dependabot"], rule_ids={"dependabot": [key]}),
        remediation=Remediation(
            summary=(
                f"Upgrade {name} to {patched} or later." if patched else "No patched version yet."
            ),
            references=refs[:20],
        ),
        package=Package(name, vrange, eco),
    )


def fetch_code_scanning(transport: Transport, token: str, repo: str, api: str = API) -> Fetched:
    url = f"{api}/repos/{repo}/code-scanning/alerts?state=open&per_page={PER_PAGE}"
    return _fetch(transport, token, url, "GitHub code scanning", code_scanning_finding)


def fetch_dependabot(transport: Transport, token: str, repo: str, api: str = API) -> Fetched:
    url = f"{api}/repos/{repo}/dependabot/alerts?state=open&per_page={PER_PAGE}"
    return _fetch(transport, token, url, "GitHub Dependabot", dependabot_finding)


def _fetch(transport: Transport, token: str, url: str, what: str, build: Any) -> Fetched:
    out = Fetched([], 0)
    skipped = 0
    for page, n in link_pages(transport, url, _headers(token), what):
        out.requests = n
        for alert in page:
            if not isinstance(alert, dict):
                continue
            out.items += 1
            finding = build(alert)
            if finding is None:
                skipped += 1
            else:
                out.findings.append(finding)
    if skipped:
        out.warnings.append(f"{skipped} alert(s) had no location and were skipped")
    return out
