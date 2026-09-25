"""Unified risk score (0-100), documented in docs/risk-score.md.

    impact     = CVSS/10 when known, else a fixed weight per normalized severity
    likelihood = KEV -> 1.0; EPSS known -> sqrt(EPSS/0.5) capped at 1; CVE, no exploit data -> 0.3;
                 non-dependency findings (code, secrets, IaC) -> the merged confidence
    risk       = 100 * impact * (0.5 + 0.5 * likelihood);  listed in CISA KEV -> at least 90

A transparent heuristic for ordering work, not a probability, and not validated against outcomes.
Every score carries the human-readable factors that produced it.
"""

from __future__ import annotations

import math
from dataclasses import replace

from core.models import Category, Finding, Severity
from core.risk.feeds import Feeds

SEVERITY_IMPACT = {
    Severity.CRITICAL: 0.95,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.05,
}
KEV_FLOOR = 90
UNKNOWN_LIKELIHOOD = 0.3
EPSS_FULL_AT = 0.5  # an EPSS of 50% or more counts as certain enough for full weight


def cves_of(f: Finding) -> set[str]:
    return {
        c.upper() for c in (*f.taxonomy.cve, *f.taxonomy.aliases) if c.upper().startswith("CVE-")
    }


def epss_likelihood(epss: float) -> float:
    return min(1.0, math.sqrt(max(epss, 0.0) / EPSS_FULL_AT))


def score_finding(f: Finding, feeds: Feeds) -> Finding:
    cves = cves_of(f)
    epss = max((feeds.epss[c] for c in cves if c in feeds.epss), default=None)
    kev = any(c in feeds.kev for c in cves)
    sc = f.scoring
    factors: list[str] = []

    if sc.cvss_v3_1 is not None:
        impact = min(max(sc.cvss_v3_1, 0.0), 10.0) / 10
        factors.append(f"CVSS {sc.cvss_v3_1:g}")
    else:
        impact = SEVERITY_IMPACT[sc.normalized_severity]
        factors.append(f"{sc.normalized_severity.value.title()} severity")

    if kev:
        likelihood = 1.0
        factors.append("In CISA KEV: exploited in the wild")
    elif epss is not None:
        likelihood = epss_likelihood(epss)
        factors.append(f"EPSS {epss:.1%}: chance of exploitation in the next 30 days")
    elif cves or f.taxonomy.category is Category.SCA:
        # A dependency advisory without a CVE id cannot be looked up: unknown, not confident.
        likelihood = UNKNOWN_LIKELIHOOD
        if not cves:
            factors.append("No CVE id to look up exploit data")
        else:
            factors.append(
                "No exploit data for this CVE" if feeds.epss_loaded else "Exploit feeds not loaded"
            )
    else:
        likelihood = min(max(sc.confidence, 0.0), 1.0)
        n = f.evidence.agreement_count
        factors.append(
            f"Flagged by {n} scanner{'s' if n != 1 else ''}, confidence {likelihood:.0%}"
        )

    score = round(100 * impact * (0.5 + 0.5 * likelihood))
    if kev:
        score = max(score, KEV_FLOOR)
    score = min(score, 100)
    return replace(
        f,
        scoring=replace(
            sc,
            epss_score=epss if epss is not None else sc.epss_score,
            in_cisa_kev=kev or sc.in_cisa_kev,
            risk_score=score,
            risk_factors=factors,
        ),
    )


def apply_risk(findings: list[Finding], feeds: Feeds | None = None) -> list[Finding]:
    """Score every finding. Loads feeds from the cache if not given; missing feeds never raise."""
    if feeds is None:
        wanted = set().union(*(cves_of(f) for f in findings)) if findings else set()
        feeds = Feeds.load(wanted)
    return [score_finding(f, feeds) for f in findings]
