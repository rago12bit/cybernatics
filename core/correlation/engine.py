"""Cross-tool correlation: deduplicate findings that several tools report for one defect.

Rules (ADR-004):
  SCA        same package identity (ecosystem, name, version) AND a shared vulnerability id/alias.
  Code/IaC   same file, compatible category, overlapping CWE family, lines within LINE_WINDOW, and
             either a similar normalized snippet or (when a snippet is a redaction placeholder or
             too short to compare) an adjacent line.
  Never      merge two findings from the same tool and the same rule: those are distinct
             occurrences, even when a third tool's finding spans both.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from core.correlation import normalize as norm
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)

LINE_WINDOW = 3  # max distance between two findings' line ranges to be the same defect
ADJACENT = 1  # stricter distance when the snippet gives no evidence either way
SNIPPET_OVERLAP = 0.8  # min token-set overlap coefficient
MIN_TOKENS = 4  # below this a snippet is too short to compare

# Parent/child CWEs that describe one defect to a user.
CWE_FAMILY = {"CWE-259": "CWE-798", "CWE-321": "CWE-798", "CWE-260": "CWE-798"}
# Categories that may be the same defect seen by different kinds of tool.
_COMPATIBLE = [{Category.SAST, Category.SECRETS}]

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_TOOL_PRIORITY = {"trivy": 0, "osv-scanner": 1, "gitleaks": 2, "semgrep": 3, "bandit": 4}


def _cwe_family(f: Finding) -> set[str]:
    return {CWE_FAMILY.get(c, c) for c in f.taxonomy.cwe}


def _compatible(a: Category, b: Category) -> bool:
    return a is b or any(a in g and b in g for g in _COMPATIBLE)


def _line_distance(a: Location, b: Location) -> int:
    return max(0, max(a.start_line, b.start_line) - min(a.end_line, b.end_line))


def _rule_keys(f: Finding) -> set[tuple[str, str]]:
    return {(t, r) for t, rules in f.evidence.rule_ids.items() for r in rules}


def _same_sca(a: Finding, b: Finding) -> bool:
    if not (a.package and b.package and a.package == b.package):
        return False
    ids_a = {x.upper() for x in (*a.taxonomy.aliases, *a.taxonomy.cve)}
    ids_b = {x.upper() for x in (*b.taxonomy.aliases, *b.taxonomy.cve)}
    return bool(ids_a & ids_b)


def _same_code(a: Finding, b: Finding) -> bool:
    if a.location.path != b.location.path or not _compatible(
        a.taxonomy.category, b.taxonomy.category
    ):
        return False
    if not (_cwe_family(a) & _cwe_family(b)):
        return False
    dist = _line_distance(a.location, b.location)
    if dist > LINE_WINDOW:
        return False
    sa, sb = a.location.snippet, b.location.snippet
    if norm.is_placeholder(sa) or norm.is_placeholder(sb):
        return dist <= ADJACENT
    ta, tb = norm.tokens(sa), norm.tokens(sb)
    if min(len(ta), len(tb)) < MIN_TOKENS:
        return dist <= ADJACENT
    return norm.overlap(ta, tb) >= SNIPPET_OVERLAP


def same_defect(a: Finding, b: Finding) -> bool:
    if a.package or b.package:
        return _same_sca(a, b)
    return _same_code(a, b)


class _Clusters:
    def __init__(self, n: int, findings: list[Finding]) -> None:
        self.parent = list(range(n))
        self.rules = [_rule_keys(f) for f in findings]

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        ri, rj = self.find(i), self.find(j)
        if ri == rj or (self.rules[ri] & self.rules[rj]):  # same tool+rule: distinct occurrences
            return
        self.parent[rj] = ri
        self.rules[ri] |= self.rules[rj]


@dataclass(frozen=True)
class CorrelationStats:
    raw: int
    unique: int

    @property
    def dedup_rate(self) -> float:
        return 0.0 if self.raw == 0 else 1 - self.unique / self.raw


def correlate(findings: Iterable[Finding]) -> tuple[list[Finding], CorrelationStats]:
    items = list(findings)
    clusters = _Clusters(len(items), items)
    buckets: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(items):
        # SCA findings meet by package; everything else by file. (Candidate pruning only.)
        key = (
            f"pkg:{f.package.ecosystem}:{f.package.name}"
            if f.package
            else f"file:{f.location.path}"
        )
        buckets[key].append(i)
    for idxs in buckets.values():
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                if same_defect(items[idxs[x]], items[idxs[y]]):
                    clusters.union(idxs[x], idxs[y])
    groups: dict[int, list[Finding]] = defaultdict(list)
    for i, f in enumerate(items):
        groups[clusters.find(i)].append(f)
    merged = [_merge(g) for g in groups.values()]
    merged.sort(key=lambda f: (-_SEV_ORDER.index(f.scoring.normalized_severity), f.location.path,
                               f.location.start_line, f.id))  # fmt: skip
    return merged, CorrelationStats(raw=len(items), unique=len(merged))


def _primary(group: list[Finding]) -> Finding:
    return max(
        group,
        key=lambda f: (
            _SEV_ORDER.index(f.scoring.normalized_severity),
            f.scoring.confidence,
            -_TOOL_PRIORITY.get(f.evidence.reported_by[0] if f.evidence.reported_by else "", 9),
        ),
    )


def _union(seq: Iterable[Iterable[str]]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(x for part in seq for x in part))


def _merge(group: list[Finding]) -> Finding:
    p = _primary(group)
    tools = list(dict.fromkeys(t for f in group for t in f.evidence.reported_by))
    rule_ids: dict[str, list[str]] = {}
    native: dict[str, str] = {}
    for f in group:
        for t, rules in f.evidence.rule_ids.items():
            rule_ids.setdefault(t, [])
            rule_ids[t] += [r for r in rules if r not in rule_ids[t]]
        native.update(f.scoring.native_severity)
    conf = 1.0
    for f in group:  # noisy-OR: independent tools agreeing raise confidence, capped below certainty
        conf *= 1 - f.scoring.confidence
    cvss = [f.scoring.cvss_v3_1 for f in group if f.scoring.cvss_v3_1 is not None]
    summary = next((f.remediation.summary for f in [p, *group] if f.remediation.summary), "")
    merged = Finding(
        id=p.id,
        title=p.title,
        description=p.description,
        location=p.location,
        taxonomy=Taxonomy(
            p.taxonomy.category,
            cwe=_union(f.taxonomy.cwe for f in [p, *group]),
            owasp_top_10_2021=_union(f.taxonomy.owasp_top_10_2021 for f in [p, *group]),
            cve=_union(f.taxonomy.cve for f in [p, *group]),
            aliases=_union(f.taxonomy.aliases for f in [p, *group]),
        ),
        scoring=Scoring(
            native_severity=native,
            normalized_severity=max(
                (f.scoring.normalized_severity for f in group), key=_SEV_ORDER.index
            ),
            cvss_v3_1=max(cvss) if cvss else None,
            confidence=min(round(1 - conf, 3), 0.99),
        ),
        evidence=Evidence(reported_by=tools, agreement_count=len(tools), rule_ids=rule_ids),
        remediation=Remediation(
            summary=summary,
            suggested_patch=p.remediation.suggested_patch,
            references=list(_union(f.remediation.references for f in [p, *group])),
            generated_by=p.remediation.generated_by,
        ),
        package=next((f.package for f in group if f.package), None),
    )
    merged.fingerprint = fingerprint(merged)
    return merged


def fingerprint(f: Finding) -> str:
    """Stable identity for a defect across scans.

    SCA is exact: sha256(ecosystem|name|version|primary vuln id), where the primary id is the
    smallest CVE (else smallest alias). Code findings hash (smallest CWE in the family | path |
    normalized snippet); this survives whitespace, comment and identifier changes but is best-effort
    when the set of enabled tools changes, because the quoted snippet differs by tool.
    """
    if f.package:
        ids = sorted(f.taxonomy.cve) or sorted(f.taxonomy.aliases) or [f.id]
        raw = f"{f.package.ecosystem}|{f.package.name}|{f.package.version}|{ids[0].upper()}"
    else:
        cwe = min(_cwe_family(f) or {"none"})
        snip = f.location.snippet
        if norm.is_placeholder(snip):  # nothing comparable in the snippet: anchor on the line
            raw = f"{cwe}|{f.location.path}|placeholder|{f.location.start_line}"
        else:
            raw = f"{cwe}|{f.location.path}|{norm.snippet_hash(snip)}|"
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
