"""Per-CWE scoring for the Juliet Java suite. Reuses the confusion-matrix maths of the OWASP Benchmark scorer.

A test case is one side of one file: `<path>#bad` (the vulnerable flow: a real vulnerability) or `<path>#good`
(the safe flow: a look-alike that must not be reported). The result file stores, per case, which CWE ids the tool
reported inside that side, so scoring re-runs without the scanner or the suite.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from benchmarks.owasp.score import Confusion

# Juliet directory CWE -> CWE ids that count as the same weakness. Deliberately narrow, like the OWASP scorer's.
_XSS = frozenset({79, 80, 81, 83, 87})
_PATH = frozenset({22, 23, 36, 73})
RELATED: dict[int, frozenset[int]] = {
    78: frozenset({78, 77}), 89: frozenset({89, 564}), 90: frozenset({90}), 643: frozenset({643}),
    80: _XSS, 81: _XSS, 83: _XSS, 23: _PATH, 36: _PATH,
    113: frozenset({113, 93}), 601: frozenset({601}), 470: frozenset({470}), 134: frozenset({134}),
    15: frozenset({15}), 259: frozenset({259, 798, 321}), 321: frozenset({321, 798, 259}),
    327: frozenset({327, 326, 780, 328}), 328: frozenset({328, 327, 916}), 338: frozenset({338, 330, 331, 335}),
    614: frozenset({614}), 319: frozenset({319, 311}), 315: frozenset({315, 312}),
    256: frozenset({256, 312, 522}), 209: frozenset({209, 200, 201, 497}),
}  # fmt: skip
MATCHERS = ("exact", "related", "any")


def cwe_number(cwe: str) -> int | None:
    head = cwe.removeprefix("CWE-")
    return int(head) if head.isdigit() else None


def hit(case_cwe: int, reported: list[str] | None, matcher: str) -> bool:
    """`reported` is the CWE ids the tool gave inside this side of the file; None means it reported nothing there."""
    if reported is None:
        return False
    if matcher == "any":
        return True
    nums = {n for c in reported if (n := cwe_number(c)) is not None}
    allowed = {case_cwe} if matcher == "exact" else RELATED.get(case_cwe, frozenset({case_cwe}))
    return bool(nums & allowed)


def score_cases(
    cases: dict[str, dict[str, Any]], matcher: str
) -> tuple[Confusion, dict[int, Confusion]]:
    """`cases[id] = {"cwe": 89, "vulnerable": bool, "reported": [...] | None}` -> overall and per-CWE confusion."""
    total, by_cwe = Confusion(), defaultdict(Confusion)
    for c in cases.values():
        h = hit(c["cwe"], c.get("reported"), matcher)
        total.add(c["vulnerable"], h)
        by_cwe[c["cwe"]].add(c["vulnerable"], h)
    return total, dict(sorted(by_cwe.items()))
