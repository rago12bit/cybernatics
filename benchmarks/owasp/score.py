"""Scoring against the OWASP Benchmark's ground truth. Pure functions, no scanners, no I/O.

The Benchmark is 2,740 small Java servlets, each either really vulnerable to one weakness or a "fake" that
looks vulnerable but is not, with the expected answer in a CSV. A tool is scored per test case:

    predicted positive = the tool reported the case's weakness in that file
    TP  real vulnerability, reported          FN  real vulnerability, missed
    FP  safe case, reported                   TN  safe case, not reported

How "reported the weakness" is decided is the judgment call, so three matchers are scored and shown together:

    exact    a finding with the case's own CWE id
    related  exact, plus CWE ids that describe the same weakness for that category (see RELATED)
    any      ANY finding in the file (an upper bound: no credit for reporting the right thing)

`related` is the headline. Everything else is there so the headline cannot hide a choice.
"""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Which CWE ids count as "the same weakness" for a category, beyond the expected one. Deliberately narrow:
# a cookie missing HttpOnly (CWE-1004) is NOT a missing Secure flag (CWE-614), so it earns no credit.
RELATED: dict[str, frozenset[str]] = {
    "crypto": frozenset(
        {"CWE-327", "CWE-326", "CWE-780"}
    ),  # broken / weak cipher, small key, no OAEP
    "hash": frozenset({"CWE-328", "CWE-327", "CWE-916"}),  # weak hash
    "weakrand": frozenset({"CWE-330", "CWE-338", "CWE-331", "CWE-335"}),  # insecure randomness
}
MATCHERS = ("exact", "related", "any")


@dataclass(frozen=True)
class Case:
    name: str
    category: str
    vulnerable: bool
    cwe: str  # "CWE-89"


def load_truth(csv_path: Path) -> dict[str, Case]:
    """Parse expectedresults-*.csv: `name,category,real vulnerability,cwe`."""
    cases: dict[str, Case] = {}
    with csv_path.open(newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = (c.strip() for c in row[:4])
            if real not in ("true", "false") or not cwe.isdigit():
                raise ValueError(f"unexpected row in {csv_path.name}: {row}")
            cases[name] = Case(name, category, real == "true", f"CWE-{cwe}")
    return cases


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def positive(case: Case, cwes: Iterable[str] | None, matcher: str) -> bool:
    """Did a tool that reported `cwes` for this case's file report the case's weakness?"""
    if cwes is None:  # no finding in the file
        return False
    got = set(cwes)
    if matcher == "any":
        return True
    if matcher == "exact":
        return case.cwe in got
    if matcher == "related":
        return case.cwe in got or bool(got & RELATED.get(case.category, frozenset()))
    raise ValueError(f"unknown matcher {matcher!r}")


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, vulnerable: bool, predicted: bool) -> None:
        if vulnerable:
            self.tp += predicted
            self.fn += not predicted
        else:
            self.fp += predicted
            self.tn += not predicted

    @property
    def real(self) -> int:
        return self.tp + self.fn

    @property
    def fake(self) -> int:
        return self.fp + self.tn

    def rates(self) -> dict[str, Any]:
        """recall (TPR), false positive rate, precision, F1 and the Benchmark's own score TPR - FPR."""
        tpr = self.tp / self.real if self.real else 0.0
        fpr = self.fp / self.fake if self.fake else 0.0
        flagged = self.tp + self.fp
        precision = self.tp / flagged if flagged else None  # undefined when nothing was flagged
        f1 = (
            2 * precision * tpr / (precision + tpr)
            if precision is not None and (precision + tpr)
            else None
        )
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "recall": tpr, "recall_ci": wilson(self.tp, self.real),
            "fpr": fpr, "fpr_ci": wilson(self.fp, self.fake),
            "precision": precision, "precision_ci": wilson(self.tp, flagged) if flagged else None,
            "f1": f1, "benchmark_score": tpr - fpr,
        }  # fmt: skip


def score(
    truth: dict[str, Case], predictions: dict[str, list[str]], matcher: str
) -> tuple[Confusion, dict[str, Confusion]]:
    """Overall confusion matrix and one per category. `predictions` maps test name to reported CWE ids."""
    total, by_cat = Confusion(), defaultdict(Confusion)
    for name, case in truth.items():
        hit = positive(case, predictions.get(name), matcher)
        total.add(case.vulnerable, hit)
        by_cat[case.category].add(case.vulnerable, hit)
    return total, dict(sorted(by_cat.items()))


def ensemble(per_tool: dict[str, dict[str, list[str]]], min_agree: int = 1) -> dict[str, list[str]]:
    """Combine tools per test case: the union of their CWE ids when at least `min_agree` tools reported the file.

    With `min_agree=1` this is what running every tool and reading all the findings gives; with 2 or more, a
    finding needs independent agreement. It only makes sense over tools that scan the same language.
    """
    names: dict[str, list[str]] = defaultdict(list)
    for tool_preds in per_tool.values():
        for case, cwes in tool_preds.items():
            names[case].append(",".join(cwes))
    out: dict[str, list[str]] = {}
    for case in names:
        reporting = [t for t, p in per_tool.items() if case in p]
        if len(reporting) >= min_agree:
            out[case] = sorted({c for t in reporting for c in per_tool[t][case]})
    return out
