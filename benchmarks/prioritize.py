"""Prioritization quality: does Bulwark's risk score put real vulnerabilities above false alarms?

    python -m benchmarks.prioritize collect            # scan the OWASP Benchmark with Semgrep, save scored records
    python -m benchmarks.prioritize score records.json # top-K precision: risk score vs severity only vs random

Each finding in a Benchmark test file is labelled: a true positive if the test is a real vulnerability and the
finding names its weakness (the "related" matcher of docs/evaluation-owasp.md), otherwise a false alarm.
Top-K precision is the share of the K highest-ranked findings that are true positives.

Ties matter: a scanner with one severity scale ties thousands of findings. A tied group that straddles the
cut-off contributes its expected value (K_remaining / group size x its true positives), which is what a random
tie-break gives on average; nothing is decided by input order.

Limit, stated in the output: only code findings with ground truth can be scored. The parts of the risk score
that matter most for dependencies (EPSS, KEV, reachability) have no ground truth here, so this does not
evaluate them.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"
KS = (10, 20, 50, 100)
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

Record = dict[str, Any]  # {"case", "cwe": [...], "severity", "risk", "true_positive"}


def precision_at_k(records: Sequence[Record], key: Callable[[Record], float], k: int) -> float:
    """Expected top-k precision when ranking by `key` (higher first) with ties broken at random."""
    k = min(k, len(records))
    if k == 0:
        return 0.0
    groups: dict[float, list[Record]] = defaultdict(list)
    for r in records:
        groups[key(r)].append(r)
    left, hits = k, 0.0
    for score in sorted(groups, reverse=True):
        g = groups[score]
        take = min(left, len(g))
        hits += take * sum(r["true_positive"] for r in g) / len(g)
        left -= take
        if not left:
            break
    return hits / k


def by_risk(r: Record) -> float:
    return float(r["risk"])


def by_severity(r: Record) -> float:
    return float(SEVERITY_RANK[r["severity"]])


def base_rate(records: Sequence[Record]) -> float:
    return sum(r["true_positive"] for r in records) / len(records) if records else 0.0


def bootstrap_diff(
    records: Sequence[Record], k: int, n: int = 500, seed: int = 20260926
) -> tuple[float, float]:
    """95% interval for (risk-score P@k - severity-only P@k), resampling findings with replacement."""
    rng = random.Random(seed)
    diffs = []
    for _ in range(n):
        s = rng.choices(records, k=len(records))
        diffs.append(precision_at_k(s, by_risk, k) - precision_at_k(s, by_severity, k))
    diffs.sort()
    return diffs[int(0.025 * n)], diffs[int(0.975 * n) - 1]


def evaluate(records: Sequence[Record]) -> dict[str, Any]:
    rows = []
    for k in KS:
        risk = precision_at_k(records, by_risk, k)
        sev = precision_at_k(records, by_severity, k)
        lo, hi = bootstrap_diff(records, k)
        rows.append({"k": k, "risk_score": risk, "severity_only": sev, "random": base_rate(records),
                     "diff": risk - sev, "diff_ci95": [lo, hi]})  # fmt: skip
    return {
        "findings": len(records),
        "true_positives": sum(r["true_positive"] for r in records),
        "distinct_risk_scores": len({r["risk"] for r in records}),
        "distinct_severities": len({r["severity"] for r in records}),
        "rows": rows,
    }


def label(findings: list[Any], truth: dict[str, Any]) -> list[Record]:
    """Attach ground truth to scored findings. Findings outside a Benchmark test file are dropped."""
    from benchmarks.owasp.run import _TEST_FILE
    from benchmarks.owasp.score import positive

    out: list[Record] = []
    for f in findings:
        m = _TEST_FILE.search(f.location.path)
        case = truth.get(m.group(1)) if m else None
        if case is None:
            continue
        cwes = sorted(f.taxonomy.cwe)
        out.append({
            "case": case.name, "cwe": cwes, "severity": f.scoring.normalized_severity.value,
            "risk": f.scoring.risk_score,
            "true_positive": bool(case.vulnerable and positive(case, cwes, "related")),
        })  # fmt: skip
    return out


def collect(label_: str) -> dict[str, Any]:
    from benchmarks.owasp.run import TAG, fetch, stage
    from benchmarks.owasp.score import load_truth
    from core.scan import scan
    from core.source import materialize

    bench = fetch()
    truth = load_truth(bench / "expectedresults-1.2beta.csv")
    with tempfile.TemporaryDirectory() as tmp:
        staged = stage(bench, Path(tmp) / "stage")
        with materialize(str(staged)) as ws:
            result = scan(ws, ["semgrep"])
    records = label(result.findings, truth)
    return {"benchmark": {"name": "OWASP Benchmark", "tag": TAG}, "measured": date.today().isoformat(),
            "label": label_, "tool_status": result.tool_status, "records": records}  # fmt: skip


def markdown(ev: dict[str, Any]) -> str:
    L = [
        f"{ev['findings']} findings, {ev['true_positives']} true positives "
        f"({ev['true_positives'] / ev['findings']:.1%} base rate); "
        f"{ev['distinct_risk_scores']} distinct risk scores, {ev['distinct_severities']} distinct severities.",
        "",
        "| Top-K | Risk score | Severity only | Random | Risk − severity (95% CI) |",
        "|---:|---:|---:|---:|---:|",
    ]
    for r in ev["rows"]:
        lo, hi = r["diff_ci95"]
        L.append(
            f"| {r['k']} | {r['risk_score']:.1%} | {r['severity_only']:.1%} | {r['random']:.1%} "
            f"| {r['diff']:+.1%} ({lo:+.1%} to {hi:+.1%}) |"
        )
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--label", default="run")
    s = sub.add_parser("score")
    s.add_argument("records", type=Path)
    a = ap.parse_args()
    if a.cmd == "collect":
        doc = collect(a.label)
        out = RESULTS / f"prioritization-owasp-{doc['measured']}-{a.label}.records.json"
        out.write_text(json.dumps(doc, indent=1) + "\n")
        print(f"wrote {out} ({len(doc['records'])} findings)")
        return 0
    doc = json.loads(a.records.read_text())
    ev = {"benchmark": doc["benchmark"], "measured": doc["measured"], **evaluate(doc["records"])}
    (a.records.parent / a.records.name.replace(".records.json", ".scores.json")).write_text(
        json.dumps(ev, indent=1) + "\n"
    )
    print(markdown(ev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
