"""OWASP Benchmark v1.2beta: fetch, scan, score.

    python -m benchmarks.owasp.run fetch                 # clone the pinned tag into the cache (~150 MB)
    python -m benchmarks.owasp.run scan  [--tools ...]   # run scanners, write predictions-<label>.json
    python -m benchmarks.owasp.run score predictions-....json [--out report.md]

The Benchmark is GPL-2.0 and is downloaded at run time only; nothing from it is committed. Only per-test
predictions (test name -> CWE ids) are saved, so scoring can be re-run without the scanners.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

from benchmarks.owasp.score import MATCHERS, RELATED, load_truth, score

ROOT = Path(__file__).resolve().parents[2]
CACHE = Path.home() / ".cache" / "bulwark-benchmarks"
REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava"
TAG = "1.2beta"
TRUTH_NAME = "expectedresults-1.2beta.csv"
EXPECTED_CASES = 2740
_TEST_FILE = re.compile(r"(BenchmarkTest\d{5})\.java$")


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def fetch(cache: Path = CACHE) -> Path:
    dest = cache / "BenchmarkJava"
    if not dest.exists():
        cache.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--branch", TAG, REPO, str(dest)],
            check=True,
        )
    truth = load_truth(dest / TRUTH_NAME)
    if len(truth) != EXPECTED_CASES:
        raise SystemExit(
            f"expected {EXPECTED_CASES} test cases, found {len(truth)}: wrong benchmark version?"
        )
    print(
        f"benchmark at {dest} ({len(truth)} cases, commit {_git('rev-parse', 'HEAD', cwd=dest)[:12]})"
    )
    return dest


def stage(bench: Path, dest: Path) -> Path:
    """Only the Java test cases and pom.xml: the repository also carries other tools' reference results."""
    src = bench / "src/main/java/org/owasp/benchmark/testcode"
    out = dest / "src/main/java/org/owasp/benchmark/testcode"
    if dest.exists():
        shutil.rmtree(dest)
    out.mkdir(parents=True)
    for f in src.glob("BenchmarkTest*.java"):
        shutil.copy(f, out / f.name)
    shutil.copy(bench / "pom.xml", dest / "pom.xml")
    return dest


def predictions_by_case(findings: list[Any]) -> tuple[dict[str, list[str]], int]:
    """{test name: sorted CWE ids} for findings in a test file, and how many findings were in no test file."""
    out: dict[str, set[str]] = {}
    other = 0
    for f in findings:
        m = _TEST_FILE.search(f.location.path)
        if not m:
            other += 1
            continue
        out.setdefault(m.group(1), set()).update(f.taxonomy.cwe)
    return {k: sorted(v) for k, v in sorted(out.items())}, other


def scan_tools(bench: Path, tools: list[str], label: str) -> dict[str, Any]:
    from core.scan import ADAPTERS, detect_context, execute_tool
    from core.source import materialize
    from core.taxonomy import enrich_all

    with __import__("tempfile").TemporaryDirectory() as tmp:
        staged = stage(bench, Path(tmp) / "stage")
        result: dict[str, Any] = {}
        with materialize(str(staged)) as ws:
            ctx = detect_context(ws)
            for name in tools:
                if not ADAPTERS[name].applies_to(ctx):
                    result[name] = {
                        "status": "not-applicable",
                        "predictions": {},
                        "unattributed_findings": 0,
                    }
                    continue
                t0 = time.monotonic()
                out = execute_tool(name, ws)
                preds, other = predictions_by_case(enrich_all(out.findings))
                result[name] = {
                    "status": out.status, "error": out.error, "duration_seconds": round(time.monotonic() - t0, 1),
                    "image": ADAPTERS[name].spec.image, "findings": len(out.findings),
                    "unattributed_findings": other, "predictions": preds,
                }  # fmt: skip
                print(
                    f"{name}: {out.status}, {len(out.findings)} findings, {len(preds)} test files flagged"
                )
    truth_csv = bench / TRUTH_NAME
    return {
        "benchmark": {"name": "OWASP Benchmark", "tag": TAG, "commit": _git("rev-parse", "HEAD", cwd=bench),
                      "cases": EXPECTED_CASES, "truth_sha256": hashlib.sha256(truth_csv.read_bytes()).hexdigest()},
        "measured": date.today().isoformat(), "label": label, "tools": result,
    }  # fmt: skip


def evaluate(doc: dict[str, Any], truth_csv: Path) -> dict[str, Any]:
    from benchmarks.owasp.score import ensemble

    truth = load_truth(truth_csv)
    ran = {t: v["predictions"] for t, v in doc["tools"].items() if v.get("status") == "ok"}
    # A tool that flagged nothing in any test file does not analyse Java code, so it is scored (as 0% recall) but
    # kept out of the ensemble: averaging in a tool with no coverage would only make agreement impossible.
    per_tool = {t: p for t, p in ran.items() if p}
    rows: dict[str, Any] = {}
    combos = dict(ran)
    ensemble_note = ""
    if len(per_tool) > 1:
        combos["ensemble (any tool)"] = ensemble(per_tool, 1)
        combos["ensemble (2+ tools agree)"] = ensemble(per_tool, 2)
    else:
        only = next(iter(per_tool), "none")
        ensemble_note = f"Not computed: only {len(per_tool)} tool ({only}) analyses these files, so an ensemble would equal it."
    for name, preds in combos.items():
        rows[name] = {}
        for matcher in MATCHERS:
            total, by_cat = score(truth, preds, matcher)
            rows[name][matcher] = {
                "overall": total.rates(),
                "by_category": {c: v.rates() for c, v in by_cat.items()},
            }
    return {"benchmark": doc["benchmark"], "measured": doc["measured"], "tools": rows, "ensemble_note": ensemble_note,
            "tool_status": {t: {k: v.get(k) for k in ("status", "duration_seconds", "findings", "unattributed_findings", "image")} for t, v in doc["tools"].items()},
            "related_cwes": {k: sorted(v) for k, v in RELATED.items()}}  # fmt: skip


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def markdown(ev: dict[str, Any]) -> str:
    L = [
        "| Tool | Matcher | Recall (TPR) | False-positive rate | Precision | F1 | Benchmark score (TPR-FPR) | TP / FP / TN / FN |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for tool, per in ev["tools"].items():
        for m in MATCHERS:
            r = per[m]["overall"]
            lo, hi = r["recall_ci"]
            L.append(
                f"| {tool} | {m} | {_pct(r['recall'])} ({_pct(lo)}-{_pct(hi)}) | {_pct(r['fpr'])} | {_pct(r['precision'])} | {_pct(r['f1'])} | {r['benchmark_score']:+.3f} | {r['tp']} / {r['fp']} / {r['tn']} / {r['fn']} |"
            )
    return "\n".join(L)


def category_markdown(ev: dict[str, Any], tool: str, matcher: str = "related") -> str:
    L = [
        "| Category | Real | Fake | Recall | False-positive rate | Score |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cat, r in ev["tools"][tool][matcher]["by_category"].items():
        L.append(
            f"| {cat} | {r['tp'] + r['fn']} | {r['fp'] + r['tn']} | {_pct(r['recall'])} | {_pct(r['fpr'])} | {r['benchmark_score']:+.3f} |"
        )
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    p = sub.add_parser("scan")
    p.add_argument("--tools", default="semgrep,bandit,gitleaks,trivy,osv-scanner")
    p.add_argument("--label", default="run")
    p.add_argument("--cache", type=Path, default=CACHE)
    p = sub.add_parser("score")
    p.add_argument("predictions", type=Path)
    p.add_argument("--truth", type=Path, default=None)
    p.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch()
    elif args.cmd == "scan":
        bench = fetch(args.cache)
        doc = scan_tools(bench, [t.strip() for t in args.tools.split(",") if t.strip()], args.label)
        out = (
            ROOT
            / "benchmarks"
            / "results"
            / f"owasp-{TAG}-{doc['measured']}-{args.label}.predictions.json"
        )
        out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(f"wrote {out}")
    else:
        doc = json.loads(args.predictions.read_text())
        truth = args.truth or (CACHE / "BenchmarkJava" / TRUTH_NAME)
        ev = evaluate(doc, truth)
        text = json.dumps(ev, indent=1, sort_keys=True) + "\n"
        (args.out or args.predictions.with_suffix("")).with_suffix(".scores.json").write_text(text)
        print(markdown(ev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
