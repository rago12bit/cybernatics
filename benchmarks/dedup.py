"""Baseline deduplication benchmark (design doc §10.2 metric 1).

Deduplication rate = 1 - unique/raw over a repository set, where `raw` is the sum of every tool's
findings and `unique` is what remains after cross-tool correlation.
Reproduce with benchmarks/run.sh.
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path

from core.correlation import correlate
from core.correlation import engine as eng
from core.scan import ADAPTERS, DEFAULT_TOOLS, ScanResult, detect_context, scan
from core.source import materialize

REPOS = [
    ("VAmPI", "https://github.com/erev0s/VAmPI"),
    ("NodeGoat", "https://github.com/OWASP/NodeGoat"),
    ("nodejs-goof", "https://github.com/snyk-labs/nodejs-goof"),
    ("Vulnerable-Flask-App", "https://github.com/we45/Vulnerable-Flask-App"),
    ("terragoat", "https://github.com/bridgecrewio/terragoat"),
]
ROOT = Path(__file__).resolve().parent


def measure(name: str, source: str) -> dict[str, object]:
    t0 = time.monotonic()
    try:
        with materialize(source) as ws:
            ctx = detect_context(ws)
            result: ScanResult = scan(ws, list(DEFAULT_TOOLS))
            # scan() already correlated; recompute raw per tool from tool_status.
    except Exception as exc:  # noqa: BLE001 - a repo that can't be scanned is a data point
        return {"repo": name, "source": source, "error": f"{type(exc).__name__}: {exc}"}
    per_tool = {t: v.get("findings", 0) for t, v in result.tool_status.items()}
    merged = [f for f in result.findings if f.evidence.agreement_count > 1]
    return {
        "repo": name,
        "source": source,
        "languages": sorted(ctx.languages),
        "wall_seconds": round(time.monotonic() - t0, 1),
        "tool_status": {t: v["status"] for t, v in result.tool_status.items()},
        "raw_findings": result.stats.raw,
        "unique_findings": result.stats.unique,
        "dedup_rate": round(result.stats.dedup_rate, 4),
        "raw_per_tool": per_tool,
        "cross_tool_merged": len(merged),
        "by_category": dict(Counter(f.taxonomy.category.value for f in result.findings)),
    }


def main() -> None:
    label = sys.argv[1] if len(sys.argv) > 1 else "run"
    rows = [measure(n, u) for n, u in REPOS]
    ok = [r for r in rows if "error" not in r]
    raw = sum(int(r["raw_findings"]) for r in ok)  # type: ignore[call-overload]
    uniq = sum(int(r["unique_findings"]) for r in ok)  # type: ignore[call-overload]
    out = {
        "label": label,
        "measured_on": date.today().isoformat(),
        "corpus": "5 public repos (see repos[].source), scanned at default branch HEAD",
        "correlation_params": {
            "line_window": eng.LINE_WINDOW,
            "snippet_overlap": eng.SNIPPET_OVERLAP,
            "min_tokens": eng.MIN_TOKENS,
        },
        "images": {n: a.spec.image for n, a in ADAPTERS.items()},
        "repos": rows,
        "aggregate": {
            "repos_scanned": len(ok),
            "raw_findings": raw,
            "unique_findings": uniq,
            "dedup_rate": round(1 - uniq / raw, 4) if raw else None,
        },
    }
    path = ROOT / "results" / f"dedup-{out['measured_on']}-{label}.json"
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out["aggregate"], indent=2), file=sys.stderr)
    print(f"wrote {path}", file=sys.stderr)


_ = correlate

if __name__ == "__main__":
    main()
