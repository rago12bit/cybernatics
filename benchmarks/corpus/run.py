"""A curated corpus of 25 public repositories: deduplication rate, wall time and crash rate.

    python -m benchmarks.corpus.run pin              # resolve each repo's default-branch HEAD and write it into corpus.json
    python -m benchmarks.corpus.run fetch            # fetch every repo at its pinned commit (shallow) into the cache
    python -m benchmarks.corpus.run scan --label v1  # run the default scanners on each, one repo at a time
    python -m benchmarks.corpus.run report <results.json>

Repositories are scanned one at a time, alone on the machine: wall time is only meaningful that way. A repository
that cannot be scanned is a data point (recorded with its error), not something to drop.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("corpus.json")
CACHE = Path.home() / ".cache" / "bulwark-benchmarks" / "corpus"
FAILED = {"error", "timeout"}


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text())  # type: ignore[no-any-return]


def pin() -> None:
    doc = load_manifest()
    for r in doc["repos"]:
        out = subprocess.run(
            ["git", "ls-remote", r["url"], "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        r["commit"] = out.stdout.split()[0]
        print(f"{r['name']:30} {r['commit'][:12]}")
    doc["pinned_on"] = date.today().isoformat()
    MANIFEST.write_text(json.dumps(doc, indent=2) + "\n")


def fetch_repo(r: dict[str, Any], cache: Path = CACHE) -> Path:
    """Shallow-fetch exactly the pinned commit (GitHub serves any reachable sha)."""
    dest = cache / r["name"]
    if (dest / ".git").exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    for args in (
        ["init", "-q"],
        ["remote", "add", "origin", r["url"]],
        ["fetch", "-q", "--depth", "1", "origin", r["commit"]],
        ["checkout", "-q", "FETCH_HEAD"],
    ):
        subprocess.run(["git", *args], cwd=dest, check=True, capture_output=True, timeout=600)
    return dest


def measure(r: dict[str, Any], path: Path) -> dict[str, Any]:
    from core.scan import DEFAULT_TOOLS, detect_context, scan
    from core.source import materialize

    t0 = time.monotonic()
    row: dict[str, Any] = {"repo": r["name"], "kind": r["kind"], "commit": r["commit"]}
    try:
        with materialize(str(path)) as ws:
            ctx = detect_context(ws)
            files = sum(1 for p in ws.rglob("*") if p.is_file())
            result = scan(ws, list(DEFAULT_TOOLS))
    except Exception as exc:  # noqa: BLE001 - a repo that cannot be scanned is a data point
        return {
            **row,
            "error": f"{type(exc).__name__}: {exc}",
            "wall_seconds": round(time.monotonic() - t0, 1),
        }
    merged = [f for f in result.findings if f.evidence.agreement_count > 1]
    return {
        **row, "languages": sorted(ctx.languages), "files": files, "wall_seconds": round(time.monotonic() - t0, 1),
        "tool_status": {t: {"status": v["status"], "seconds": v.get("duration_seconds"), "findings": v.get("findings", 0)} for t, v in result.tool_status.items()},
        "raw_findings": result.stats.raw, "unique_findings": result.stats.unique,
        "dedup_rate": round(result.stats.dedup_rate, 4), "cross_tool_merged": len(merged),
        "by_severity": dict(Counter(f.scoring.normalized_severity.value for f in result.findings)),
        "by_category": dict(Counter(f.taxonomy.category.value for f in result.findings)),
    }  # fmt: skip


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rows if "error" not in r]
    runs = [
        (r["repo"], t, v["status"])
        for r in ok
        for t, v in r["tool_status"].items()
        if v["status"] != "skipped"
    ]
    failed = [x for x in runs if x[2] in FAILED]

    def dedup(rs: list[dict[str, Any]]) -> float | None:
        raw, uniq = sum(r["raw_findings"] for r in rs), sum(r["unique_findings"] for r in rs)
        return round(1 - uniq / raw, 4) if raw else None

    walls = sorted(r["wall_seconds"] for r in ok)
    return {
        "repos": len(rows), "scanned": len(ok), "scan_level_failures": [r["repo"] for r in rows if "error" in r],
        "tool_runs": len(runs), "tool_run_failures": [{"repo": a, "tool": b, "status": c} for a, b, c in failed],
        "crash_rate": round(len(failed) / len(runs), 4) if runs else None,
        "raw_findings": sum(r["raw_findings"] for r in ok), "unique_findings": sum(r["unique_findings"] for r in ok),
        "dedup_rate_pooled": dedup(ok),
        "dedup_rate_median": round(statistics.median(r["dedup_rate"] for r in ok), 4) if ok else None,
        "dedup_rate_by_kind": {k: dedup([r for r in ok if r["kind"] == k]) for k in ("vulnerable", "real")},
        "wall_seconds": {"total": round(sum(walls), 1), "median": statistics.median(walls) if walls else None,
                         "max": walls[-1] if walls else None, "p90": walls[int(0.9 * (len(walls) - 1))] if walls else None},
    }  # fmt: skip


def table(rows: list[dict[str, Any]]) -> str:
    L = [
        "| Repository | Kind | Languages | Files | Raw | Unique | Dedup | Merged across tools | Wall time |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        if "error" in r:
            L.append(f"| {r['repo']} | {r['kind']} | | | | | | | **failed: {r['error'][:60]}** |")
        else:
            L.append(
                f"| {r['repo']} | {r['kind']} | {', '.join(r['languages']) or '-'} | {r['files']} | {r['raw_findings']} | {r['unique_findings']} | {r['dedup_rate']:.1%} | {r['cross_tool_merged']} | {r['wall_seconds']:.0f}s |"
            )
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pin")
    sub.add_parser("fetch")
    p = sub.add_parser("scan")
    p.add_argument("--label", default="run")
    p = sub.add_parser("report")
    p.add_argument("results", type=Path)
    args = ap.parse_args()
    if args.cmd == "pin":
        pin()
    elif args.cmd == "fetch":
        for r in load_manifest()["repos"]:
            print(f"{r['name']}: {fetch_repo(r)}")
    elif args.cmd == "scan":
        from core.scan import ADAPTERS, DEFAULT_TOOLS

        doc = load_manifest()
        rows = []
        for r in doc["repos"]:
            row = measure(r, fetch_repo(r))
            rows.append(row)
            print(
                f"{r['name']}: "
                + (
                    row.get("error")
                    or f"{row['unique_findings']} unique, {row['dedup_rate']:.1%} dedup, {row['wall_seconds']}s"
                ),
                flush=True,
            )
        out = {"label": args.label, "measured": date.today().isoformat(), "pinned_on": doc.get("pinned_on"),
               "images": {n: ADAPTERS[n].spec.image for n in DEFAULT_TOOLS}, "repos": rows, "aggregate": aggregate(rows)}  # fmt: skip
        path = ROOT / "benchmarks" / "results" / f"corpus-{out['measured']}-{args.label}.json"
        path.write_text(json.dumps(out, indent=1) + "\n")
        print(json.dumps(out["aggregate"], indent=1))
        print(f"wrote {path}")
    else:
        doc = json.loads(args.results.read_text())
        print(table(doc["repos"]))
        print(json.dumps(doc["aggregate"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
