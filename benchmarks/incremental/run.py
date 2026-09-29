"""Incremental scanning (plan §20.1/§36): median PR scan time against a full scan.

    python -m benchmarks.incremental.run --repo NodeGoat --reps 3

Methodology: clone the repo once, run one full (cold-cache) scan, then simulate a pull request by
editing a small, fixed number of files and rescanning with the *same* cache directory, repeated
`--reps` times for a median. This is one repository, not the full plan §34 evaluation ("replay the
last 20 merged PRs of each repository in the 30-repository corpus") -- that is a separate, larger
evaluation task; this is the narrower thing Week 36 itself asks to measure.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from core.cache import ResultCache  # noqa: E402
from core.gitfetch import clone_repo  # noqa: E402
from core.scan import DEFAULT_TOOLS, scan  # noqa: E402

CLONE_CACHE = Path.home() / ".cache" / "bulwark-benchmarks" / "incremental"
CORPUS = json.loads((ROOT / "benchmarks" / "corpus" / "corpus.json").read_text())


def _repo(name: str) -> dict[str, Any]:
    return next(r for r in CORPUS["repos"] if r["name"] == name)


def _checkout(repo: dict[str, Any]) -> Path:
    dest = CLONE_CACHE / repo["name"]
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    return clone_repo(repo["url"], dest, ref=None)


def _simulate_pr(root: Path, n_files: int) -> list[Path]:
    """Touch `n_files` existing source files (append a harmless comment line), the way a small
    pull request would -- a real diff, not a synthetic one, so the cache genuinely has to
    recompute exactly these files' results and nothing else."""
    candidates = sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix in (".js", ".py", ".ts") and "node_modules" not in p.parts
    )
    if len(candidates) < n_files:
        raise SystemExit(f"repo has only {len(candidates)} eligible files, need {n_files}")
    touched = candidates[:n_files]
    for p in touched:
        line = "# bench-touch\n" if p.suffix == ".py" else "// bench-touch\n"
        with p.open("a") as fh:
            fh.write(line)
    return touched


def run(repo_name: str, reps: int, n_files: int) -> dict[str, Any]:
    repo = _repo(repo_name)
    print(f"cloning {repo_name} at {repo['commit'][:12]}...")
    root = _checkout(repo)
    cache_dir = CLONE_CACHE / f"{repo_name}-cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)  # start cold, every run of this script
    cache = ResultCache(cache_dir)
    tools = list(DEFAULT_TOOLS)

    print("full scan (cold cache)...")
    start = time.monotonic()
    cold_result = scan(root, tools, cache=cache)
    cold_seconds = time.monotonic() - start
    print(f"  {cold_seconds:.1f}s, {len(cold_result.findings)} findings, cache hits={cache.hits}")

    warm_seconds: list[float] = []
    for i in range(reps):
        touched = _simulate_pr(root, n_files)
        start = time.monotonic()
        warm_result = scan(root, tools, cache=cache)
        elapsed = time.monotonic() - start
        warm_seconds.append(elapsed)
        print(
            f"  rep {i + 1}/{reps}: {elapsed:.1f}s, {len(warm_result.findings)} findings, "
            f"{len(touched)} file(s) touched, cache hits={cache.hits}, misses={cache.misses}"
        )

    median_warm = statistics.median(warm_seconds)
    return {
        "repo": repo_name,
        "commit": repo["commit"],
        "tools": tools,
        "files_touched_per_rep": n_files,
        "cold_full_scan_seconds": round(cold_seconds, 1),
        "warm_pr_scan_seconds": [round(s, 1) for s in warm_seconds],
        "median_warm_pr_scan_seconds": round(median_warm, 1),
        "speedup": round(cold_seconds / median_warm, 1) if median_warm else None,
        "measured_on": date.today().isoformat(),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", default="NodeGoat")
    p.add_argument("--reps", type=int, default=3)
    p.add_argument("--files-touched", type=int, default=3, dest="n_files")
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()

    result = run(args.repo, args.reps, args.n_files)
    print(json.dumps(result, indent=2))
    out = args.out or (
        ROOT
        / "benchmarks"
        / "results"
        / f"incremental-{result['measured_on']}-{args.repo.lower()}.json"
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
