"""NIST Juliet Test Suite for Java v1.3: fetch, scan, score.

    python -m benchmarks.juliet.run fetch                 # 77 MB from NIST SARD, verified by SHA-256
    python -m benchmarks.juliet.run scan --label v1       # stage the security CWEs, run Semgrep, save per-case results
    python -m benchmarks.juliet.run score <predictions.json.gz>

Juliet is a NIST work (public domain in the US). It is downloaded at run time and never committed here. Only the
security-relevant CWE directories are scanned (see CWES): the arithmetic, null-pointer and resource CWEs are outside
what a security scanner claims to find.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

from benchmarks.juliet.regions import extract_regions, region_of
from benchmarks.juliet.score import MATCHERS, RELATED, score_cases

ROOT = Path(__file__).resolve().parents[2]
CACHE = Path.home() / ".cache" / "bulwark-benchmarks" / "juliet"
URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip"
SHA256 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
SIZE = 76_798_417
TESTCASES = "Java/src/testcases"
CWES = sorted(RELATED)  # the security CWE directories that are scored
CHUNK = 1500
SCAFFOLDING = {"Main.java", "ServletMain.java"}


def fetch(cache: Path = CACHE) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    zpath = cache / "juliet-java-1.3.zip"
    if not zpath.exists():
        print(f"downloading {URL} (about {SIZE // 1_000_000} MB)")
        try:
            with (
                urllib.request.urlopen(URL, timeout=120) as resp,
                zpath.open("wb") as out,
            ):  # noqa: S310
                while chunk := resp.read(1 << 20):
                    out.write(chunk)
        except OSError:  # some Python builds lack a usable CA bundle; curl uses the system one
            subprocess.run(["curl", "-fsSL", "-o", str(zpath), URL], check=True)
    digest = hashlib.sha256(zpath.read_bytes()).hexdigest()
    if digest != SHA256:
        raise SystemExit(f"checksum mismatch for {zpath.name}: got {digest}")
    root = cache / "src"
    if not (root / TESTCASES).is_dir():
        with zipfile.ZipFile(zpath) as z:
            for (
                name
            ) in z.namelist():  # refuse anything that would land outside the target directory
                if name.startswith("/") or ".." in Path(name).parts:
                    raise SystemExit(f"unsafe path in archive: {name}")
            z.extractall(root)
    print(f"juliet at {root / TESTCASES}")
    return root / TESTCASES


def selected_dirs(testcases: Path) -> dict[int, Path]:
    out: dict[int, Path] = {}
    for d in sorted(testcases.iterdir()):
        head = d.name.split("_", 1)[0].removeprefix("CWE")
        if d.is_dir() and head.isdigit() and int(head) in RELATED:
            out[int(head)] = d
    return out


def build_cases(
    testcases: Path, staged: Path, findings: list[Any]
) -> tuple[dict[str, dict[str, Any]], int]:
    """Attribute each finding to a side (bad/good) of a file and return {case id: verdict + what was reported}."""
    by_file: dict[str, list[Any]] = {}
    for f in findings:
        by_file.setdefault(f.location.path, []).append(f)
    cases: dict[str, dict[str, Any]] = {}
    outside = 0
    for cwe, d in selected_dirs(testcases).items():
        for src in sorted(d.rglob("*.java")):
            if src.name in SCAFFOLDING:
                continue
            rel = src.relative_to(testcases).as_posix()
            regions = extract_regions(src.read_text(errors="replace"), src.name)
            reported: dict[str, set[str] | None] = {"bad": None, "good": None}
            for f in by_file.get(f"{TESTCASES.split('/', 1)[1]}/{rel}", []):
                side = region_of(f.location.start_line, f.location.end_line, regions)
                if side is None:
                    outside += 1
                    continue
                reported[side] = (reported[side] or set()) | set(f.taxonomy.cwe)
            for side in ("bad", "good"):
                if regions[side]:
                    got = reported[side]
                    cases[f"{rel}#{side}"] = {"cwe": cwe, "vulnerable": side == "bad",
                                              "reported": None if got is None else sorted(got)}  # fmt: skip
    return cases, outside


def scan(testcases: Path, label: str) -> dict[str, Any]:
    from core.scan import ADAPTERS, execute_tool
    from core.source import materialize
    from core.taxonomy import enrich_all

    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "stage" / "src" / "testcases"
        for d in selected_dirs(testcases).values():
            for f in d.rglob("*.java"):
                if f.name in SCAFFOLDING:
                    continue
                dest = staged / f.relative_to(testcases)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(f.read_bytes())
        n = sum(1 for _ in staged.rglob("*.java"))
        print(f"staged {n} files from {len(selected_dirs(testcases))} CWE directories")
        t0 = time.monotonic()
        files = sorted(staged.rglob("*.java"))
        findings, statuses = [], []
        # One scan of everything exceeds the tool's 900 s wall clock, so scan in chunks.
        for i in range(0, len(files), CHUNK):
            chunk = Path(tmp) / f"chunk{i // CHUNK}" / "src" / "testcases"
            for f in files[i : i + CHUNK]:
                dest = chunk / f.relative_to(staged)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(f, dest)
            with materialize(str(chunk.parents[1])) as ws:
                out = execute_tool("semgrep", ws)
            print(f"  chunk {i // CHUNK + 1}: {out.status}, {len(out.findings)} findings, "
                  f"{out.duration_seconds or 0:.0f}s", flush=True)  # fmt: skip
            statuses.append(out.status)
            findings += out.findings
            shutil.rmtree(chunk.parents[1], ignore_errors=True)
        status = (
            "ok"
            if all(x == "ok" for x in statuses)
            else "partial:" + ",".join(sorted(set(statuses)))
        )
        findings = enrich_all(findings)
        cases, outside = build_cases(testcases, staged, findings)
    print(
        f"semgrep: {status}, {len(findings)} findings ({outside} outside any bad/good method), {len(cases)} cases"
    )
    return {
        "suite": {"name": "Juliet Test Suite for Java", "version": "1.3", "sha256": SHA256, "source": URL,
                  "files_scanned": n, "cwe_directories": CWES},
        "measured": date.today().isoformat(), "label": label,
        "tool": {"name": "semgrep", "image": ADAPTERS["semgrep"].spec.image, "status": status, "chunks": len(statuses),
                 "seconds": round(time.monotonic() - t0, 1), "findings": len(findings), "outside_regions": outside},
        "cases": cases,
    }  # fmt: skip


def evaluate(doc: dict[str, Any]) -> dict[str, Any]:
    res: dict[str, Any] = {}
    for m in MATCHERS:
        total, by_cwe = score_cases(doc["cases"], m)
        res[m] = {
            "overall": total.rates(),
            "by_cwe": {str(k): v.rates() for k, v in by_cwe.items()},
        }
    return {"suite": doc["suite"], "measured": doc["measured"], "tool": doc["tool"], "results": res}


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def cwe_table(ev: dict[str, Any], matcher: str = "related") -> str:
    L = [
        "| CWE | Real | Safe | Detection rate (recall) | False-alarm rate | Score |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cwe, r in ev["results"][matcher]["by_cwe"].items():
        L.append(
            f"| CWE-{cwe} | {r['tp'] + r['fn']} | {r['fp'] + r['tn']} | {_pct(r['recall'])} | {_pct(r['fpr'])} | {r['benchmark_score']:+.2f} |"
        )
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    p = sub.add_parser("scan")
    p.add_argument("--label", default="run")
    p = sub.add_parser("score")
    p.add_argument("predictions", type=Path)
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch()
    elif args.cmd == "scan":
        doc = scan(fetch(), args.label)
        out = (
            ROOT
            / "benchmarks"
            / "results"
            / f"juliet-java-1.3-{doc['measured']}-{args.label}.predictions.json.gz"
        )
        out.write_bytes(gzip.compress(json.dumps(doc, sort_keys=True).encode()))
        print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    else:
        doc = json.loads(gzip.decompress(args.predictions.read_bytes()))
        ev = evaluate(doc)
        out = args.predictions.with_name(
            args.predictions.name.replace(".predictions.json.gz", ".scores.json")
        )
        out.write_text(json.dumps(ev, indent=1, sort_keys=True) + "\n")
        o = ev["results"]["related"]["overall"]
        print(
            f"related: recall {_pct(o['recall'])}, false-alarm {_pct(o['fpr'])}, score {o['benchmark_score']:+.3f}"
        )
        print(cwe_table(ev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
