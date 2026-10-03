"""Ingest throughput and memory (plan §60 "Ingest": findings per second and peak memory on a
100 MB report; large Nessus and SARIF files).

    python -m benchmarks.ingest_throughput --mb 100            # build the files, measure, print JSON
    python -m benchmarks.ingest_throughput --mb 100 --keep     # keep the generated files in /tmp

There is no 100 MB real report to hand, so the files are *tiled from real ones*: a real Nessus
`ReportHost` (the DefectDojo sample `nessus_with_cvssv3.nessus`) repeated under distinct host names,
and a real Semgrep SARIF result repeated across distinct files. That scales the volume faithfully
-- real element shapes, real text sizes -- but it is not a real 100 MB scan: its findings are more
uniform than a real one's, which flatters correlation, so read the numbers as a floor for parsing
and an optimistic figure for `prepare`.

Each measurement runs in a fresh child process so peak memory is that stage's alone:

* **parse (streamed)**: the parser's own throughput and memory, findings counted and dropped;
* **parse + prepare**: the whole path an import takes before it touches the database (redact,
  correlate, score), with every finding kept, which is what the worker holds;
* **parse + prepare + apply** (with `--db`): the whole import, written to a real Postgres as the
  non-superuser worker role under Row-Level Security -- the number a user waits for.
"""

from __future__ import annotations

import argparse
import json
import re
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NESSUS_SAMPLE = ROOT / "tests/golden/ingest/defectdojo/nessus/nessus_with_cvssv3.nessus"
SARIF_SAMPLE = ROOT / "tests/golden/semgrep/raw.json"


def build_nessus(path: Path, target_bytes: int) -> int:
    """A `.nessus` file of about `target_bytes`: the sample's first host, repeated."""
    raw = NESSUS_SAMPLE.read_text(encoding="utf-8")
    start = raw.index("<ReportHost")
    end = raw.index("</ReportHost>", start) + len("</ReportHost>")
    head, block, tail = raw[:start], raw[start:end], raw[raw.index("</Report>") :]
    items = block.count("<ReportItem")
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        fh.write(head)
        while fh.tell() < target_bytes:
            fh.write(
                re.sub(
                    r'name="[^"]*"',
                    f'name="10.{n // 65536}.{n // 256 % 256}.{n % 256}"',
                    block,
                    count=1,
                )
            )
            n += 1
        fh.write(tail)
    return n * items


def build_sarif(path: Path, target_bytes: int) -> int:
    doc = json.loads(SARIF_SAMPLE.read_text())
    run = doc["runs"][0]
    template = run["results"]
    run["results"] = []
    text = json.dumps(doc)
    cut = text.index('"results": []')
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        fh.write(text[:cut] + '"results": [')
        while fh.tell() < target_bytes:
            for r in template:
                clone = json.loads(json.dumps(r))
                loc = clone["locations"][0]["physicalLocation"]
                loc["artifactLocation"]["uri"] = f"src/pkg{n % 4000}/file{n}.py"
                fh.write(("," if n else "") + json.dumps(clone))
                n += 1
        fh.write("]" + text[cut + len('"results": []') :])
    return n


def _apply(findings: list, parser: str, url: str) -> None:
    """Write one import to Postgres exactly as the worker does: its own org, asset and Test."""
    import uuid

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from core.imports.service import apply_import
    from core.persistence import repo
    from core.tenancy import set_session_org

    engine = create_engine(url)
    sessions = sessionmaker(engine, expire_on_commit=False)
    org = f"bench-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, 'bench', now())"),
            {"id": org},
        )
        s.commit()
    with sessions() as s:
        set_session_org(s, org)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="bench/x", org_id=org)
        eng = repo.create_engagement(
            s, org_id=org, asset_id=asset.id, name="bench", engagement_type="import"
        )
        test = repo.get_or_create_engagement_test(s, org_id=org, engagement_id=eng.id, name="t")
        apply_import(
            s, org_id=org, test_id=test.id, findings=findings, parser=parser,
            file_digest=uuid.uuid4().hex * 2, file_name="bench",
        )  # fmt: skip
        s.execute(text("SELECT 1"))
    engine.dispose()


def child(stage: str, parser: str, path: Path, db: str = "") -> None:
    from core.imports.parsers import get_parser
    from core.imports.parsers.base import ParseContext
    from core.imports.prepare import prepare

    p = get_parser(parser)
    ctx = ParseContext()
    started = time.monotonic()
    with path.open("rb") as fh:
        if stage == "parse":
            count = sum(1 for _ in p.parse(fh, ctx))
        else:
            findings = list(p.parse(fh, ctx))
            count = len(findings)
            if not ctx.error:
                findings = prepare(findings)
                count = len(findings)
                if stage == "parse+prepare+apply":
                    _apply(findings, parser, db)
    seconds = time.monotonic() - started
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mb = rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024
    print(
        json.dumps({"findings": count, "seconds": seconds, "peak_mb": peak_mb, "error": ctx.error})
    )


def measure(stage: str, parser: str, path: Path, db: str = "") -> dict:
    out = subprocess.run(
        [sys.executable, "-m", "benchmarks.ingest_throughput", "--child", stage, parser, str(path),
         *(["--db", db] if db else [])],
        capture_output=True, text=True, cwd=ROOT, check=True,
    )  # fmt: skip
    r = json.loads(out.stdout.strip().splitlines()[-1])
    r["findings_per_second"] = r["findings"] / r["seconds"] if r["seconds"] else 0
    return r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=int, default=100)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--out", type=Path, help="write the results here as JSON")
    ap.add_argument("--db", default="", help="SQLAlchemy URL of a migrated Postgres (worker role)")
    ap.add_argument("--child", nargs=3, metavar=("STAGE", "PARSER", "PATH"))
    args = ap.parse_args()
    if args.child:
        child(args.child[0], args.child[1], Path(args.child[2]), args.db)
        return 0

    work = Path(tempfile.mkdtemp(prefix="bulwark-ingest-bench-"))
    results = []
    for label, parser, build, name in (
        ("Nessus XML", "nessus", build_nessus, "big.nessus"),
        ("SARIF", "sarif", build_sarif, "big.sarif"),
    ):
        path = work / name
        expected = build(path, args.mb * 1024 * 1024)
        size = path.stat().st_size / (1024 * 1024)
        for stage in ("parse", "parse+prepare", *(["parse+prepare+apply"] if args.db else [])):
            r = measure(stage, parser, path, args.db)
            results.append(
                {"file": label, "mb": round(size, 1), "records": expected, "stage": stage, **r}
            )
            print(json.dumps(results[-1]), flush=True)
    if args.out:
        import platform

        args.out.write_text(
            json.dumps(
                {"date": time.strftime("%Y-%m-%d"), "machine": platform.platform(),
                 "python": platform.python_version(), "database": "postgres" if args.db else None,
                 "results": results},
                indent=1,
            ) + "\n"
        )  # fmt: skip
    if not args.keep:
        for f in work.iterdir():
            f.unlink()
        work.rmdir()
    return 0


if __name__ == "__main__":
    sys.exit(main())
