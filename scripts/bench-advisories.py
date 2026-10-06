#!/usr/bin/env python3
"""The advisory engine at scale, on Postgres under forced RLS (plan §46.2, journey J7).

Ingests OSV dumps through `feeds.update_osv`, then records N projects' SBOMs -- real package names
from the advisory data at real affected and fixed versions, mixed with packages no advisory names
-- each of which runs matching, and times: ingesting, recording plus matching, a full match of the
organization, the morning list, and the impact view of the most widespread vulnerability.

    BULWARK_BENCH_OWNER_URL=postgresql+psycopg://bulwark:...@localhost:55432/bulwark \
    BULWARK_BENCH_APP_URL=postgresql+psycopg://bulwark_worker:...@localhost:55432/bulwark \
    python scripts/bench-advisories.py --zips DIR --projects 300 --packages 1000

It deletes the organization it created; the advisories stay (they are shared, public data).
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, func, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from core import inventory  # noqa: E402
from core.advisories import feeds, impact, view  # noqa: E402
from core.advisories.osv import ECOSYSTEMS  # noqa: E402
from core.persistence import repo  # noqa: E402
from core.persistence.models import AdvisoryImpact, AdvisoryPackage  # noqa: E402
from core.tenancy import set_session_org  # noqa: E402

PURL = {"pypi": "pkg:pypi/{}@{}", "npm": "pkg:npm/{}@{}", "go": "pkg:golang/{}@v{}", "maven": "pkg:maven/{}@{}"}  # fmt: skip


def purl(eco: str, name: str, version: str) -> str:
    if eco == "maven":
        name = name.replace(":", "/", 1)
    if eco == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    return PURL[eco].format(name, version.removeprefix("v") if eco == "go" else version)


def measure(s: Any, org: str) -> None:
    opened = s.scalar(select(func.count()).select_from(AdvisoryImpact).where(AdvisoryImpact.resolved_at.is_(None)))  # fmt: skip
    vulns = s.scalar(select(func.count(func.distinct(AdvisoryImpact.vuln_key))))
    print(f"{opened} open impacts, {vulns} vulnerabilities")
    for name, fn in (("morning list", lambda: view.listing(s, org, limit=100)),
                     ("morning list, known exploited only", lambda: view.listing(s, org, kev_only=True)),
                     ("morning list, search 'log4j'", lambda: view.listing(s, org, q="log4j"))):  # fmt: skip
        fn()
        ms = []
        for _ in range(5):
            t = time.perf_counter()
            rows = fn()
            ms.append((time.perf_counter() - t) * 1000)
        print(f"{name}: p50 {statistics.median(ms):.0f} ms ({len(rows)} rows)")
    top = s.execute(
        select(AdvisoryImpact.vuln_key, func.count(func.distinct(AdvisoryImpact.asset_id)))
        .group_by(AdvisoryImpact.vuln_key).order_by(func.count(func.distinct(AdvisoryImpact.asset_id)).desc()).limit(1)
    ).one()  # fmt: skip
    ms = []
    for _ in range(5):
        t = time.perf_counter()
        v = view.impact(s, org, top[0])
        ms.append((time.perf_counter() - t) * 1000)
    print(f"impact view of {top[0]} ({top[1]} projects, {len(v['uses']) if v else 0} uses): p50 {statistics.median(ms):.0f} ms")  # fmt: skip


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zips", type=Path, required=True)
    ap.add_argument("--projects", type=int, default=300)
    ap.add_argument("--packages", type=int, default=1000)
    ap.add_argument("--affected-share", type=float, default=0.3)
    ap.add_argument("--keep", action="store_true", help="leave the organization in place")
    ap.add_argument("--org", help="only measure an organization a --keep run left")
    args = ap.parse_args()
    owner = create_engine(os.environ["BULWARK_BENCH_OWNER_URL"])
    app = sessionmaker(create_engine(os.environ["BULWARK_BENCH_APP_URL"]), expire_on_commit=False)

    if args.org:
        with app() as s:
            set_session_org(s, args.org)
            measure(s, args.org)
        return 0
    with app() as s:
        for eco in ECOSYSTEMS:
            t = time.perf_counter()
            run = feeds.update_osv(s, eco, zip_path=args.zips / f"{eco}-all.zip")
            print(f"ingest {eco:6s} {run.seen:7d} records, {len(run.changed):7d} written in {time.perf_counter() - t:6.1f}s", flush=True)  # fmt: skip
        pool = [
            (eco, name, d)
            for eco, name, d in s.execute(
                select(AdvisoryPackage.ecosystem, AdvisoryPackage.name, AdvisoryPackage.data)
                .where(AdvisoryPackage.ecosystem.in_(["pypi", "npm", "go", "maven"]))
                .order_by(AdvisoryPackage.id)
                .limit(200000)
            )
        ]
    rng = random.Random(68)
    candidates = []
    for eco, name, d in pool:
        versions = [v for r in d.get("ranges") or [] for k, v in r["events"] if k in ("introduced", "fixed") and v != "0"]  # fmt: skip
        versions += (d.get("versions") or [])[:3]
        if versions:
            candidates.append((eco, name, versions))
    print(f"{len(candidates)} advisory packages with versions to draw from", flush=True)

    org = f"bench-adv-{uuid.uuid4().hex[:8]}"
    with owner.begin() as c:
        c.execute(text("INSERT INTO organizations (id, name, created_at) VALUES (:o, 'bench', now())"), {"o": org})  # fmt: skip
    try:
        times = []
        with app() as s:
            set_session_org(s, org)
            for p in range(args.projects):
                n_aff = int(args.packages * args.affected_share)
                pkgs = []
                for eco, name, versions in rng.sample(candidates, n_aff):
                    pkgs.append({"purl": purl(eco, name, rng.choice(versions))})
                pkgs += [{"purl": f"pkg:npm/bench-lib-{rng.randint(0, 30000)}@1.{rng.randint(0, 9)}.0"} for _ in range(args.packages - n_aff)]  # fmt: skip
                sc = repo.create_scan(s, source_type="git", source_ref=f"https://example.com/p/{p}",
                                      source_label=f"bench/p{p}", tools=["syft"], org_id=org)  # fmt: skip
                assert sc.asset_id is not None
                t = time.perf_counter()
                inventory.record(s, org_id=org, asset_id=sc.asset_id, scan_id=sc.id, source="scan", packages=pkgs)  # fmt: skip
                times.append(time.perf_counter() - t)
                if p % 50 == 49:
                    print(f"  {p + 1} projects; record+match p50 {statistics.median(times):.2f}s", flush=True)  # fmt: skip
            times.sort()
            print(f"recorded {args.projects} SBOMs of {args.packages} packages: record+match p50 {statistics.median(times):.2f}s, p95 {times[int(len(times) * 0.95)]:.2f}s")  # fmt: skip
            t = time.perf_counter()
            full = impact.match(s, org)
            print(f"full match of the organization: {time.perf_counter() - t:.1f}s ({full.opened} opened, {full.resolved} resolved)")  # fmt: skip
            measure(s, org)
    finally:
        if args.keep:
            print(f"kept {org}")
        else:
            with owner.begin() as c:
                for stmt in (
                    "DELETE FROM advisory_impacts WHERE org_id = :o", "DELETE FROM advisory_states WHERE org_id = :o",
                    "DELETE FROM outbox_events WHERE org_id = :o", "DELETE FROM components WHERE org_id = :o",
                    "DELETE FROM libraries WHERE org_id = :o", "DELETE FROM scans WHERE org_id = :o",
                    "DELETE FROM assets WHERE org_id = :o", "DELETE FROM organizations WHERE id = :o",
                ):  # fmt: skip
                    c.execute(text(stmt), {"o": org})
    return 0


if __name__ == "__main__":
    sys.exit(main())
