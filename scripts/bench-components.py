#!/usr/bin/env python3
"""How fast "where do we use this?" answers for a large organization (plan §46.1: "under a
second across the whole organization").

Seeds one organization through the real write path (`core.inventory.record`) on Postgres -- N
projects, each with two SBOMs (the first becomes history), drawn from a pool of libraries with a
long tail -- then times the searches the Components screen makes, as an application role under
forced RLS. Run against a throwaway database at head:

    BULWARK_BENCH_OWNER_URL=postgresql+psycopg://bulwark:...@localhost:55432/bulwark \
    BULWARK_BENCH_APP_URL=postgresql+psycopg://bulwark_worker:...@localhost:55432/bulwark \
    python scripts/bench-components.py --projects 1000 --packages 1500

It deletes only the organization it created.
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from core import inventory  # noqa: E402
from core.persistence import repo  # noqa: E402
from core.tenancy import set_session_org  # noqa: E402

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core"
LOG4J_VERSIONS = ["2.0-beta9", "2.11.1", "2.13.3", "2.14.1", "2.15.0", "2.16.0", "2.17.0", "2.17.1", "2.20.0", "2.23.1"]  # fmt: skip


def pool(size: int) -> list[str]:
    out = []
    for i in range(size):
        eco = ("npm", "pypi", "maven", "golang")[i % 4]
        if eco == "maven":
            out.append(f"pkg:maven/com.example.g{i % 97}/artifact-{i}")
        elif eco == "golang":
            out.append(f"pkg:golang/github.com/org{i % 89}/mod-{i}")
        else:
            out.append(f"pkg:{eco}/lib-{i}")
    return out


def sbom(rng: random.Random, libs: list[str], n: int) -> list[dict[str, str]]:
    """Exactly `n` distinct libraries: a popular head that most projects share (the first 400,
    each taken with probability 0.6) and the rest from the long tail."""
    head = [p for p in libs[:400] if rng.random() < 0.6][:n]
    tail = rng.sample(libs[400:], n - len(head))
    pkgs = []
    for purl in head + tail:
        ver = f"{rng.randint(0, 5)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"
        pkgs.append({"purl": f"{purl}@{ver}", "relation": rng.choice(["direct", "transitive"]),
                     "path": "package-lock.json"})  # fmt: skip
    if rng.random() < 0.3:
        pkgs.append({"purl": f"{LOG4J}@{rng.choice(LOG4J_VERSIONS)}", "relation": "transitive",
                     "path": "pom.xml"})  # fmt: skip
    return pkgs


def timed(fn, runs: int) -> list[float]:  # type: ignore[no-untyped-def]
    out = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", type=int, default=1000)
    ap.add_argument("--packages", type=int, default=1500)
    ap.add_argument("--libraries", type=int, default=40000)
    ap.add_argument("--runs", type=int, default=20)
    args = ap.parse_args()
    owner = create_engine(os.environ["BULWARK_BENCH_OWNER_URL"])
    app = sessionmaker(create_engine(os.environ["BULWARK_BENCH_APP_URL"]), expire_on_commit=False)
    org = f"bench-{uuid.uuid4().hex[:8]}"
    with owner.begin() as c:
        c.execute(text("INSERT INTO organizations (id, name, created_at) VALUES (:o, 'bench', now())"), {"o": org})  # fmt: skip
    rng = random.Random(67)
    libs = pool(args.libraries)
    try:
        started = time.perf_counter()
        with app() as s:
            set_session_org(s, org)
            for p in range(args.projects):
                for _round in range(2):  # the first SBOM becomes history
                    sc = repo.create_scan(
                        s, source_type="git", source_ref=f"https://example.com/p/{p}",
                        source_label=f"bench/p{p}", tools=["syft"], org_id=org,
                    )  # fmt: skip
                    assert sc.asset_id is not None
                    inventory.record(s, org_id=org, asset_id=sc.asset_id, scan_id=sc.id,
                                     source="scan", packages=sbom(rng, libs, args.packages))  # fmt: skip
                if p % 100 == 99:
                    print(f"  {p + 1} projects in {time.perf_counter() - started:.0f}s", flush=True)
        seed_s = time.perf_counter() - started
        with owner.connect() as c:
            c.execute(text("ANALYZE components; ANALYZE libraries"))
            counts = c.execute(
                text("SELECT count(*), count(*) FILTER (WHERE current) FROM components WHERE org_id = :o"), {"o": org}  # fmt: skip
            ).one()
            nlibs = c.execute(text("SELECT count(*) FROM libraries WHERE org_id = :o"), {"o": org}).scalar()  # fmt: skip
        print(f"seeded {args.projects} projects: {counts[0]} component rows ({counts[1]} current), "
              f"{nlibs} libraries, in {seed_s:.0f}s")  # fmt: skip

        with app() as s:
            set_session_org(s, org)
            common = inventory.libraries(s, org, limit=1)[0]["purl"]
            cases = {
                "log4j-core <2.17.1 (in ~30% of projects)": lambda: inventory.search(s, org, purl=LOG4J, constraint="<2.17.1"),  # fmt: skip
                "the most-used library, every version": lambda: inventory.search(
                    s, org, purl=common
                ),
                "the most-used library, >=1.0,<3.0": lambda: inventory.search(s, org, purl=common, constraint=">=1.0,<3.0"),  # fmt: skip
                "a library nobody uses": lambda: inventory.search(s, org, purl="pkg:npm/left-pad"),
                "name search 'artifact-1'": lambda: inventory.libraries(s, org, q="artifact-1"),
                "most-used libraries (no query)": lambda: inventory.libraries(s, org),
            }
            for name, fn in cases.items():
                fn()  # warm
                ms = sorted(timed(fn, args.runs))
                p95 = ms[min(len(ms) - 1, int(len(ms) * 0.95))]
                print(f"{name:45s} p50 {statistics.median(ms):7.1f} ms  p95 {p95:7.1f} ms  max {ms[-1]:7.1f} ms")  # fmt: skip
            r = inventory.search(s, org, purl=LOG4J, constraint="<2.17.1")
            print(f"log4j-core <2.17.1 -> {r.summary()}")
            plan = s.execute(text(
                "EXPLAIN ANALYZE SELECT version, count(DISTINCT asset_id) FROM components "
                "WHERE library_id = (SELECT id FROM libraries WHERE key = :k) AND current GROUP BY version"
            ), {"k": "maven:org.apache.logging.log4j:log4j-core"}).all()  # fmt: skip
            print("\n".join(row[0] for row in plan))
    finally:
        with owner.begin() as c:
            for stmt in (
                "DELETE FROM components WHERE org_id = :o", "DELETE FROM libraries WHERE org_id = :o",
                "DELETE FROM scans WHERE org_id = :o", "DELETE FROM assets WHERE org_id = :o",
                "DELETE FROM organizations WHERE id = :o",
            ):  # fmt: skip
                c.execute(text(stmt), {"o": org})
    return 0


if __name__ == "__main__":
    sys.exit(main())
