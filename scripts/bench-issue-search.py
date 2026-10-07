#!/usr/bin/env python3
"""The org-wide Issues search at tens of thousands of Issues, on Postgres under forced RLS (plan §56,
§58: "the issues table stays responsive at 50,000 rows").

Seeds an organization inside Postgres (generate_series, seconds): P projects in 10 portfolios with
I Issues each -- a year of history, about a third fixed, some accepted and not a risk, bands,
scores, assignees, SLA policies on half the projects, a tag on two portfolios. Then, as
`bulwark_worker`, times each query 20 times (first page and its count) and pages 25 pages deep by
cursor, reporting p50 and p95 against a 300 ms budget per page.

    BULWARK_BENCH_OWNER_URL=postgresql+psycopg://bulwark:...@localhost:55432/bulwark \
    BULWARK_BENCH_APP_URL=postgresql+psycopg://bulwark_worker:...@localhost:55432/bulwark \
    python scripts/bench-issue-search.py --projects 200 --issues 500 [--out results.json]

It deletes the organization afterwards unless --keep.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from core.search import issues as search  # noqa: E402
from core.search.language import parse  # noqa: E402
from core.tenancy import set_session_org  # noqa: E402

BUDGET_MS = 300.0
STARTER = '{"CRITICAL":{"days":7,"warn":2},"HIGH":{"days":30,"warn":7},"MEDIUM":{"days":90,"warn":14},"LOW":{"days":180,"warn":30},"INFO":{"days":null,"warn":null}}'  # noqa: E501

QUERIES = {
    "default (the active queue)": "",
    "plan example": "priority:P1 sla:breached project:p1* -status:accepted",
    "one business unit, unassigned, older than 90 days": "portfolio:unit-3 assignee:none first_seen:>90d",  # noqa: E501
    "critical, newest first": "severity:critical",
    "free text": "injection",
    "a tag (inherited from units)": "tag:pci",
    "everything, fixed too": "status:open,accepted,not_a_risk,fixed",
}
SORT_FOR = {"critical, newest first": "newest"}


def seed(owner: Any, org: str, projects: int, issues: int) -> None:
    with owner.begin() as c:
        c.execute(text("INSERT INTO organizations (id, name, created_at) VALUES (:o, 'bench', now())"),
                  {"o": org})  # fmt: skip
        units = [str(uuid.uuid4()) for _ in range(10)]
        for k, u in enumerate(units):
            c.execute(text("INSERT INTO portfolios (id, org_id, name, created_at) VALUES (:i, :o, :n, now())"),  # noqa: E501
                      {"i": u, "o": org, "n": f"unit-{k}"})  # fmt: skip
        for unit in units[:2]:
            c.execute(text("INSERT INTO tags (id, org_id, target_type, target_id, name, created_by, created_at) "  # noqa: E501
                           "VALUES (:i, :o, 'portfolio', :t, 'pci', 'bench', now())"),
                      {"i": str(uuid.uuid4()), "o": org, "t": unit})  # fmt: skip
        for p in range(projects):
            a = str(uuid.uuid4())
            c.execute(text("INSERT INTO assets (id, org_id, source_type, key, label, created_at, last_scanned_at, portfolio_id) "  # noqa: E501
                           "VALUES (:a, :o, 'git', :k, :l, now(), now(), :u)"),
                      {"a": a, "o": org, "k": f"https://example.com/{org}/{p}", "l": f"bench/p{p}",
                       "u": units[p % 10]})  # fmt: skip
            if p % 2 == 0:
                c.execute(text("INSERT INTO sla_policies (id, org_id, asset_id, version, enabled, basis, bands, created_by, created_at) "  # noqa: E501
                               "VALUES (:i, :o, :a, 1, true, 'severity', CAST(:b AS jsonb), 'bench', now())"),  # noqa: E501
                          {"i": str(uuid.uuid4()), "o": org, "a": a, "b": STARTER})  # fmt: skip
            c.execute(text(
                """INSERT INTO issues (id, asset_id, fingerprint, state, category, severity, path,
                     title, first_seen_at, last_seen_at, fixed_at, triage_status, triage_expires_at,
                     source, priority_band, priority_score, assignee)
                   SELECT md5(:a || g)::uuid::text, :a, 'sha256:' || md5(:a || g),
                     CASE WHEN g % 3 = 0 THEN 'fixed' ELSE 'open' END,
                     (ARRAY['sast','sca','secrets','iac'])[1 + (g % 4)],
                     (ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO'])[1 + (g % 5)],
                     'src/m' || (g % 40) || '/x' || g || '.py',
                     (ARRAY['SQL injection in','Open redirect in','Hard-coded secret in',
                            'Outdated library in','Missing check in'])[1 + (g % 5)] || ' handler ' || g,
                     now() - (random() * 365) * interval '1 day', now(),
                     CASE WHEN g % 3 = 0 THEN now() - (random() * 30) * interval '1 day' END,
                     CASE WHEN g % 20 = 1 THEN 'accepted' WHEN g % 20 = 2 THEN 'not_a_risk' ELSE 'open' END,
                     CASE WHEN g % 20 = 1 THEN now() + interval '30 days' END,
                     'scanner', (ARRAY['P1','P2','P3','P4'])[1 + (g % 4)], (random() * 100)::int,
                     CASE WHEN g % 7 = 0 THEN 'token:bench' || (g % 5) END
                   FROM generate_series(1, :n) g"""), {"a": a, "n": issues})  # fmt: skip  # noqa: E501


def timed(fn: Any, runs: int = 20) -> dict[str, float]:
    fn()
    ms = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        ms.append((time.perf_counter() - t) * 1000)
    ms.sort()
    return {"p50": round(statistics.median(ms), 1), "p95": round(ms[int(len(ms) * 0.95) - 1], 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", type=int, default=200)
    ap.add_argument("--issues", type=int, default=500)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    owner = create_engine(os.environ["BULWARK_BENCH_OWNER_URL"])
    app = sessionmaker(create_engine(os.environ["BULWARK_BENCH_APP_URL"]), expire_on_commit=False)
    org = f"bench-s-{uuid.uuid4().hex[:8]}"
    result: dict[str, Any] = {"projects": args.projects, "issues_per_project": args.issues,
                              "date": time.strftime("%Y-%m-%d"), "machine": platform.platform(),
                              "cpu": platform.processor() or platform.machine(),
                              "budget_ms_per_page": BUDGET_MS}  # fmt: skip
    with owner.connect() as c:
        result["postgres"] = c.execute(text("SHOW server_version")).scalar()
    try:
        t = time.perf_counter()
        seed(owner, org, args.projects, args.issues)
        with owner.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
            c.execute(text("VACUUM (ANALYZE, PARALLEL 0)"))
        result["issues"] = args.projects * args.issues
        result["seed_s"] = round(time.perf_counter() - t, 1)
        print(f"seeded {result['issues']:,} Issues in {result['seed_s']} s", flush=True)
        timings: dict[str, Any] = {}
        worst = 0.0
        with app() as s:
            set_session_org(s, org)
            for name, q in QUERIES.items():
                query = parse(q)
                sort = SORT_FOR.get(name, "priority")
                ctx = search.Context("token:bench0", datetime.now(timezone.utc))
                page = search.search(s, org, query, ctx=ctx, sort=sort)
                first = timed(
                    lambda q=query, c=ctx, o=sort: search.search(s, org, q, ctx=c, sort=o)
                )
                nocount = timed(lambda q=query, c=ctx, o=sort: search.search(
                    s, org, q, ctx=c, sort=o, with_count=False))  # fmt: skip
                timings[name] = {"query": q, "first_page_with_count": first,
                                 "page_without_count": nocount, "count": page["count"],
                                 "rows": len(page["rows"])}  # fmt: skip
                worst = max(worst, first["p95"])
                print(f"{name:52s} page+count {first['p50']}/{first['p95']} ms   "
                      f"page {nocount['p50']}/{nocount['p95']} ms   count {page['count']}",
                      flush=True)  # fmt: skip
            # Deep paging: 25 pages of 50 by cursor, each timed (page cost must not grow).
            ctx = search.Context(None, datetime.now(timezone.utc))
            query = parse("")
            after = None
            pages = []
            for _ in range(25):
                t = time.perf_counter()
                page = search.search(s, org, query, ctx=ctx, after=after, with_count=False)
                pages.append(round((time.perf_counter() - t) * 1000, 1))
                after = page["next"]
                if not after:
                    break
            timings["deep paging (25 pages of 50, no count)"] = {
                "first": pages[0], "last": pages[-1], "max": max(pages),
                "median": statistics.median(pages)}  # fmt: skip
            worst = max(worst, max(pages))
            print(
                f"deep paging: first {pages[0]} ms, page 25 {pages[-1]} ms, worst {max(pages)} ms"
            )
        result["timings"] = timings
        result["worst_p95_ms"] = worst
        result["within_budget"] = worst <= BUDGET_MS
        print(f"worst {worst} ms -> {'within' if worst <= BUDGET_MS else 'OVER'} the budget")
    finally:
        if not args.keep:
            with owner.begin() as c:
                c.execute(
                    text(
                        "DELETE FROM issues WHERE asset_id IN (SELECT id FROM assets WHERE org_id = :o)"
                    ),
                    {"o": org},
                )  # noqa: E501
                for table in ("sla_policies", "tags", "assets", "portfolios"):
                    c.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
                c.execute(text("DELETE FROM organizations WHERE id = :o"), {"o": org})
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result.get("within_budget") else 1


if __name__ == "__main__":
    sys.exit(main())
