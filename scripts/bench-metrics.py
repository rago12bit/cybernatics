#!/usr/bin/env python3
"""Dashboard metrics at one million Occurrences, on Postgres under forced RLS (plan §48.1, §60).

Seeds an organization inside Postgres (generate_series, so it takes seconds): P projects in 10
portfolios, I Issues per project each seen in 4 scans (P x I x 4 Occurrences), SLA policies, tags
on portfolios and Issues, libraries with advisory impacts, risk acceptances and engagements. Then,
as `bulwark_worker`:

- refreshes every project's summary rows (what the worker does) and one project alone (what a scan
  pays);
- times every metric 20 times, with no filter and with a portfolio, a project and a tag, and the
  first page of the Issues behind a number; reports p50 and p95 against the 300 ms budget.

    BULWARK_BENCH_OWNER_URL=postgresql+psycopg://bulwark:...@localhost:55432/bulwark \
    BULWARK_BENCH_APP_URL=postgresql+psycopg://bulwark_worker:...@localhost:55432/bulwark \
    python scripts/bench-metrics.py --projects 200 --issues 1250 [--keep] [--out results.json]

It deletes the organization afterwards (its metric rows cascade) unless --keep.
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
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from core.metrics import query, rollup  # noqa: E402
from core.metrics.definitions import METRICS  # noqa: E402
from core.persistence.models import Asset, Portfolio  # noqa: E402
from core.tenancy import set_session_org  # noqa: E402

BUDGET_MS = 300.0
STARTER = '{"CRITICAL":{"days":7,"warn":2},"HIGH":{"days":30,"warn":7},"MEDIUM":{"days":90,"warn":14},"LOW":{"days":180,"warn":30},"INFO":{"days":null,"warn":null}}'  # noqa: E501

SEED = [
    # Issues: a year of history, ~half fixed, 5% not a risk, bands and scores spread.
    """INSERT INTO issues (id, asset_id, fingerprint, state, category, severity, path, title,
         first_seen_at, last_seen_at, fixed_at, triage_status, source, priority_band,
         priority_score)
       SELECT md5(:a || g)::uuid::text, :a, 'sha256:' || md5(:a || g), 'open', 'sast',
         (ARRAY['CRITICAL','HIGH','MEDIUM','LOW'])[1 + (g % 4)], 'app/x' || g || '.py',
         'Issue ' || g, now() - (random() * 365) * interval '1 day', now(), NULL,
         CASE WHEN random() < 0.05 THEN 'not_a_risk' ELSE 'open' END, 'scanner',
         (ARRAY['P1','P2','P3','P4'])[1 + (g % 4)], (random() * 100)::int
       FROM generate_series(1, :n) g""",
    """UPDATE issues SET state = 'fixed',
         fixed_at = LEAST(now(), first_seen_at + (random() * 120) * interval '1 day')
       WHERE asset_id = :a AND random() < 0.5""",
    # Four scans per project, each finding every Issue: 4 Occurrences per Issue.
    """INSERT INTO findings (scan_id, finding_id, fingerprint, category, severity, severity_rank,
         path, start_line, tools, data, issue_id, issue_state)
       SELECT sc.id, 'f' || i.id, i.fingerprint, 'sast', i.severity, 1, i.path, 1, '["semgrep"]',
         jsonb_build_object('taxonomy', jsonb_build_object('cwe',
           jsonb_build_array((ARRAY['CWE-89','CWE-79','CWE-78','CWE-22','CWE-502'])[1 + (abs(hashtext(i.id)) % 5)]))),
         i.id, i.state
       FROM issues i CROSS JOIN (SELECT id FROM scans WHERE asset_id = :a) sc
       WHERE i.asset_id = :a""",  # noqa: E501
]


def seed(owner: Any, org: str, projects: int, issues: int) -> None:
    with owner.begin() as c:
        c.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:o, 'bench', now())"),
            {"o": org},
        )  # noqa: E501
        units = [str(uuid.uuid4()) for _ in range(10)]
        for k, u in enumerate(units):
            c.execute(text("INSERT INTO portfolios (id, org_id, name, created_at) VALUES (:i, :o, :n, now())"),
                      {"i": u, "o": org, "n": f"unit-{k}"})  # fmt: skip  # noqa: E501
        for p in range(projects):
            a = str(uuid.uuid4())
            c.execute(text("INSERT INTO assets (id, org_id, source_type, key, label, created_at, last_scanned_at, portfolio_id) "  # noqa: E501
                           "VALUES (:a, :o, 'git', :k, :l, now(), now(), :u)"),
                      {"a": a, "o": org, "k": f"https://example.com/{org}/{p}", "l": f"bench/p{p}", "u": units[p % 10]})  # fmt: skip  # noqa: E501
            for k in range(4):
                c.execute(text("INSERT INTO scans (id, org_id, status, source_type, source_ref, source_label, tools, asset_id, "  # noqa: E501
                               "llm_tokens_used, created_at, finished_at) VALUES (:s, :o, 'completed', 'git', 'x', :l, "  # noqa: E501
                               "'[\"semgrep\"]', :a, 0, now(), now() - :d * interval '1 day')"),
                          {"s": str(uuid.uuid4()), "o": org, "l": f"bench/p{p}", "a": a, "d": k * 9 + (p % 40)})  # fmt: skip  # noqa: E501
            c.execute(text("INSERT INTO sla_policies (id, org_id, asset_id, version, enabled, basis, bands, created_at) "  # noqa: E501
                           "VALUES (:i, :o, :a, 1, true, 'severity', CAST(:b AS jsonb), now())"),
                      {"i": str(uuid.uuid4()), "o": org, "a": a, "b": STARTER})  # fmt: skip
            for stmt in SEED:
                c.execute(text(stmt), {"a": a, "n": issues})
        c.execute(text("INSERT INTO tags (id, org_id, target_type, target_id, name, created_at) "
                       "SELECT md5(id || 'pci')::uuid::text, CAST(:o AS varchar), 'portfolio', id, 'pci', now() FROM portfolios WHERE org_id = :o "  # noqa: E501
                       "ORDER BY name LIMIT 2"), {"o": org})  # fmt: skip
        c.execute(text("INSERT INTO tags (id, org_id, target_type, target_id, name, created_at) "
                       "SELECT md5(i.id || 'tm')::uuid::text, CAST(:o AS varchar), 'issue', i.id, 'triage-me', now() FROM issues i "  # noqa: E501
                       "JOIN assets a ON a.id = i.asset_id WHERE a.org_id = :o AND random() < 0.01"), {"o": org})  # fmt: skip  # noqa: E501
        c.execute(text("INSERT INTO libraries (id, org_id, ecosystem, name, key, purl, first_seen_at, last_seen_at, project_count, version_count) "  # noqa: E501
                       "SELECT md5(CAST(:o AS text) || g)::uuid::text, CAST(:o AS varchar), 'npm', 'lib-' || g, 'npm:lib-' || g, 'pkg:npm/lib-' || g, now(), now(), 0, 0 "  # noqa: E501
                       "FROM generate_series(1, 2000) g"), {"o": org})  # fmt: skip
        c.execute(text("INSERT INTO advisory_impacts (id, org_id, vuln_key, advisory_ids, library_id, asset_id, version, fixed_version, "  # noqa: E501
                       "certain, first_seen_at, last_seen_at) "
                       "SELECT md5(CAST(:o AS text) || g || 'imp')::uuid::text, CAST(:o AS varchar), 'CVE-2099-' || (g % 5000), '[]', libs.ids[(1 + (g::bigint * 7919) % 2000)::int], projs.ids[(1 + (g::bigint * 104729) % :p)::int], '1.' || (g % 7), NULL, true, "  # noqa: E501
                       "now() - (g % 90) * interval '1 day', now() "
                       "FROM generate_series(1, 150000) g "
                       "CROSS JOIN (SELECT array_agg(id ORDER BY id) AS ids FROM libraries WHERE org_id = :o) libs "  # noqa: E501
                       "CROSS JOIN (SELECT array_agg(id ORDER BY id) AS ids FROM assets WHERE org_id = :o) projs "  # noqa: E501
                       "ON CONFLICT DO NOTHING"), {"o": org, "p": projects})  # fmt: skip
        c.execute(text("INSERT INTO advisory_states (id, org_id, vuln_key, state, first_seen_at, updated_at) "  # noqa: E501
                       "SELECT md5(CAST(:o AS text) || g || 'st')::uuid::text, CAST(:o AS varchar), 'CVE-2099-' || g, CASE WHEN g % 3 = 0 THEN 'issues' ELSE 'new' END, "  # noqa: E501
                       "now() - (g % 120) * interval '1 day', now() FROM generate_series(0, 4999) g"), {"o": org})  # fmt: skip  # noqa: E501
        c.execute(text("INSERT INTO risk_acceptances (id, org_id, asset_id, decision, justification, controls, proof_links, expires_at, "  # noqa: E501
                       "restart_sla, state, requested_by, requested_at, legacy) "
                       "SELECT md5(a.id || 'ra')::uuid::text, CAST(:o AS varchar), a.id, 'accept', 'j', 'c', '[]', now() + (random() * 90) * interval '1 day', "  # noqa: E501
                       "false, 'approved', 'token:x', now(), false FROM assets a WHERE a.org_id = :o"), {"o": org})  # fmt: skip  # noqa: E501
        c.execute(text("INSERT INTO engagements (id, org_id, asset_id, name, engagement_type, status, started_at, created_at, scope_targets, scope_routes, testers, target_end_at) "  # noqa: E501
                       "SELECT md5(a.id || 'en')::uuid::text, CAST(:o AS varchar), a.id, 'test ' || a.label, 'pentest', CASE WHEN random() < 0.5 THEN 'active' ELSE 'completed' END, "  # noqa: E501
                       "now(), now(), '[]', '[]', '[]', now() + interval '10 days' FROM assets a WHERE a.org_id = :o LIMIT 100"), {"o": org})  # fmt: skip  # noqa: E501


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
    ap.add_argument("--issues", type=int, default=1250)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--org")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    owner = create_engine(os.environ["BULWARK_BENCH_OWNER_URL"])
    app = sessionmaker(create_engine(os.environ["BULWARK_BENCH_APP_URL"]), expire_on_commit=False)
    org = args.org or f"bench-m-{uuid.uuid4().hex[:8]}"
    result: dict[str, Any] = {"projects": args.projects, "issues_per_project": args.issues,
                              "date": time.strftime("%Y-%m-%d"), "machine": platform.platform(),
                              "cpu": platform.processor() or platform.machine()}  # fmt: skip
    with owner.connect() as c:
        result["postgres"] = c.execute(text("SHOW server_version")).scalar()
    try:
        if not args.org:
            t = time.perf_counter()
            seed(owner, org, args.projects, args.issues)
            # VACUUM as well as ANALYZE: a table at rest, not one autovacuum is still working through
            # (the first run, timed during autovacuum, was up to 294 ms at p95; see ADR-0054).
            with owner.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
                c.execute(text("VACUUM (ANALYZE, PARALLEL 0)"))  # Docker's 64 MB /dev/shm
                counts = c.execute(
                    text(
                        "SELECT (SELECT count(*) FROM issues i JOIN assets a ON a.id = i.asset_id WHERE a.org_id = :o), "  # noqa: E501
                        "(SELECT count(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.org_id = :o)"
                    ),
                    {"o": org},
                ).one()  # noqa: E501
            result.update(
                issues=counts[0], occurrences=counts[1], seed_s=round(time.perf_counter() - t, 1)
            )  # noqa: E501
            print(
                f"seeded {counts[0]:,} Issues, {counts[1]:,} Occurrences in {result['seed_s']} s",
                flush=True,
            )  # noqa: E501
            with app() as s:
                set_session_org(s, org)
                t = time.perf_counter()
                rollup.refresh_all(s, org)
                result["refresh_all_s"] = round(time.perf_counter() - t, 1)
                one = s.scalars(select(Asset.id).where(Asset.org_id == org)).first()
                t = time.perf_counter()
                rollup.refresh_asset(s, org, one)  # type: ignore[arg-type]
                s.commit()
                result["refresh_one_project_s"] = round(time.perf_counter() - t, 2)
            print(
                f"refresh: all {result['refresh_all_s']} s, one project {result['refresh_one_project_s']} s",
                flush=True,
            )  # noqa: E501
        with app() as s:
            set_session_org(s, org)
            unit = s.scalars(
                select(Portfolio.id).where(Portfolio.org_id == org).order_by(Portfolio.name)
            ).first()  # noqa: E501
            project = s.scalars(
                select(Asset.id).where(Asset.org_id == org).order_by(Asset.id)
            ).first()  # noqa: E501
            variants = {"none": query.Filters(), "portfolio": query.Filters(portfolios=[unit]),  # type: ignore[list-item]
                        "project": query.Filters(projects=[project]),  # type: ignore[list-item]
                        "tag": query.Filters(tag="pci"), "issue tag": query.Filters(tag="triage-me")}  # fmt: skip
            timings: dict[str, Any] = {}
            worst = 0.0
            for m in METRICS:
                timings[m.id] = {}
                for name, f in variants.items():
                    r = timed(lambda f=f, m=m: query.compute(s, org, m.id, f))
                    timings[m.id][name] = r
                    worst = max(worst, r["p95"])
                print(
                    f"{m.id:24s} "
                    + "  ".join(f"{k}: {v['p50']}/{v['p95']}" for k, v in timings[m.id].items()),
                    flush=True,
                )  # noqa: E501
            for kind in ("open", "past_sla", "fixed"):
                r = timed(
                    lambda kind=kind: query.issues(s, org, query.Filters(), kind=kind, band="P1")
                )  # noqa: E501
                timings[f"issues:{kind}"] = r
                worst = max(worst, r["p95"])
                print(f"issues behind ({kind}, P1): {r['p50']}/{r['p95']} ms", flush=True)
            result["timings_ms"] = timings
            result["worst_p95_ms"] = worst
            print(f"worst p95: {worst} ms (budget {BUDGET_MS} ms)", flush=True)
        if args.out:
            args.out.write_text(json.dumps(result, indent=2))
    finally:
        if args.keep:
            print("kept", org)
        elif not args.org:
            with owner.begin() as c:
                for stmt in (
                    "DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE org_id = :o)",
                    "DELETE FROM tags WHERE org_id = :o",
                    "DELETE FROM advisory_impacts WHERE org_id = :o",
                    "DELETE FROM advisory_states WHERE org_id = :o",
                    "DELETE FROM risk_acceptances WHERE org_id = :o",
                    "DELETE FROM engagements WHERE org_id = :o",
                    "DELETE FROM libraries WHERE org_id = :o",
                    "DELETE FROM issues WHERE asset_id IN (SELECT id FROM assets WHERE org_id = :o)",
                    "DELETE FROM sla_policies WHERE org_id = :o",
                    "DELETE FROM scans WHERE org_id = :o",
                    "DELETE FROM assets WHERE org_id = :o",
                    "DELETE FROM portfolios WHERE org_id = :o",
                    "DELETE FROM organizations WHERE id = :o",
                ):
                    c.execute(text(stmt), {"o": org})
    return 0


if __name__ == "__main__":
    sys.exit(main())
