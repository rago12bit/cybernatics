#!/usr/bin/env python3
"""Evidence packs at scale, on Postgres under forced RLS (plan §47).

Creates an organization with N projects, each with M Issues (one occurrence each, a CWE, an SLA
policy, a spread of first-seen and fixed dates) and K audit-log entries, then times the preview
(`pack.collect`), the whole pack (`pack.build`: PDF, bundle) and the ASVS benchmark of one project.

    BULWARK_BENCH_OWNER_URL=postgresql+psycopg://bulwark:...@localhost:55432/bulwark \
    BULWARK_BENCH_APP_URL=postgresql+psycopg://bulwark_worker:...@localhost:55432/bulwark \
    python scripts/bench-evidence.py --projects 50 --issues 2000 --audit 20000

It deletes what it created (audit entries are append-only and stay, as in production).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from core import audit  # noqa: E402
from core.compliance import asvs  # noqa: E402
from core.evidence import pack  # noqa: E402
from core.sla.policy import STARTER  # noqa: E402
from core.tenancy import set_session_org  # noqa: E402

CWES = ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502", "CWE-287", "CWE-352", "CWE-918"]
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FRAMEWORKS = ["pci-dss-4.0-req6", "iso27001-2022-a8.8", "soc2-2017-cc7.1", "asvs-4.0.3",
              "owasp-top10-2021"]  # fmt: skip


def seed(owner_url: str, org: str, projects: int, issues: int, audit_n: int) -> list[str]:
    rng = random.Random(69)
    now = datetime.now(timezone.utc)
    eng = create_engine(owner_url)
    assets = []
    with eng.begin() as c:
        c.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:o, 'bench', now())"),
            {"o": org},
        )  # noqa: E501
        for p in range(projects):
            aid, sid = str(uuid.uuid4()), str(uuid.uuid4())
            assets.append(aid)
            c.execute(
                text(
                    "INSERT INTO assets (id, org_id, source_type, key, label, created_at, last_scanned_at) "
                    "VALUES (:a, :o, 'git', :k, :l, now(), now())"
                ),
                {"a": aid, "o": org, "k": f"https://example.com/{org}/{p}", "l": f"bench/p{p}"},
            )  # noqa: E501
            c.execute(
                text(
                    "INSERT INTO scans (id, org_id, status, source_type, source_ref, source_label, tools, "
                    "asset_id, llm_tokens_used, created_at, finished_at) VALUES (:s, :o, 'completed', 'git', "
                    "'x', :l, '[\"opengrep\"]', :a, 0, now(), now() - interval '3 days')"
                ),
                {"s": sid, "o": org, "l": f"bench/p{p}", "a": aid},
            )  # noqa: E501
            c.execute(
                text(
                    "INSERT INTO sla_policies (id, org_id, asset_id, version, enabled, basis, bands, created_at) "
                    "VALUES (:i, :o, :a, 1, true, 'severity', CAST(:b AS jsonb), now() - interval '400 days')"
                ),
                {"i": str(uuid.uuid4()), "o": org, "a": aid, "b": json.dumps(STARTER)},
            )  # noqa: E501
            rows, frows = [], []
            for i in range(issues):
                iid = str(uuid.uuid4())
                seen = now - timedelta(days=rng.randint(1, 360))
                fixed = seen + timedelta(days=rng.randint(1, 120)) if rng.random() < 0.6 else None
                if fixed and fixed > now:
                    fixed = None
                sev = rng.choice(SEVS)
                rows.append({"id": iid, "a": aid, "fp": f"sha256:{iid}", "st": "fixed" if fixed else "open",
                             "sev": sev, "seen": seen, "fixed": fixed,
                             "tr": "not_a_risk" if rng.random() < 0.05 else "open",
                             "band": f"P{SEVS.index(sev) + 1}"})  # fmt: skip
                frows.append({"s": sid, "f": f"f{i}", "fp": f"sha256:{iid}", "sev": sev, "i": iid,
                              "d": json.dumps({"taxonomy": {"cwe": [rng.choice(CWES)]}})})  # fmt: skip
            c.execute(
                text(
                    "INSERT INTO issues (id, asset_id, fingerprint, state, category, severity, path, title, "
                    "first_seen_at, last_seen_at, fixed_at, triage_status, source, priority_band) VALUES "
                    "(:id, :a, :fp, :st, 'sast', :sev, 'x.py', 't', :seen, :seen, :fixed, :tr, 'scanner', :band)"
                ),
                rows,
            )  # noqa: E501
            c.execute(
                text(
                    "INSERT INTO findings (scan_id, finding_id, fingerprint, category, severity, severity_rank, "
                    "path, start_line, tools, data, issue_id) VALUES (:s, :f, :fp, 'sast', :sev, 1, 'x.py', 1, "
                    "'[]', CAST(:d AS jsonb), :i)"
                ),
                frows,
            )  # noqa: E501
        last = c.execute(
            text("SELECT seq, entry_hash FROM audit_entries ORDER BY seq DESC LIMIT 1")
        ).first()  # noqa: E501
        seq, prev = (last[0], last[1]) if last else (0, audit.GENESIS_HASH)
        entries = []
        for k in range(audit_n):
            seq += 1
            ts = now - timedelta(seconds=audit_n - k)
            mine = k % 3 != 0
            o = org if mine else None
            pd = audit.payload_digest({"k": k})
            body = audit.body_digest(timestamp=ts, org_id=o, actor="token:bench", action="bench.did",
                                     target=f"t{k}", payload_digest=pd)  # fmt: skip
            h = audit.compute_hash_v2(seq=seq, prev_hash=prev, body_digest=body)
            entries.append(
                {"seq": seq, "p": prev, "h": h, "ts": ts, "o": o, "pd": pd, "b": body, "t": f"t{k}"}
            )  # noqa: E501
            prev = h
        c.execute(
            text(
                "INSERT INTO audit_entries (seq, prev_hash, entry_hash, timestamp, actor, action, target, "
                "payload_digest, version, org_id, body_digest) VALUES (:seq, :p, :h, :ts, 'token:bench', "
                "'bench.did', :t, :pd, 2, :o, :b)"
            ),
            entries,
        )  # noqa: E501
    return assets


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", type=int, default=50)
    ap.add_argument("--issues", type=int, default=2000)
    ap.add_argument("--audit", type=int, default=20000)
    args = ap.parse_args()
    owner_url, app_url = os.environ["BULWARK_BENCH_OWNER_URL"], os.environ["BULWARK_BENCH_APP_URL"]
    org = f"bench-ev-{uuid.uuid4().hex[:8]}"
    t = time.perf_counter()
    assets = seed(owner_url, org, args.projects, args.issues, args.audit)
    print(
        f"seeded {args.projects} projects x {args.issues} Issues, {args.audit} audit entries in {time.perf_counter() - t:.1f}s",
        flush=True,
    )  # noqa: E501
    app = sessionmaker(create_engine(app_url), expire_on_commit=False)
    end = date.today()
    start = end - timedelta(days=89)
    try:
        with app() as s:
            set_session_org(s, org)
            for name, fn in (
                ("preview (collect)", lambda: pack.collect(s, org, start, end, FRAMEWORKS)),
                ("whole pack (build)", lambda: pack.build(s, org, start, end, FRAMEWORKS, actor="bench")),
                ("ASVS L2, one project", lambda: asvs.benchmark(s, org, assets[0], level=2)),
            ):  # fmt: skip
                t = time.perf_counter()
                out = fn()
                took = time.perf_counter() - t
                extra = f", bundle {len(out.bundle) / 1e6:.1f} MB" if hasattr(out, "bundle") else ""
                print(f"{name}: {took:.1f}s{extra}", flush=True)
            ev = pack.collect(s, org, start, end, [])
            print("sla", {k: ev["sla"][k] for k in ("met", "missed", "open_past_deadline", "exempt")},
                  "audit", {k: ev["audit_check"][k] for k in ("entries", "disclosed", "recomputed", "ok")})  # fmt: skip
    finally:
        with create_engine(owner_url).begin() as c:
            for stmt in (
                "DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE org_id = :o)",
                "DELETE FROM issues WHERE asset_id IN (SELECT id FROM assets WHERE org_id = :o)",
                "DELETE FROM sla_policies WHERE org_id = :o", "DELETE FROM scans WHERE org_id = :o",
                "DELETE FROM assets WHERE org_id = :o", "DELETE FROM organizations WHERE id = :o",
            ):  # fmt: skip
                c.execute(text(stmt), {"o": org})
    return 0


if __name__ == "__main__":
    sys.exit(main())
