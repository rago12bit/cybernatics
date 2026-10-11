#!/usr/bin/env python3
"""The rules engine under load: rule evaluation latency at p95 with a synthetic event stream
(plan §45, §60: "Rule evaluation latency at p95 under load -- load test with a synthetic event
stream").

Seeds an organization on Postgres (P projects x I open Issues), and, as `bulwark_worker` under forced
RLS, creates a set of enabled rules through the real rules service. Then, for each rate in --rates:

- a producer writes `issue.created` / `issue.reopened` / `issue.closed` outbox events at that rate
  for --seconds, in batches every 100 ms, shaped exactly as `repo` writes them after a scan;
- the real dispatcher (`core.dispatch.dispatch`, batches of 500, the advisory lock, every
  subscriber: rules, tickets, notifications) drains the outbox as fast as it can, in another
  connection, while events keep arriving;
- every `opa eval` the engine makes is timed (that is "rule evaluation": one per rule per batch, over
  every candidate in the batch), as is every dispatched batch, and each event's delay from written
  to dispatched; the backlog is sampled every half second.

The real worker drains every ten seconds (`core.dispatch.drain` on a beat), which adds up to ten
seconds of waiting to every event by design; this measures what the engine itself can keep up with.

    BULWARK_BENCH_OWNER_URL=postgresql+psycopg://bulwark:...@localhost:55432/bulwark \\
    BULWARK_BENCH_APP_URL=postgresql+psycopg://bulwark_worker:...@localhost:55432/bulwark \\
    python scripts/bench-rules.py --rates 50,200,500,1000 --seconds 30 [--out results.json]

Use a throwaway database: the rules write audit entries, which are append-only, so the organization
is left behind.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import statistics
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, func, select, text  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from core import dispatch as dispatcher  # noqa: E402
from core.persistence import repo  # noqa: E402
from core.persistence.models import OutboxEvent, RuleRun  # noqa: E402
from core.rules import rego  # noqa: E402
from core.rules import service as rules  # noqa: E402
from core.tenancy import set_session_org  # noqa: E402

# Ten rules, the kind the template gallery starts people with: most on new Issues, some that match
# often, some rarely, one never; their actions write (priority overrides, tags) and announce
# follow-up events, as real ones do. No notification actions: those would call out to the network.
RULES: list[dict[str, Any]] = [
    {"trigger": "issue.created", "condition": 'input.issue.severity == "CRITICAL"',
     "actions": [{"type": "set_priority", "band": "P1"}, {"type": "tag", "tags": ["hot"]}]},
    {"trigger": "issue.created",
     "condition": 'input.issue.severity == "HIGH"\nstartswith(input.issue.path, "app/x1")',
     "actions": [{"type": "tag", "tags": ["review"]}]},
    {"trigger": "issue.created", "condition": 'contains(input.issue.title, "Issue 7")',
     "actions": [{"type": "set_priority", "band": "P2"}]},
    {"trigger": "issue.created", "condition": 'input.issue.category == "secrets"',
     "actions": [{"type": "set_priority", "band": "P1"}]},
    {"trigger": "issue.created", "condition": 'input.project.name == "no such project"',
     "actions": [{"type": "tag", "tags": ["never"]}]},
    {"trigger": "issue.created", "condition": "input.issue.age_days > 300",
     "actions": [{"type": "tag", "tags": ["old"]}]},
    {"trigger": "issue.reopened", "condition": 'input.issue.severity == "HIGH"',
     "actions": [{"type": "set_priority", "band": "P1"}]},
    {"trigger": "issue.reopened", "condition": 'input.issue.severity != "LOW"',
     "actions": [{"type": "tag", "tags": ["came-back"]}]},
    {"trigger": "issue.closed", "condition": 'input.issue.severity == "CRITICAL"',
     "actions": [{"type": "tag", "tags": ["fixed-critical"]}]},
    {"trigger": "issue.closed", "condition": 'endswith(input.issue.path, "0.py")',
     "actions": [{"type": "tag", "tags": ["closed-0"]}]},
]  # fmt: skip
MIX = (("issue.created", 0.6), ("issue.reopened", 0.2), ("issue.closed", 0.2))


def seed(owner: Any, org: str, projects: int, issues: int) -> list[tuple[str, str, str]]:
    """Returns (issue id, asset id, scan id) for every Issue."""
    with owner.begin() as c:
        c.execute(text("INSERT INTO organizations (id, name, created_at) VALUES (:o, 'bench-rules', now())"),
                  {"o": org})  # fmt: skip
        for p in range(projects):
            a, sc = str(uuid.uuid4()), str(uuid.uuid4())
            c.execute(text("INSERT INTO assets (id, org_id, source_type, key, label, created_at, last_scanned_at) "  # noqa: E501
                           "VALUES (:a, :o, 'git', :k, :l, now(), now())"),
                      {"a": a, "o": org, "k": f"https://example.com/{org}/{p}", "l": f"bench/p{p}"})  # fmt: skip  # noqa: E501
            c.execute(text("INSERT INTO scans (id, org_id, status, source_type, source_ref, source_label, tools, asset_id, "  # noqa: E501
                           "llm_tokens_used, created_at, finished_at) VALUES (:s, :o, 'completed', 'git', 'x', :l, "  # noqa: E501
                           "'[\"semgrep\"]', :a, 0, now(), now())"),
                      {"s": sc, "o": org, "l": f"bench/p{p}", "a": a})  # fmt: skip
            c.execute(text(
                """INSERT INTO issues (id, asset_id, fingerprint, state, category, severity, path, title,
                     first_seen_at, last_seen_at, triage_status, source)
                   SELECT md5(:a || g)::uuid::text, :a, 'sha256:' || md5(:a || g), 'open',
                     (ARRAY['sast','sast','sast','secrets','sca'])[1 + (g % 5)],
                     (ARRAY['CRITICAL','HIGH','MEDIUM','LOW'])[1 + (g % 4)], 'app/x' || g || '.py',
                     'Issue ' || g, now() - (random() * 365) * interval '1 day', now(), 'open', 'scanner'
                   FROM generate_series(1, :n) g"""), {"a": a, "n": issues})  # fmt: skip
        rows = c.execute(text("SELECT i.id, i.asset_id, s.id FROM issues i JOIN scans s ON s.asset_id = i.asset_id "  # noqa: E501
                              "WHERE s.org_id = :o"), {"o": org}).all()  # fmt: skip
    with owner.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
        c.execute(text("VACUUM (ANALYZE, PARALLEL 0)"))
    return [(r[0], r[1], r[2]) for r in rows]


def make_rules(app: sessionmaker[Session], org: str) -> None:
    with app() as s:
        set_session_org(s, org)
        for k, r in enumerate(RULES):
            d = rules.validate(s, org, {"name": f"bench rule {k}", **r})
            rules.create(s, org, d, actor="bench")
        s.commit()


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(q / 100 * (len(ordered) - 1)))]


def summary(values: list[float], digits: int = 1) -> dict[str, float]:
    return {"n": len(values), "p50": round(pct(values, 50), digits), "p95": round(pct(values, 95), digits),
            "p99": round(pct(values, 99), digits), "max": round(max(values, default=0.0), digits)}  # fmt: skip


class Evaluations:
    """Times every `opa eval` the engine makes (rego.matches): one per rule per batch."""

    def __init__(self) -> None:
        self.ms: list[float] = []
        self.items: list[int] = []
        self._lock = threading.Lock()
        self._real = rego.matches

    def __enter__(self) -> Evaluations:
        def timed(condition: str, items: Any) -> set[int]:
            t = time.perf_counter()
            try:
                return self._real(condition, items)
            finally:
                with self._lock:
                    self.ms.append((time.perf_counter() - t) * 1000)
                    self.items.append(len(items))

        rego.matches = timed  # type: ignore[assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        rego.matches = self._real  # type: ignore[assignment]


def produce(app: sessionmaker[Session], org: str, issues: list[tuple[str, str, str]], rate: int,
            seconds: float, written: list[int]) -> None:  # fmt: skip
    rng = random.Random(rate)
    kinds, weights = zip(*MIX, strict=True)
    with app() as s:
        set_session_org(s, org)
        start, owed = time.monotonic(), 0.0
        while (elapsed := time.monotonic() - start) < seconds:
            owed += rate * 0.1
            n, owed = int(owed), owed - int(owed)
            for kind in rng.choices(kinds, weights, k=n):
                issue_id, asset_id, scan_id = rng.choice(issues)
                repo.add_outbox_event(s, org_id=org, event_type=kind, payload={
                    "asset_id": asset_id, "scan_id": scan_id, "source": "scan", "issue_id": issue_id})  # fmt: skip  # noqa: E501
            s.commit()
            written[0] += n
            time.sleep(max(0.0, 0.1 - (time.monotonic() - start - elapsed)))


def pending(owner: Any, org: str) -> int:
    with owner.connect() as c:
        return int(c.execute(text("SELECT count(*) FROM outbox_events WHERE org_id = :o AND dispatched_at IS NULL"),
                             {"o": org}).scalar() or 0)  # fmt: skip


def stage(owner: Any, app: sessionmaker[Session], org: str, issues: list[tuple[str, str, str]],
          rate: int, seconds: float) -> dict[str, Any]:  # fmt: skip
    with owner.connect() as c:
        first_id = int(
            c.execute(text("SELECT coalesce(max(id), 0) FROM outbox_events")).scalar() or 0
        )
        runs_before = int(
            c.execute(text("SELECT count(*) FROM rule_runs WHERE org_id = :o"), {"o": org}).scalar()
            or 0
        )  # noqa: E501
    written = [0]
    producer = threading.Thread(target=produce, args=(app, org, issues, rate, seconds, written))
    batches: list[tuple[float, int]] = []
    backlog: list[int] = []
    t0 = time.monotonic()
    with Evaluations() as ev, app() as s:
        set_session_org(s, org)
        producer.start()
        next_sample = 0.0
        while True:
            now = time.monotonic() - t0
            if now >= next_sample:
                backlog.append(pending(owner, org))
                next_sample += 0.5
            t = time.perf_counter()
            n = dispatcher.dispatch(s, org)
            if n:
                batches.append(((time.perf_counter() - t) * 1000, n))
            elif not producer.is_alive():
                break
            else:
                time.sleep(0.02)
        producer.join()
    elapsed = time.monotonic() - t0
    with owner.connect() as c:
        delays = [float(r[0]) for r in c.execute(text(
            "SELECT extract(epoch FROM dispatched_at - created_at) FROM outbox_events "
            "WHERE org_id = :o AND id > :f AND event_type IN ('issue.created', 'issue.reopened', 'issue.closed')"),
            {"o": org, "f": first_id})]  # fmt: skip
        followups = int(c.execute(text("SELECT count(*) FROM outbox_events WHERE org_id = :o AND id > :f "
                                       "AND event_type NOT IN ('issue.created', 'issue.reopened', 'issue.closed')"),  # noqa: E501
                                  {"o": org, "f": first_id}).scalar() or 0)  # fmt: skip
        runs = int(
            c.execute(text("SELECT count(*) FROM rule_runs WHERE org_id = :o"), {"o": org}).scalar()
            or 0
        )  # noqa: E501
    batch_ms = [b[0] for b in batches]
    return {
        "target_rate_per_s": rate,
        "events_written": written[0],
        "written_per_s": round(written[0] / seconds, 1),
        "follow_up_events": followups,
        "dispatched_per_s": round((written[0] + followups) / elapsed, 1),
        "drained_after_s": round(elapsed - seconds, 1),
        "rule_runs": runs - runs_before,
        "rule_evaluation_ms": summary(ev.ms),
        "candidates_per_evaluation": round(statistics.mean(ev.items), 1) if ev.items else 0,
        "batch_ms": summary(batch_ms),
        "events_per_batch": round(statistics.mean(b[1] for b in batches), 1) if batches else 0,
        "event_delay_s": summary(delays, 2),
        "backlog_max": max(backlog, default=0),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--projects", type=int, default=20)
    ap.add_argument("--issues", type=int, default=500, help="open Issues per project")
    ap.add_argument("--rates", default="50,200,500,1000", help="events per second, one stage each")
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    owner = create_engine(os.environ["BULWARK_BENCH_OWNER_URL"])
    app = sessionmaker(create_engine(os.environ["BULWARK_BENCH_APP_URL"]), expire_on_commit=False)
    org = f"bench-r-{uuid.uuid4().hex[:8]}"
    result: dict[str, Any] = {"date": time.strftime("%Y-%m-%d"), "machine": platform.platform(),
                              "cpu": platform.processor() or platform.machine(),
                              "projects": args.projects, "issues_per_project": args.issues,
                              "rules": len(RULES), "batch": dispatcher.BATCH,
                              "stage_seconds": args.seconds}  # fmt: skip
    with owner.connect() as c:
        result["postgres"] = c.execute(text("SHOW server_version")).scalar()
    issues = seed(owner, org, args.projects, args.issues)
    make_rules(app, org)
    print(f"{len(issues):,} Issues in {args.projects} projects, {len(RULES)} rules", flush=True)
    result["stages"] = []
    for rate in (int(r) for r in args.rates.split(",")):
        r = stage(owner, app, org, issues, rate, args.seconds)
        result["stages"].append(r)
        e, d = r["rule_evaluation_ms"], r["event_delay_s"]
        print(f"{rate:>5}/s: wrote {r['events_written']} (+{r['follow_up_events']} follow-ups), "
              f"evaluation p50/p95/p99 {e['p50']}/{e['p95']}/{e['p99']} ms over {e['n']} evals "
              f"({r['candidates_per_evaluation']} candidates each), batch p95 {r['batch_ms']['p95']} ms, "
              f"event delay p50/p95 {d['p50']}/{d['p95']} s, backlog max {r['backlog_max']}, "
              f"drained {r['drained_after_s']} s after the stream stopped", flush=True)  # fmt: skip
    with app() as s:
        set_session_org(s, org)
        result["rule_runs_total"] = s.scalar(select(func.count()).select_from(RuleRun))
        assert s.scalar(select(func.count()).select_from(OutboxEvent).where(
            OutboxEvent.dispatched_at.is_(None))) == 0, "events left undispatched"  # fmt: skip
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n")
        print("wrote", args.out)


if __name__ == "__main__":
    main()
