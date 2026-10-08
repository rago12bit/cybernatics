#!/usr/bin/env python3
"""Disposable, self-seeding Bulwark API server for Playwright end-to-end tests (Week 35, plan
§31's "Playwright end-to-end tests for journeys J1-J5"). Not for production or manual dev use.

Playwright's CI job has no Docker, Postgres or Redis (it's a dedicated `e2e` job: Python + Node,
no scanner images). This server uses the real FastAPI app (`api.main.create_app`) and the real
persistence layer (`core.persistence.repo`) against a real file-backed SQLite database in WAL mode
(unlike `tests/conftest.py`'s in-memory `sessions` fixture -- this process serves genuinely
concurrent requests, which an in-memory single-connection database can't safely do; see `main()`'s
own comment), so every HTTP request Playwright makes runs real application code. Only two things a
scanner-less, worker-less CI job genuinely cannot do are faked, both clearly marked below:

  1. Running actual scanner containers (`core/runner.py`, Docker): `_FakeEnqueue.__call__` stands
     in for the Celery worker, marking the scan "running" then, after a short delay, writing real
     `Finding` rows (built directly from `core.models`, not scanner output) through the same
     `repo.sync_issues_for_scan` / `repo.add_findings` / `repo.finish_scan` calls the real pipeline
     uses. The frontend cannot tell the difference -- it never sees `core/pipeline.py` at all.
  2. Redis pub/sub for live WebSocket updates: `_EmptySubscriber.subscribe()` yields nothing, so
     the API's `/scans/{id}/ws` handler sends its one real "snapshot" message and closes -- which
     is exactly what makes `web/lib/useScan.ts` fall back to its own real polling path (see that
     file's docstring). Polling every 3s is fast enough for a scan that "finishes" in ~1.5s.

Week 74 (journeys J6-J10) adds three more, for the same reason -- the e2e job has no Docker, no
network and no worker:

  3. Uploaded reports are parsed in this process (`ingest_sandbox=False`, the mode
     `core.imports.jobs.parse_file` already has for Docker-less runs), on a thread standing in for
     the worker, through the real `core.imports.jobs.process_import`.
  4. The advisory feeds are not fetched: two real OSV records from `tests/fixtures/osv/` are stored
     at start-up through the real `core.advisories.store.upsert` -- Log4Shell (GHSA-jfh8-c2jp-5v3q,
     journey J7) and lodash's CVE-2021-23337 (GHSA-35jh-r3h4-6jhm, only the visual snapshot uses
     it, so its screen does not depend on which journeys ran first). Matching is the real code.
  5. GitHub's Issues API is an in-memory stand-in (`_FakeGitHubIssues`), set as
     `core.tickets.sync.TRANSPORT`, so filing a ticket runs the real ticket code end to end without
     calling github.com.

Usage: python scripts/e2e_server.py --port 8000
Prints "E2E_TOKEN=<token>" and "E2E_READY" to stdout once listening, for the caller to parse.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.llm.limits import UsageLimiter
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)
from core.persistence import repo
from core.persistence.models import ApiToken, Base
from core.tenancy import DEFAULT_ORG_ID
from core.tokens import hash_token, verify_checksum

TEST_TOKEN = (
    "e2e-test-token-not-a-real-secret-0123456789"  # local, in-memory DB only; dies with the process
)
# A personal token (the shared token is nobody, so it can't approve a risk acceptance -- Week 62's
# four-eyes rule). Fixed, so Playwright knows it; checksum-valid so it passes `core.tokens`'s
# format check; as fake as TEST_TOKEN and gone with the process. Must match playwright.config.ts.
APPROVER_TOKEN = "bulwark_e2e0approver0not0a0real0secret0000000000_0XGUOc"
APPROVER_NAME = "Priya N."


class _EmptySubscriber:
    """See module docstring (2). A real EventSubscriber never has to yield anything for a caller
    that only cares about the terminal state, which is exactly what polling then reads from the
    database -- the real source of truth either way (`web/lib/useScan.ts`'s own docstring)."""

    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield {}  # pragma: no cover - makes this an async generator; never reached


def _fixture_findings(scan_id: str) -> list[Finding]:
    """Two real, valid Findings (not scanner output -- see module docstring (1)) covering enough
    ground for J1 (a verdict) and J2 (a fix-first item with a location and remediation)."""
    return [
        Finding(
            id=f"e2e:sqli:{scan_id}",
            title="SQL injection in the login handler",
            description="User input reaches a raw SQL query without parameterization.",
            location=Location(
                "routes/auth.py",
                21,
                21,
                "cursor.execute(q)",
                Location.hash_snippet("cursor.execute(q)"),
            ),
            taxonomy=Taxonomy(Category.SAST, cwe=("CWE-89",)),
            scoring=Scoring(
                native_severity={"semgrep": "HIGH"},
                normalized_severity=Severity.HIGH,
                risk_score=82,
                risk_factors=["High severity", "Flagged by 1 scanner"],
                confidence=0.8,
            ),
            evidence=Evidence(
                reported_by=["semgrep"],
                agreement_count=1,
                rule_ids={"semgrep": ["python.sql-injection"]},
            ),
            remediation=Remediation(summary="Use a parameterized query."),
            fingerprint=f"e2e-sqli-{scan_id}",
        ),
        Finding(
            id=f"e2e:secret:{scan_id}",
            title="AWS access key committed in config.py",
            description="A credential matching AWS's access key format was found in source.",
            location=Location("config.py", 5, 5, "[snippet withheld: e2e fixture]", ""),
            taxonomy=Taxonomy(Category.SECRETS),
            scoring=Scoring(
                native_severity={"gitleaks": "CRITICAL"},
                normalized_severity=Severity.CRITICAL,
                risk_score=95,
                risk_factors=["Critical severity", "Secret is live"],
                confidence=0.95,
            ),
            evidence=Evidence(
                reported_by=["gitleaks"],
                agreement_count=1,
                rule_ids={"gitleaks": ["aws-access-key"]},
            ),
            remediation=Remediation(summary="Rotate the key, then remove it from history."),
            fingerprint=f"e2e-secret-{scan_id}",
        ),
    ]


def make_fake_enqueue(sessions: sessionmaker) -> Any:
    def _finish_later(scan_id: str) -> None:
        time.sleep(0.3)
        with sessions() as s:
            repo.mark_running(s, scan_id)
        time.sleep(1.2)
        with sessions() as s:
            for tool in ("semgrep", "gitleaks", "bandit", "trivy", "osv-scanner"):
                repo.add_tool_run(
                    s,
                    scan_id,
                    tool,
                    {"status": "ok", "findings": 1, "exit_code": 0, "duration_seconds": 1.1},
                )
            findings = _fixture_findings(scan_id)
            issues = repo.sync_issues_for_scan(s, scan_id, findings)
            repo.add_findings(s, scan_id, findings, issues.updates)
            repo.finish_scan(s, scan_id, "completed")

    def enqueue(scan_id: str, org_id: str) -> None:
        threading.Thread(target=_finish_later, args=(scan_id,), daemon=True).start()

    return enqueue


def _seed_approver(sessions: sessionmaker[Session]) -> None:
    assert verify_checksum(APPROVER_TOKEN), "APPROVER_TOKEN must pass core.tokens's checksum"
    with sessions() as s:
        s.add(
            ApiToken(
                org_id=DEFAULT_ORG_ID, name=APPROVER_NAME, token_hash=hash_token(APPROVER_TOKEN),
                display_prefix=APPROVER_TOKEN[: len("bulwark_") + 6],
                scopes=["scans:read", "scans:write"],
            )
        )  # fmt: skip
        s.commit()


ROOT = Path(__file__).resolve().parent.parent


def _seed_advisory(sessions: sessionmaker[Session]) -> None:
    """See module docstring (4)."""
    from core.advisories import osv, store

    for record, source in (
        ("GHSA-jfh8-c2jp-5v3q", "osv:Maven"),
        ("GHSA-35jh-r3h4-6jhm", "osv:npm"),
    ):
        advisory = osv.parse((ROOT / f"tests/fixtures/osv/{record}.json").read_bytes())
        assert advisory is not None
        with sessions() as s:
            store.upsert(s, [advisory], source=source)


def make_import_runner(sessions: sessionmaker[Session], settings: Settings) -> Any:
    """See module docstring (3)."""
    from core.imports.jobs import process_import

    def _run(import_id: str, org_id: str) -> None:
        time.sleep(0.2)
        with sessions() as s:
            process_import(s, import_id, org_id, settings)

    def enqueue(import_id: str, org_id: str) -> None:
        threading.Thread(target=_run, args=(import_id, org_id), daemon=True).start()

    return enqueue


class _FakeGitHubIssues:
    """See module docstring (5): GitHub's Issues API, in memory, for one process's lifetime."""

    _URL = re.compile(
        r"^https://api\.github\.com/repos/([^/]+/[^/]+)/issues(?:/(\d+))?(/comments)?$"
    )

    def __init__(self) -> None:
        self.issues: dict[tuple[str, int], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        m = self._URL.match(url.split("?", 1)[0])
        if m is None:
            return 404, None
        repo_name, number, comments = m.group(1), m.group(2), m.group(3)
        data = json.loads(body) if body else {}
        with self._lock:
            if number is None and method == "POST":
                n = 1 + sum(1 for r, _ in self.issues if r == repo_name)
                self.issues[(repo_name, n)] = {
                    "number": n,
                    "state": "open",
                    "labels": [],
                    "assignee": None,
                    "title": data.get("title", ""),
                    "html_url": f"https://github.com/{repo_name}/issues/{n}",
                }
                return 201, self.issues[(repo_name, n)]
            issue = self.issues.get((repo_name, int(number or 0)))
            if issue is None:
                return 404, None
            if comments:
                return 201, {"id": 1}
            if method == "PATCH":
                issue.update({k: v for k, v in data.items() if k in ("state", "title")})
            return 200, issue


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--web-origin", default="http://localhost:3000")
    args = ap.parse_args()

    # A real file, not `sqlite://` + StaticPool's one shared in-memory connection: uvicorn serves
    # requests from a thread pool, and the fake worker above adds its own background threads, so
    # multiple real, concurrent SQLite connections is the actual shape of this fixture's load --
    # StaticPool's single shared connection can't safely interleave transactions from more than one
    # of them ("cannot commit transaction - SQL statements in progress", a real failure this
    # surfaced under genuine parallelism, not a hypothetical). WAL mode plus a busy timeout is
    # SQLite's own documented answer to concurrent readers/writers on one file.
    db_path = Path(tempfile.mkdtemp(prefix="bulwark-e2e-db-")) / "e2e.sqlite3"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"timeout": 30})

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection: Any, _record: Any) -> None:
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    _seed_approver(sessions)
    _seed_advisory(sessions)
    import core.tickets.sync

    core.tickets.sync.TRANSPORT = _FakeGitHubIssues()

    settings = Settings(
        database_url=f"sqlite:///{db_path}", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="e2e", api_token=TEST_TOKEN, workdir=Path("/tmp/bulwark-e2e"),
        upload_dir=Path("/tmp/bulwark-e2e/uploads"), max_upload_bytes=50 * 1024 * 1024,
        cors_origins=(args.web_origin,), ingest_sandbox=False,
    )  # fmt: skip
    settings.workdir.mkdir(parents=True, exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)

    state = AppState(
        settings=settings, sessions=sessions, enqueue=make_fake_enqueue(sessions),
        subscriber=_EmptySubscriber(), llm=None, limiter=UsageLimiter(),
        enqueue_import=make_import_runner(sessions, settings),
    )  # fmt: skip
    app = create_app(state)

    print(f"E2E_TOKEN={TEST_TOKEN}", flush=True)
    print("E2E_READY", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
