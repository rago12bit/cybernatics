"""The real `run_dast_campaign_job` end to end, through the real egress proxy, against real Postgres
and a real local HTTP target (Week 49b, plan §22.4 follow-up) -- not mocks, with one deliberate,
disclosed exception: the live DNS/HTTP ownership re-check itself is stubbed to `ok=True`, the same
choice Week 49's own task 3 verification made, for the same reason -- a synthetic local target can
never pass a real DNS TXT or `.well-known` check, and that check's own real behavior (including a
real failure against `example.com`) is already fully proven in `tests/unit/test_dast_ownership.py`
and `tests/integration/test_asset_verification_rls_docker.py`. Everything else here is real: the
campaign row, the rate-limit check, a real `BackgroundProxy`, a real `zap-baseline.py` run against a
real local HTTP server through that proxy, real persistence, and a real audit-log entry for the
egress attempts the proxy actually refused.

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head (same
convention as this repo's other Docker-dependent integration tests) and a working Docker daemon.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.dast import ownership
from core.dast.pipeline import run_dast_campaign_job
from core.persistence import repo
from core.persistence.models import Scan
from core.tenancy import set_session_org


def _rls_test_db_url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _postgres_ready() -> bool:
    url = _rls_test_db_url()
    if not url:
        return False
    try:
        create_engine(url).connect().close()
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


pytestmark = [
    pytest.mark.skipif(
        not _postgres_ready(),
        reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable -- see "
        ".github/workflows/ci.yml's tenancy-rls job",
    ),
    pytest.mark.skipif(not _docker_available(), reason="docker is not available"),
]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>hello</body></html>")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def local_target() -> Iterator[int]:
    server = HTTPServer(("0.0.0.0", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    thread.join(timeout=2)


class _NullBus:
    def publish(self, scan_id: str, payload: dict[str, object]) -> None:
        pass


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def org(sessions: sessionmaker[Session]) -> Iterator[str]:
    org_id = f"dast-proxy-live-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, 'live', now())"),
            {"id": org_id},
        )
        s.commit()
    yield org_id
    with sessions() as s:
        set_session_org(s, org_id)
        s.execute(
            text("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE org_id = :o)"),
            {"o": org_id},
        )
        s.execute(
            text("DELETE FROM tool_runs WHERE scan_id IN (SELECT id FROM scans WHERE org_id = :o)"),
            {"o": org_id},
        )
        s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org_id})
        s.execute(
            text(
                "DELETE FROM asset_verifications WHERE asset_id IN "
                "(SELECT id FROM assets WHERE org_id = :o)"
            ),
            {"o": org_id},
        )
        s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org_id})
        # A campaign announces its Issues in the outbox (plan §41.1), which this predates.
        s.execute(text("DELETE FROM outbox_events WHERE org_id = :o"), {"o": org_id})
        s.commit()
    with sessions() as s:
        s.execute(text("DELETE FROM organizations WHERE id = :o"), {"o": org_id})
        s.commit()


def _scoped_factory(sessions: sessionmaker[Session], org_id: str):  # type: ignore[no-untyped-def]
    def factory() -> Session:
        s = sessions()
        set_session_org(s, org_id)
        return s

    return factory


def test_a_real_campaign_scans_through_the_real_egress_proxy_and_records_blocked_attempts(
    monkeypatch: pytest.MonkeyPatch,
    sessions: sessionmaker[Session],
    org: str,
    local_target: int,
) -> None:
    # The live DNS/HTTP check itself is stubbed -- see the module docstring for why this is the one
    # deliberate exception in an otherwise fully real test.
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )

    target_url = f"http://host.docker.internal:{local_target}/"
    with sessions() as s:
        set_session_org(s, org)
        web_asset, _ = repo.register_web_asset(
            s, domain="host.docker.internal", method="well_known", org_id=org
        )
        scan = Scan(
            org_id=org,
            source_type="web",
            source_ref=target_url,
            source_label="host.docker.internal",
            tools=["zap-baseline"],
            asset_id=web_asset.id,
            dast_mode="passive",
        )
        s.add(scan)
        s.commit()
        scan_id = scan.id

    status = run_dast_campaign_job(scan_id, _scoped_factory(sessions, org), _NullBus(), org_id=org)

    assert status == "completed"
    with sessions() as s:
        set_session_org(s, org)
        scan_row = repo.get_scan(s, scan_id, org_id=org)
        assert scan_row is not None
        assert scan_row.status == "completed"
        findings = s.execute(
            text("SELECT count(*) FROM findings WHERE scan_id = :sid"), {"sid": scan_id}
        ).scalar_one()
        assert findings > 0, "a real zap-baseline scan through the proxy still finds real issues"

        tool_run_names = {
            row[0]
            for row in s.execute(
                text("SELECT tool FROM tool_runs WHERE scan_id = :sid"), {"sid": scan_id}
            ).fetchall()
        }
        assert "zap-baseline" in tool_run_names
        # ZAP's own background "check for updates"/telemetry calls go out on the same proxy and are
        # not the verified target, so they're refused -- proven live in core.dast.adapters.zap's own
        # module docstring; this is that same refusal landing on the campaign's own record.
        assert "egress-proxy" in tool_run_names

        # audit_entries is a single global hash-chained ledger (ADR-0019), not org-scoped -- filter
        # by this campaign's own scan id rather than relying on RLS to narrow it.
        audit_actions = [
            row[0]
            for row in s.execute(
                text("SELECT action FROM audit_entries WHERE target = :sid ORDER BY seq"),
                {"sid": scan_id},
            ).fetchall()
        ]
        assert "dast.campaign.egress_blocked" in audit_actions
        assert "dast.campaign.completed" in audit_actions
