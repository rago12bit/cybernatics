"""SAST/DAST correlation end to end, against real Postgres and a real bandit scan (Week 49 task 4,
plan §22.4) -- not mocks, except for the DAST finding itself, which is a synthetic stand-in for a
real ZAP/Nuclei finding (already proven live in tests/integration/test_dast_adapters_live.py and
test_dast_proxy_live.py): reproducing "a real scanner reports CWE-78 against this exact route" needs
a real vulnerable live server, which this test's local app isn't (it's static source on disk).

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head -- same
convention as this repo's other Docker-dependent integration tests.
"""

from __future__ import annotations

import os
import shutil
import uuid
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.dast.pipeline import _confirm_sast_findings_at_runtime
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.persistence.storage import MemoryStore
from core.pipeline import run_scan_job
from core.tenancy import set_session_org

APP_SOURCE = """\
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    query = request.args.get("q")
    return subprocess.call(query, shell=True)
"""


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


pytestmark = pytest.mark.skipif(
    not _postgres_ready(),
    reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable -- see "
    ".github/workflows/ci.yml's tenancy-rls job",
)


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def org(sessions: sessionmaker[Session]) -> Iterator[str]:
    org_id = f"dast-sast-corr-{uuid.uuid4().hex[:8]}"
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
        s.execute(
            text("DELETE FROM issues WHERE asset_id IN (SELECT id FROM assets WHERE org_id = :o)"),
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
        # Scans and campaigns announce their Issues in the outbox (plan §41.1), which this predates.
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


def test_a_real_bandit_finding_is_confirmed_at_runtime_by_a_matching_dast_finding(
    sessions: sessionmaker[Session], org: str, tmp_path: Path
) -> None:
    zip_path = tmp_path / "app.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("app.py", APP_SOURCE)
    archive_copy = tmp_path / "app-upload-copy.zip"
    shutil.copy(zip_path, archive_copy)  # run_scan_job deletes the "uploaded" file when it's done

    with sessions() as s:
        set_session_org(s, org)
        sast_scan = repo.create_scan(
            s, source_type="archive", source_ref=str(archive_copy), source_label="app.zip",
            tools=["bandit"], org_id=org,
        )  # fmt: skip
        sast_scan_id, sast_asset_id = sast_scan.id, sast_scan.asset_id

    status = run_scan_job(
        sast_scan_id, _scoped_factory(sessions, org), MemoryStore(), _NullBus(), org_id=org
    )
    assert status == "completed"

    with sessions() as s:
        set_session_org(s, org)
        scan_row = repo.get_scan(s, sast_scan_id, org_id=org)
        assert scan_row is not None
        assert scan_row.route_map == [{"route": "/search", "path": "app.py", "line": 9}]

        web_asset, _ = repo.register_web_asset(
            s, domain="example.com", method="dns_txt", org_id=org, source_asset_id=sast_asset_id
        )
        web_asset_id = web_asset.id

    dast_finding = Finding(
        id="dast-synthetic-1",
        title="OS command injection",
        description="",
        location=Location(path="", start_line=0, end_line=0, route="/search"),
        taxonomy=Taxonomy(category=Category.DAST, cwe=("CWE-78",)),
    )
    _confirm_sast_findings_at_runtime(
        _scoped_factory(sessions, org), web_asset_id, "dast-scan-id", [dast_finding], org_id=org
    )

    with sessions() as s:
        set_session_org(s, org)
        rows = s.execute(
            text(
                "SELECT confirmed_at_runtime_at, confirmed_by_scan_id FROM issues "
                "WHERE asset_id = :a AND path = 'app.py' AND confirmed_at_runtime_at IS NOT NULL"
            ),
            {"a": sast_asset_id},
        ).fetchall()
        assert len(rows) >= 1, "at least the CWE-78 finding near the /search handler is confirmed"
        assert all(r.confirmed_by_scan_id == "dast-scan-id" for r in rows)


class _NullBus:
    def publish(self, scan_id: str, payload: dict[str, object]) -> None:
        pass
