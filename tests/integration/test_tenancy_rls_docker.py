"""The automated cross-tenant leak test ADR-0013 committed to running on every pull request
(Week 29 backfill): against REAL Postgres with real Row-Level Security, not the SQLite
application-level test in `tests/unit/test_tenancy.py` (which is what protects the fast suite, but
proves nothing about RLS itself -- SQLite has no equivalent).

Needs `BULWARK_DATABASE_URL` pointed at a real Postgres already migrated to head, connected as the
non-superuser `bulwark_app` role (ADR-0013) -- exactly the connection the real API uses. Skips
everywhere else, the same way the Docker-dependent scanner integration tests do.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.persistence import repo
from core.tenancy import set_session_org

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


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
    reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable (needs a migrated Postgres, "
    "connected as bulwark_app) -- set up by .github/workflows/ci.yml's tenancy-rls job",
)


class FakeSubscriber:
    async def subscribe(self, scan_id: str):  # pragma: no cover - not exercised here
        return
        yield  # makes this an async generator; never reached


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    settings = Settings(
        database_url=_rls_test_db_url(), redis_url="", s3_endpoint=None, s3_access_key="",  # type: ignore[arg-type]
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "up", max_upload_bytes=1000,
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, FakeSubscriber()))
    return TestClient(app)


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    """`organizations` carries no RLS (ADR-0013/ADR-0017): this insert works over the same
    `bulwark_app` connection the test client itself uses, no admin role needed."""
    a, b = f"rls-test-a-{uuid.uuid4().hex[:8]}", f"rls-test-b-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a, "n": "A"}, {"id": b, "n": "B"}],
        )
        s.commit()
    yield a, b
    # DELETE is subject to RLS too (scans/assets carry it): without org context set, this would
    # silently match zero rows rather than error, leaving orphaned test data behind.
    with sessions() as s:
        for org in (a, b):
            set_session_org(s, org)
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def test_a_scan_created_in_one_org_returns_404_for_every_endpoint_under_another_org(
    client: TestClient, two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    hdr_a = {**AUTH, "X-Bulwark-Org": org_a}
    hdr_b = {**AUTH, "X-Bulwark-Org": org_b}

    sid = client.post(
        "/scans", headers=hdr_a, json={"source": {"type": "git", "url": "https://github.com/a/b"}}
    ).json()["id"]

    # Every endpoint that takes a scan id: org B gets 404, never 200, never a 500 from RLS
    # silently returning zero rows somewhere the code didn't expect it to.
    for method, path in [
        ("GET", f"/scans/{sid}"),
        ("GET", f"/scans/{sid}/findings"),
        ("GET", f"/scans/{sid}/export"),
        ("GET", f"/scans/{sid}/guidance?finding_id=x"),
    ]:
        r = client.request(method, path, headers=hdr_b)
        assert r.status_code == 404, f"{method} {path} returned {r.status_code}, not 404"

    # And org A can see its own scan throughout -- this isn't just "everything 404s."
    assert client.get(f"/scans/{sid}", headers=hdr_a).status_code == 200
    assert sid in {sc["id"] for sc in client.get("/scans", headers=hdr_a).json()}
    assert sid not in {sc["id"] for sc in client.get("/scans", headers=hdr_b).json()}


def test_two_orgs_scanning_the_same_public_repo_get_separate_assets_and_issue_history(
    client: TestClient, sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """The exact leak ADR-0013's own design pass caught before it shipped (Week 29's ADR text):
    Asset identity must be org-scoped, or one org's Issue history leaks into another's."""
    org_a, org_b = two_orgs
    url = "https://github.com/OWASP/NodeGoat"
    with sessions() as s:
        set_session_org(s, org_a)  # this direct repo call needs org context set explicitly,
        asset_a = repo.get_or_create_asset(s, source_type="git", source_label=url, org_id=org_a)
    with sessions() as s:
        set_session_org(s, org_b)  # like every other place that writes tenant-scoped data
        asset_b = repo.get_or_create_asset(s, source_type="git", source_label=url, org_id=org_b)
    assert asset_a.id != asset_b.id
