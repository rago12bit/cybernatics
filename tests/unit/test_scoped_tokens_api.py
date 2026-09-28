"""Scoped API tokens through the real API surface (Week 29 backfill, ADR-0018): org derivation,
scope enforcement, and revoked/expired rejection -- on top of the existing `X-Bulwark-Org` header
mechanism, which the legacy shared token still uses unchanged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.persistence import repo

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class FakeSubscriber:
    async def subscribe(self, scan_id: str):  # pragma: no cover - not exercised here
        return
        yield  # makes this an async generator; never reached


@pytest.fixture
def client(sessions: sessionmaker[Session], tmp_path: Path) -> TestClient:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "up", max_upload_bytes=1000,
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, FakeSubscriber()))
    return TestClient(app)


def _mk_token(sessions: sessionmaker[Session], org_id: str, scopes: list[str], **kw: Any) -> str:
    with sessions() as s:
        _, raw = repo.create_api_token(s, org_id=org_id, name="t", scopes=scopes, **kw)
    return raw


def test_a_scoped_token_authenticates_and_is_scoped_to_its_own_org(
    client: TestClient, sessions: sessionmaker[Session]
) -> None:
    raw = _mk_token(sessions, "org-a", ["scans:read", "scans:write"])
    hdr = {"Authorization": f"Bearer {raw}"}
    r = client.post(
        "/scans", headers=hdr, json={"source": {"type": "git", "url": "https://github.com/a/b"}}
    )
    assert r.status_code == 202
    sid = r.json()["id"]
    with sessions() as s:
        from core.persistence.models import Scan

        scan = s.get(Scan, sid)
        assert scan is not None and scan.org_id == "org-a"


def test_the_org_header_is_ignored_for_a_scoped_token_not_trusted_over_the_token_itself(
    client: TestClient, sessions: sessionmaker[Session]
) -> None:
    """A scoped token's org is authoritative -- a client can't override it by also sending
    X-Bulwark-Org, which would defeat the point of scoping the token to begin with."""
    raw = _mk_token(sessions, "org-a", ["scans:write"])
    hdr = {"Authorization": f"Bearer {raw}", "X-Bulwark-Org": "org-b"}
    sid = client.post(
        "/scans", headers=hdr, json={"source": {"type": "git", "url": "https://github.com/a/c"}}
    ).json()["id"]
    with sessions() as s:
        from core.persistence.models import Scan

        assert s.get(Scan, sid).org_id == "org-a"  # not org-b, despite the header


def test_a_token_without_the_write_scope_cannot_create_a_scan(
    client: TestClient, sessions: sessionmaker[Session]
) -> None:
    raw = _mk_token(sessions, "org-a", ["scans:read"])
    hdr = {"Authorization": f"Bearer {raw}"}
    r = client.post(
        "/scans", headers=hdr, json={"source": {"type": "git", "url": "https://github.com/a/b"}}
    )
    assert r.status_code == 403


def test_a_token_without_the_read_scope_cannot_list_scans(
    client: TestClient, sessions: sessionmaker[Session]
) -> None:
    raw = _mk_token(sessions, "org-a", ["scans:write"])
    r = client.get("/scans", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 403


def test_a_revoked_token_is_rejected(client: TestClient, sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        row, raw = repo.create_api_token(s, org_id="org-a", name="t", scopes=["scans:read"])
        repo.revoke_api_token(s, row.id)
    r = client.get("/scans", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 401


def test_an_expired_token_is_rejected(client: TestClient, sessions: sessionmaker[Session]) -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    raw = _mk_token(sessions, "org-a", ["scans:read"], expires_at=past)
    r = client.get("/scans", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 401


def test_a_malformed_or_unknown_token_is_a_clean_401_not_a_500(client: TestClient) -> None:
    for bad in ["bulwark_not_a_real_token_00000", "bulwark_" + "a" * 40 + "_zzzzzz", "garbage"]:
        r = client.get("/scans", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401


def test_the_legacy_shared_token_is_completely_unaffected(
    client: TestClient, sessions: sessionmaker[Session]
) -> None:
    """The original single-shared-token trust model (full access, header-selected org) must keep
    working exactly as it did before scoped tokens existed."""
    r = client.post(
        "/scans", headers=AUTH, json={"source": {"type": "git", "url": "https://github.com/a/d"}}
    )
    assert r.status_code == 202
    assert client.get("/scans", headers=AUTH).status_code == 200


def test_touching_a_token_records_last_used_at(
    client: TestClient, sessions: sessionmaker[Session]
) -> None:
    raw = _mk_token(sessions, "org-a", ["scans:read"])
    client.get("/scans", headers={"Authorization": f"Bearer {raw}"})
    with sessions() as s:
        from core.persistence.models import ApiToken

        row = s.query(ApiToken).filter_by(org_id="org-a").one()
        assert row.last_used_at is not None
