"""GET/PUT /settings/retention (Week 47 task 2, plan §22.2)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.persistence import repo
from core.persistence.models import DEFAULT_RETENTION_DAYS, AuditEntry
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


def _settings(tmp_path: Any) -> Settings:
    return Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip


def _client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    return TestClient(create_app(app_state))


def test_get_returns_the_default_when_never_set(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).get("/settings/retention", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["retention_days"] == DEFAULT_RETENTION_DAYS


def test_put_then_get_returns_the_new_value(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    client = _client(sessions, tmp_path)
    r = client.put("/settings/retention", headers=AUTH, json={"retention_days": 30})
    assert r.status_code == 200
    assert r.json()["retention_days"] == 30
    r2 = client.get("/settings/retention", headers=AUTH)
    assert r2.json()["retention_days"] == 30


def test_put_rejects_less_than_one(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    r = _client(sessions, tmp_path).put(
        "/settings/retention", headers=AUTH, json={"retention_days": 0}
    )
    assert r.status_code == 422


def test_two_orgs_have_independent_retention_settings(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    hdr_a = {**AUTH, "X-Bulwark-Org": "org-a"}
    hdr_b = {**AUTH, "X-Bulwark-Org": "org-b"}
    client.put("/settings/retention", headers=hdr_a, json={"retention_days": 90})
    r_a = client.get("/settings/retention", headers=hdr_a)
    r_b = client.get("/settings/retention", headers=hdr_b)
    assert r_a.json()["retention_days"] == 90
    assert r_b.json()["retention_days"] == DEFAULT_RETENTION_DAYS


def test_get_requires_auth(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    r = _client(sessions, tmp_path).get("/settings/retention")
    assert r.status_code == 401


def test_put_requires_auth(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    r = _client(sessions, tmp_path).put("/settings/retention", json={"retention_days": 7})
    assert r.status_code == 401


def _token(sessions: sessionmaker[Session], *scopes: str) -> dict[str, str]:
    with sessions() as s:
        _, raw = repo.create_api_token(s, org_id=DEFAULT_ORG_ID, name="t", scopes=list(scopes))
    return {"Authorization": f"Bearer {raw}"}


def test_a_token_that_may_only_run_scans_cannot_shorten_retention(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    """A day's retention makes the nightly sweep destroy every older scan's data key, which
    cannot be undone: a CI token (scans:write) or a Member must not be able to set it."""
    client = _client(sessions, tmp_path)
    r = client.put("/settings/retention", headers=_token(sessions, "scans:read", "scans:write"),
                   json={"retention_days": 1})  # fmt: skip
    assert r.status_code == 403
    assert "org:admin" in r.json()["detail"]
    assert client.get("/settings/retention", headers=AUTH).json()["retention_days"] == DEFAULT_RETENTION_DAYS


def test_an_admin_changes_retention_and_the_change_is_in_the_audit_log(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    r = client.put("/settings/retention", headers=_token(sessions, "org:admin"),
                   json={"retention_days": 3})  # fmt: skip
    assert r.status_code == 200
    with sessions() as s:
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "settings.retention_changed")).one()
    assert entry.target == DEFAULT_ORG_ID
    assert entry.actor.startswith("token:")  # who did it; the log keeps a digest of the payload only
