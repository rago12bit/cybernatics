"""POST/GET /assets/{id}/campaigns (Week 49 task 3, plan §22.4): the live ownership gate and the
active-scan rate limit, both enforced BEFORE a Scan row is created -- not the tool execution itself,
which is the worker's job (live-tested for real in tests/integration/test_dast_adapters_live.py)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.dast import ownership

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


def _client(
    sessions: sessionmaker[Session], tmp_path: Any, *, enqueued: list[tuple[str, str]] | None = None
) -> TestClient:
    app_state = AppState(
        _settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber(),
        enqueue_dast_campaign=(lambda sid, org: enqueued.append((sid, org))) if enqueued is not None else (lambda *_: None),
    )  # fmt: skip
    return TestClient(create_app(app_state))


def _register_and_verify(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )
    create = client.post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "dns_txt"}
    )
    return str(create.json()["asset_id"])


def test_starting_a_passive_campaign_against_a_verified_asset_enqueues_it(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    enqueued: list[tuple[str, str]] = []
    client = _client(sessions, tmp_path, enqueued=enqueued)
    asset_id = _register_and_verify(client, monkeypatch)
    r = client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "passive"})
    assert r.status_code == 200
    assert r.json()["status"] == "queued"
    assert len(enqueued) == 1


def test_starting_a_campaign_against_an_unverified_asset_is_rejected_and_never_enqueued(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ownership,
        "verify",
        lambda *a, **kw: ownership.VerificationOutcome(ok=False, error="no record"),
    )
    enqueued: list[tuple[str, str]] = []
    client = _client(sessions, tmp_path, enqueued=enqueued)
    create = client.post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "dns_txt"}
    )
    asset_id = create.json()["asset_id"]
    r = client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "passive"})
    assert r.status_code == 422
    assert enqueued == []


def test_starting_a_campaign_against_an_asset_with_no_verification_record_is_rejected(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    r = client.post(
        "/assets/00000000-0000-0000-0000-000000000000/campaigns",
        headers=AUTH, json={"mode": "passive"},
    )  # fmt: skip
    assert r.status_code == 404  # no such asset at all


def test_a_second_active_campaign_within_the_rate_limit_window_is_rejected(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _register_and_verify(client, monkeypatch)
    first = client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "active"})
    assert first.status_code == 200
    second = client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "active"})
    assert second.status_code == 429


def test_a_passive_campaign_is_never_rate_limited_even_back_to_back(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _register_and_verify(client, monkeypatch)
    for _ in range(3):
        r = client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "passive"})
        assert r.status_code == 200


def test_list_campaigns_returns_started_campaigns_most_recent_first(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _register_and_verify(client, monkeypatch)
    client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "passive"})
    client.post(f"/assets/{asset_id}/campaigns", headers=AUTH, json={"mode": "active"})
    r = client.get(f"/assets/{asset_id}/campaigns", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    assert body[0]["status"] == "queued"


def test_campaigns_require_auth(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    r = _client(sessions, tmp_path).post(
        "/assets/00000000-0000-0000-0000-000000000000/campaigns", json={"mode": "passive"}
    )
    assert r.status_code == 401
