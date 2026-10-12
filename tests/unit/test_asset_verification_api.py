"""POST /assets/web, GET/POST /assets/{id}/verification|verify (Week 49 task 1, plan §22.4)."""

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


def _client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    return TestClient(create_app(app_state))


def test_register_web_asset_returns_dns_instructions(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "dns_txt"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == "example.com"
    assert body["status"] == "pending"
    assert body["record_name"] == "_bulwark-challenge.example.com"
    assert body["record_value"].startswith("bulwark-site-verification=")
    assert body["well_known_url"] is None


def test_register_web_asset_returns_well_known_instructions(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "well_known"}
    )
    body = r.json()
    assert body["well_known_url"] == "https://example.com/.well-known/bulwark-verification.txt"
    assert body["file_content"]
    assert body["record_name"] is None


def test_get_verification_requires_a_prior_registration(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    create = client.post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "dns_txt"}
    )
    asset_id = create.json()["asset_id"]
    r = client.get(f"/assets/{asset_id}/verification", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_get_verification_404s_for_an_unregistered_asset(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).get(
        "/assets/00000000-0000-0000-0000-000000000000/verification", headers=AUTH
    )
    assert r.status_code == 404


def test_verify_now_runs_a_live_check_and_persists_success(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )
    client = _client(sessions, tmp_path)
    create = client.post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "dns_txt"}
    )
    asset_id = create.json()["asset_id"]
    r = client.post(f"/assets/{asset_id}/verify", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "verified"
    assert body["verified_at"] is not None

    # and it's durable -- a later GET sees the same persisted state
    r2 = client.get(f"/assets/{asset_id}/verification", headers=AUTH)
    assert r2.json()["status"] == "verified"


def test_verify_now_persists_failure_with_an_error_message(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ownership,
        "verify",
        lambda *a, **kw: ownership.VerificationOutcome(ok=False, error="no record found"),
    )
    client = _client(sessions, tmp_path)
    create = client.post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "dns_txt"}
    )
    asset_id = create.json()["asset_id"]
    r = client.post(f"/assets/{asset_id}/verify", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "failed"
    assert body["last_error"] == "no record found"
    assert body["verified_at"] is None


def test_assets_web_requires_auth(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    r = _client(sessions, tmp_path).post(
        "/assets/web", json={"domain": "example.com", "method": "dns_txt"}
    )
    assert r.status_code == 401


def test_register_web_asset_rejects_unknown_method(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).post(
        "/assets/web", headers=AUTH, json={"domain": "example.com", "method": "carrier_pigeon"}
    )
    assert r.status_code == 422


def test_a_web_targets_source_link_changes_without_resetting_verification(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import select

    from core.persistence import repo
    from core.persistence.models import AuditEntry
    from core.tenancy import DEFAULT_ORG_ID

    monkeypatch.setattr(ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True))
    client = _client(sessions, tmp_path)
    site = client.post("/assets/web", headers=AUTH,
                       json={"domain": "example.com", "method": "dns_txt"}).json()  # fmt: skip
    assert site["source_asset_id"] is None
    assert client.post(f"/assets/{site['asset_id']}/verify", headers=AUTH).status_code == 200
    with sessions() as s:
        code = repo.get_or_create_asset(s, source_type="git", source_label="https://github.com/a/b",
                                        org_id=DEFAULT_ORG_ID)  # fmt: skip
        other = repo.get_or_create_asset(s, source_type="archive", source_label="b.zip",
                                         org_id=DEFAULT_ORG_ID)  # fmt: skip
        elsewhere = repo.get_or_create_asset(s, source_type="git", source_label="https://x/y",
                                             org_id="another-org")  # fmt: skip
        s.commit()
        code_id, other_id, elsewhere_id = code.id, other.id, elsewhere.id
    url = f"/assets/{site['asset_id']}/source"

    r = client.put(url, headers=AUTH, json={"source_asset_id": code_id})
    assert r.status_code == 200, r.text
    assert (r.json()["source_asset_id"], r.json()["source_label"]) == (code_id, "https://github.com/a/b")
    assert r.json()["status"] == "verified"  # registering again would have reset this
    r = client.put(url, headers=AUTH, json={"source_asset_id": other_id})
    assert r.json()["source_label"] == "b.zip"
    got = client.get(f"/assets/{site['asset_id']}/verification", headers=AUTH).json()
    assert (got["source_asset_id"], got["status"]) == (other_id, "verified")
    r = client.put(url, headers=AUTH, json={"source_asset_id": None})
    assert (r.json()["source_asset_id"], r.json()["source_label"]) == (None, None)

    for bad, why in ((elsewhere_id, "not found"), (site["asset_id"], "code project"),
                     ("nope", "not found")):  # fmt: skip
        r = client.put(url, headers=AUTH, json={"source_asset_id": bad})
        assert r.status_code == 422 and why in r.json()["detail"], r.text
    r = client.put(f"/assets/{code_id}/source", headers=AUTH, json={"source_asset_id": other_id})
    assert r.status_code == 422 and "only a web target" in r.json()["detail"]
    assert client.put(url, json={"source_asset_id": code_id}).status_code == 401

    with sessions() as s:
        actions = list(s.scalars(select(AuditEntry.action).where(
            AuditEntry.target == site["asset_id"]).order_by(AuditEntry.seq)))  # fmt: skip
    assert actions == ["asset.source.linked", "asset.source.linked", "asset.source.unlinked"]
