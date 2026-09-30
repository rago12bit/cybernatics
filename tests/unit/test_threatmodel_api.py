"""GET/POST/PUT /assets/{asset_id}/threat-model (Week 45 task 3, plan §21.7).

core.attackpath.checkout.clone_repo is faked here (writing a real fixture into the tempdir, so the
real core.codeintel.analyze/core.threatmodel.generate still run on real source); this file is about
the API layer's wiring: auto-generate-on-first-access, that regenerate discards edits, and that a
saved edit persists until the next explicit regenerate."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}

FLASK_APP = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users', methods=['GET'])\n"
    "def list_users():\n"
    "    cursor.execute('SELECT * FROM users')\n"
)


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


@pytest.fixture
def fake_clone(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        calls.append(source_ref)
        (dest / "app.py").write_text(FLASK_APP)
        return dest

    monkeypatch.setattr("core.attackpath.checkout.clone_repo", _clone)
    return calls


def _settings(tmp_path: Any) -> Settings:
    return Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip


def _asset(sessions: sessionmaker[Session], *, source_type: str = "git") -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type=source_type, source_ref="https://example.com/x.git",
            source_label="acme/x", tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def _client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    return TestClient(create_app(app_state))


def test_no_completed_scan_returns_409(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    client = _client(sessions, tmp_path)
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip -- never finished
        asset_id = scan.asset_id
    r = client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    assert r.status_code == 409


def test_non_git_source_returns_409(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _asset(sessions, source_type="archive")
    r = client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    assert r.status_code == 409


def test_first_get_auto_generates_and_persists(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _asset(sessions)
    r = client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "generated"
    assert body["version"] == 1
    assert "user([User])" in body["mermaid"]
    assert "db[(Database)]" in body["mermaid"]
    assert len(fake_clone) == 1
    with sessions() as s:
        assert repo.get_threat_model(s, asset_id) is not None


def test_second_get_returns_the_persisted_row_without_recloning(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _asset(sessions)
    client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    r = client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["version"] == 1
    assert len(fake_clone) == 1, "second GET must not re-clone/regenerate"


def test_put_saves_an_edit_and_bumps_version(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _asset(sessions)
    client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    r = client.put(
        f"/assets/{asset_id}/threat-model",
        json={"mermaid": "flowchart LR\n    x", "stride": [{
            "element": "x", "element_kind": "process", "category": "Spoofing", "prompt": "?",
        }]},
        headers=AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "edited"
    assert body["version"] == 2
    assert body["mermaid"] == "flowchart LR\n    x"

    r2 = client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    assert r2.json()["source"] == "edited"
    assert r2.json()["mermaid"] == "flowchart LR\n    x"
    assert len(fake_clone) == 1, "GET after an edit must not silently regenerate over it"


def test_regenerate_discards_an_edit(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    client = _client(sessions, tmp_path)
    asset_id = _asset(sessions)
    client.get(f"/assets/{asset_id}/threat-model", headers=AUTH)
    client.put(
        f"/assets/{asset_id}/threat-model",
        json={"mermaid": "flowchart LR\n    x", "stride": []},
        headers=AUTH,
    )
    r = client.post(f"/assets/{asset_id}/threat-model/regenerate", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "generated"
    assert body["version"] == 3
    assert "user([User])" in body["mermaid"]
    assert len(fake_clone) == 2
