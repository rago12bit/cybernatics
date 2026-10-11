"""GET /assets/{asset_id}/attack-paths (Week 45 task 2, plan §21.6).

core.attackpath.checkout.clone_repo is faked here (writing real fixture files into the tempdir, so
the real core.codeintel.analyze still runs on real source -- the same style
test_attackpath_checkout.py and test_attackpath_service.py already use); this file is about the API
layer's wiring: 409/422 shapes and that narrative generation is best-effort, never a hard gate."""

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
from core.gitfetch import GitUrlError
from core.llm.client import Completion
from core.models import Category, Finding, Location, Scoring, Severity, Taxonomy
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


FLASK_APP = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/preview')\n"
    "def preview():\n"
    "    return helper()\n\n"
    "def helper():\n"
    "    return sink()\n\n"
    "def sink():\n"
    "    import requests\n"
    "    return requests.get('http://x')\n"
)


class FakeModel:
    model = "fake-model-1"

    def __init__(self, out: str = "ok") -> None:
        self.out = out
        self.calls = 0

    def complete(self, system: str, user: str) -> Completion:
        self.calls += 1
        return Completion(self.out, 10)


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


def _seed_asset_with_ssrf(sessions: sessionmaker[Session], *, source_type: str = "git") -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type=source_type, source_ref="https://example.com/x.git",
            source_label="acme/x", tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        scan_id, asset_id = scan.id, scan.asset_id
    assert asset_id is not None
    ssrf = Finding(
        "ssrf-1", "SSRF", "d", Location("app.py", 11, 11),
        Taxonomy(Category.SAST, cwe=("CWE-918",)),
        scoring=Scoring(normalized_severity=Severity.HIGH),
    )  # fmt: skip
    with sessions() as s:
        result = repo.sync_issues_for_scan(s, scan_id, [ssrf])
        repo.add_findings(s, scan_id, [ssrf], issue_updates=result.updates)
    return asset_id


def test_no_completed_scan_returns_409(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    client = TestClient(create_app(app_state))
    with sessions() as s:
        scan = repo.create_scan(
            s,
            source_type="git",
            source_ref="https://example.com/x.git",
            source_label="acme/x",
            tools=["bandit"],
            org_id=DEFAULT_ORG_ID,
        )  # fmt: skip -- never finished
        asset_id = scan.asset_id
    r = client.get(f"/assets/{asset_id}/attack-paths", headers=AUTH)
    assert r.status_code == 409


def test_non_git_source_returns_409(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    client = TestClient(create_app(app_state))
    asset_id = _seed_asset_with_ssrf(sessions, source_type="archive")
    r = client.get(f"/assets/{asset_id}/attack-paths", headers=AUTH)
    assert r.status_code == 409


def test_no_model_configured_still_returns_the_graph_without_narrative(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    client = TestClient(create_app(app_state))
    asset_id = _seed_asset_with_ssrf(sessions)
    r = client.get(f"/assets/{asset_id}/attack-paths", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["narrative"] is None
    assert body[0]["likelihood"] == "high" and body[0]["impact"] == "high"
    assert {n["kind"] for n in body[0]["nodes"]} == {"entrypoint", "issue", "cloud_resource"}


def test_model_configured_adds_a_narrative(
    sessions: sessionmaker[Session], tmp_path: Any, fake_clone: list[str]
) -> None:
    fake = FakeModel(
        "GET /preview reaches the SSRF issue, which exposes the Cloud metadata service "
        "(169.254.169.254)."
    )
    app_state = AppState(
        _settings(tmp_path),
        sessions,
        lambda sid, org: None,
        _FakeSubscriber(),
        llm_attack_path=fake,
    )
    client = TestClient(create_app(app_state))
    asset_id = _seed_asset_with_ssrf(sessions)
    r = client.get(f"/assets/{asset_id}/attack-paths", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body[0]["narrative"] is not None
    assert "SSRF issue" in body[0]["narrative"]
    assert fake.calls == 1


def test_git_url_error_returns_422(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _bad_clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        raise GitUrlError("blocked host")

    monkeypatch.setattr("core.attackpath.checkout.clone_repo", _bad_clone)
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    client = TestClient(create_app(app_state))
    asset_id = _seed_asset_with_ssrf(sessions)
    r = client.get(f"/assets/{asset_id}/attack-paths", headers=AUTH)
    assert r.status_code == 422


def test_a_failed_clone_returns_422_with_gits_reason(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repository that went private (or a host that is down) after it was scanned fails the clone
    with IngestError, not GitUrlError; only the latter was caught, so this answered 500."""
    from core.ingest import IngestError

    def _private(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        raise IngestError(
            "Couldn't clone this repository. Bulwark can only scan public repositories"
        )

    monkeypatch.setattr("core.attackpath.checkout.clone_repo", _private)
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    client = TestClient(create_app(app_state))
    r = client.get(f"/assets/{_seed_asset_with_ssrf(sessions)}/attack-paths", headers=AUTH)
    assert r.status_code == 422
    assert "can only scan public repositories" in r.json()["detail"]
