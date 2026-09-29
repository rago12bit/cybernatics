"""`GET /assets/{asset_id}/dependencies` (plan §20.5): the Dependencies screen's data, built from
`Scan.sbom_summary` -- see `core/pipeline.py::_process_sbom` for how that column is populated."""

from __future__ import annotations

from collections.abc import AsyncIterator
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


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover - makes this an async generator


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any):  # type: ignore[no-untyped-def]
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, _FakeSubscriber()))  # fmt: skip
    return TestClient(app), sessions


SUMMARY = {
    "components": 2,
    "ecosystems": {"pypi": 2},
    "packages": [
        {
            "name": "flask", "version": "2.0.0", "ecosystem": "pypi", "purl": "pkg:pypi/flask@2.0.0",
            "license": "BSD-3-Clause", "path": "requirements.txt", "relation": "direct",
            "depends_on": ["pkg:pypi/werkzeug@2.0.0"],
            "scorecard": {"score": 8.3, "checks": {"Maintained": 10.0}, "date": "2026-09-28"},
        },
        {
            "name": "werkzeug", "version": "2.0.0", "ecosystem": "pypi",
            "purl": "pkg:pypi/werkzeug@2.0.0", "license": "", "path": "requirements.txt",
            "relation": "transitive", "depends_on": [], "scorecard": None,
        },
    ],
}  # fmt: skip


def _run_scan_with_sbom(sessions: sessionmaker[Session], summary: dict[str, Any] | None) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="acme/api", tools=["syft"]
        )
        repo.set_sbom_summary(s, scan.id, summary)
        repo.finish_scan(s, scan.id, "completed")
        return scan.id


def test_dependencies_returns_the_latest_scans_sbom_summary(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    _run_scan_with_sbom(sessions, SUMMARY)
    asset_id = client.get("/assets", headers=AUTH).json()[0]["id"]
    r = client.get(f"/assets/{asset_id}/dependencies", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["components"] == 2
    assert body["ecosystems"] == {"pypi": 2}
    names = {p["name"] for p in body["packages"]}
    assert names == {"flask", "werkzeug"}
    flask = next(p for p in body["packages"] if p["name"] == "flask")
    assert flask["relation"] == "direct" and flask["scorecard"]["score"] == 8.3


def test_dependencies_is_empty_not_404_when_no_scan_ran_syft(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    _run_scan_with_sbom(sessions, None)  # a scan happened, but never populated sbom_summary
    asset_id = client.get("/assets", headers=AUTH).json()[0]["id"]
    r = client.get(f"/assets/{asset_id}/dependencies", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["components"] == 0 and body["packages"] == [] and body["ecosystems"] == {}


def test_dependencies_unknown_asset_id_is_404(env) -> None:  # type: ignore[no-untyped-def]
    client, _sessions = env
    r = client.get("/assets/not-a-real-uuid/dependencies", headers=AUTH)
    assert r.status_code == 404


def test_dependencies_requires_auth(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    _run_scan_with_sbom(sessions, SUMMARY)
    asset_id = client.get("/assets", headers=AUTH).json()[0]["id"]
    r = client.get(f"/assets/{asset_id}/dependencies")
    assert r.status_code in (401, 403)
