"""Settings.hosted_mode (Week 53, ADR-0038): a hosted deployment's default SAST tool is Opengrep,
not Semgrep, and an explicit request for "semgrep" is refused outright -- Semgrep's community/Pro
rules are licensed for internal business use only (ADR-006), which a hosted deployment offering
scans to other people is not. Exercised at the real `_tools()` validation point, the same one
`POST /scans` and `POST /scans/upload` both call, via a real request through the app.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


def _settings(tmp_path: Any, *, hosted: bool) -> Settings:
    return Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=1000, hosted_mode=hosted,
    )  # fmt: skip


def _client(sessions: sessionmaker[Session], tmp_path: Any, *, hosted: bool) -> TestClient:
    app_state = AppState(
        _settings(tmp_path, hosted=hosted), sessions, lambda sid, org: None, _FakeSubscriber()
    )
    return TestClient(create_app(app_state))


def _create(client: TestClient, tools: list[str] | None = None) -> Any:
    body: dict[str, Any] = {"source": {"type": "git", "url": "https://github.com/a/b"}}
    if tools is not None:
        body["tools"] = tools
    return client.post("/scans", headers=AUTH, json=body)


def test_self_host_default_still_includes_semgrep(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path, hosted=False)
    r = _create(client)
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]
    assert "semgrep" in client.get(f"/scans/{scan_id}", headers=AUTH).json()["tools"]
    assert "opengrep" not in client.get(f"/scans/{scan_id}", headers=AUTH).json()["tools"]


def test_hosted_default_runs_opengrep_not_semgrep(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path, hosted=True)
    r = _create(client)
    assert r.status_code == 202, r.text
    tools = client.get(f"/scans/{r.json()['id']}", headers=AUTH).json()["tools"]
    assert "opengrep" in tools
    assert "semgrep" not in tools


def test_hosted_mode_refuses_an_explicit_request_for_semgrep(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path, hosted=True)
    r = _create(client, tools=["bandit", "semgrep"])
    assert r.status_code == 422
    assert "semgrep" in r.json()["detail"]
    assert "opengrep" in r.json()["detail"]


def test_self_host_mode_still_allows_an_explicit_request_for_semgrep(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path, hosted=False)
    r = _create(client, tools=["bandit", "semgrep"])
    assert r.status_code == 202, r.text


def test_hosted_mode_still_allows_an_explicit_request_for_opengrep(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path, hosted=True)
    r = _create(client, tools=["bandit", "opengrep"])
    assert r.status_code == 202, r.text


def test_hosted_mode_setting_defaults_to_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading from the environment, not just the dataclass default -- a deployment that never
    sets BULWARK_HOSTED_MODE must get the existing self-host behavior, unchanged."""
    monkeypatch.delenv("BULWARK_HOSTED_MODE", raising=False)
    assert Settings.from_env().hosted_mode is False


def test_hosted_mode_setting_reads_common_truthy_spellings(monkeypatch: pytest.MonkeyPatch) -> None:
    for value in ("1", "true", "True", "YES"):
        monkeypatch.setenv("BULWARK_HOSTED_MODE", value)
        assert Settings.from_env().hosted_mode is True, value
    monkeypatch.setenv("BULWARK_HOSTED_MODE", "0")
    assert Settings.from_env().hosted_mode is False
