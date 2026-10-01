"""GET /plugins, PUT /plugins/{name}/allowlist (Week 51 task 1, plan §23).

Discovery and signing are faked here (via monkeypatch on api.main's own imported names) the same
way every other unit test in this suite fakes Docker/network-dependent code -- the real,
unmocked paths are proven live in tests/integration/test_plugin_signing_live.py and
tests/integration/test_plugin_sandbox_execution_live.py instead.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

import api.main as main_module
from api.deps import AppState
from api.main import create_app
from core.adapters.base import RepoContext, ToolSpec
from core.adapters.helpers import JsonAdapter
from core.config import Settings
from core.models import Finding
from core.plugins.manifest import PluginManifest
from core.plugins.signing import PluginSignatureError

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


class _FakePluginAdapter(JsonAdapter):
    spec = ToolSpec("demo-plugin", "example/demo:1", frozenset({"sast"}), frozenset({"python"}))

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return []

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return []

    def to_finding(self, r: dict[str, Any]) -> Finding:
        raise NotImplementedError


_MANIFEST = PluginManifest(
    adapter=_FakePluginAdapter(),
    package_name="demo-plugin-pkg",
    package_version="1.2.3",
    certificate_identity="https://github.com/acme/demo-plugin/.github/workflows/release.yml@refs/heads/main",
    certificate_oidc_issuer="https://token.actions.githubusercontent.com",
)


def _settings(tmp_path: Any) -> Settings:
    return Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip


def _client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    return TestClient(create_app(app_state))


@pytest.fixture(autouse=True)
def _one_discovered_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "discover_plugins", lambda: {"demo-plugin": _MANIFEST})


def test_list_plugins_shows_the_discovered_plugin_as_not_allowed_by_default(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).get("/plugins", headers=AUTH)
    assert r.status_code == 200
    [row] = r.json()
    assert row["name"] == "demo-plugin"
    assert row["package_name"] == "demo-plugin-pkg"
    assert row["image"] == "example/demo:1"
    assert row["allowed"] is False


def test_put_allowlist_verifies_signature_before_allowing(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "verify_plugin_image", lambda *a, **kw: [])
    client = _client(sessions, tmp_path)
    r = client.put("/plugins/demo-plugin/allowlist", headers=AUTH, json={"enabled": True})
    assert r.status_code == 200
    assert r.json()["allowed"] is True
    listed = client.get("/plugins", headers=AUTH).json()
    assert listed[0]["allowed"] is True


def test_put_allowlist_rejects_a_plugin_whose_signature_does_not_verify(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*a: Any, **kw: Any) -> None:
        raise PluginSignatureError("no matching signatures")

    monkeypatch.setattr(main_module, "verify_plugin_image", _boom)
    client = _client(sessions, tmp_path)
    r = client.put("/plugins/demo-plugin/allowlist", headers=AUTH, json={"enabled": True})
    assert r.status_code == 422
    assert "no matching signatures" in r.json()["detail"]
    listed = client.get("/plugins", headers=AUTH).json()
    assert listed[0]["allowed"] is False


def test_put_allowlist_revoke_never_calls_verify(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*a: Any, **kw: Any) -> None:
        raise AssertionError("revoking a plugin must never re-verify its signature")

    monkeypatch.setattr(main_module, "verify_plugin_image", _boom)
    r = _client(sessions, tmp_path).put(
        "/plugins/demo-plugin/allowlist", headers=AUTH, json={"enabled": False}
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is False


def test_put_allowlist_404s_for_an_undiscovered_plugin(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).put(
        "/plugins/nope/allowlist", headers=AUTH, json={"enabled": True}
    )
    assert r.status_code == 404


def test_two_orgs_have_independent_plugin_allowlists(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "verify_plugin_image", lambda *a, **kw: [])
    client = _client(sessions, tmp_path)
    hdr_a = {**AUTH, "X-Bulwark-Org": "org-a"}
    hdr_b = {**AUTH, "X-Bulwark-Org": "org-b"}
    client.put("/plugins/demo-plugin/allowlist", headers=hdr_a, json={"enabled": True})
    assert client.get("/plugins", headers=hdr_a).json()[0]["allowed"] is True
    assert client.get("/plugins", headers=hdr_b).json()[0]["allowed"] is False


def test_list_plugins_requires_auth(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    assert _client(sessions, tmp_path).get("/plugins").status_code == 401


def test_scan_creation_rejects_a_plugin_tool_not_yet_allowlisted(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).post(
        "/scans",
        headers=AUTH,
        json={"source": {"type": "git", "url": "https://github.com/a/b"}, "tools": ["demo-plugin"]},
    )
    assert r.status_code == 422
    assert "not allowlisted" in r.json()["detail"]


def test_scan_creation_accepts_an_allowlisted_plugin_tool(
    sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "verify_plugin_image", lambda *a, **kw: [])
    client = _client(sessions, tmp_path)
    client.put("/plugins/demo-plugin/allowlist", headers=AUTH, json={"enabled": True})
    r = client.post(
        "/scans",
        headers=AUTH,
        json={"source": {"type": "git", "url": "https://github.com/a/b"}, "tools": ["demo-plugin"]},
    )
    assert r.status_code == 202
