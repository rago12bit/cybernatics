"""POST/GET /assets/{asset_id}/copilot/conversations[/{id}/messages] (Week 44 task 3, plan §21.5).

core.copilot.session.clone_repo and core.copilot.service.ask are mocked here (their own real tests
cover cloning/caching and the tool-calling loop); this file is about the API layer's wiring: the
off-by-default gate, the hosted-only guard, 404/409 shapes, and that messages are actually persisted.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.codeintel.models import CodeGraph
from core.config import Settings
from core.copilot.service import CopilotAnswer, CopilotGiveUp
from core.copilot.session import CheckoutCache
from core.llm.client import AnthropicClient, LLMConfig
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


class NotAnthropicClient:
    """A duck-typed LLMClient that is NOT an AnthropicClient -- proves the endpoint's hosted-only
    guard actually checks the type, not just "is not None"."""

    model = "fake-local-model"

    def complete(self, system: str, user: str) -> Any:
        raise AssertionError("should not be called")


@pytest.fixture
def fresh_cache(monkeypatch: pytest.MonkeyPatch) -> CheckoutCache:
    cache = CheckoutCache()
    monkeypatch.setattr("core.copilot.session.default_cache", lambda: cache)
    return cache


@pytest.fixture
def clone_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        calls.append(source_ref)
        return dest

    monkeypatch.setattr("core.copilot.session.clone_repo", _clone)
    monkeypatch.setattr("core.copilot.session.analyze", lambda root: CodeGraph())
    return calls


def _settings(tmp_path: Any) -> Settings:
    return Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip


@pytest.fixture
def env(
    sessions: sessionmaker[Session],
    tmp_path: Any,
    fresh_cache: CheckoutCache,
    clone_calls: list[str],
):  # type: ignore[no-untyped-def]
    hosted = AnthropicClient(LLMConfig(enabled=True, api_key="sk-ant-t•••••••••••••••••••"))
    app_state = AppState(
        _settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber(), llm_copilot=hosted
    )
    return TestClient(create_app(app_state)), sessions, app_state


def _seed_asset_with_a_completed_scan(
    sessions: sessionmaker[Session], *, source_type: str = "git"
) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type=source_type, source_ref="https://example.com/x.git",
            source_label="acme/x", tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def test_copilot_disabled_returns_409(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    client = TestClient(create_app(app_state))
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    r = client.post(f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH)
    assert r.status_code == 409


def test_start_conversation_without_a_completed_scan_returns_409(env: Any) -> None:
    client, sessions, _ = env
    with sessions() as s:
        scan = repo.create_scan(
            s,
            source_type="git",
            source_ref="https://example.com/x.git",
            source_label="acme/x",
            tools=["bandit"],
            org_id=DEFAULT_ORG_ID,
        )  # fmt: skip -- never finished, so no completed scan exists
        asset_id = scan.asset_id
    r = client.post(f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH)
    assert r.status_code == 409


def test_start_conversation_needs_a_git_sourced_asset(env: Any) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions, source_type="archive")
    r = client.post(f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH)
    assert r.status_code == 409


def test_start_conversation_creates_a_real_row(env: Any) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    r = client.post(
        f"/assets/{asset_id}/copilot/conversations",
        json={"context_kind": "issue", "context_id": "ISS-1"},
        headers=AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["asset_id"] == asset_id
    assert body["context_kind"] == "issue" and body["context_id"] == "ISS-1"
    with sessions() as s:
        assert repo.get_conversation(s, body["id"]) is not None


def test_post_message_stores_both_turns_and_returns_the_cited_answer(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    conv_id = client.post(
        f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH
    ).json()["id"]

    monkeypatch.setattr(
        "core.copilot.service.ask",
        lambda client, ctx, q: CopilotAnswer(
            answer="here's what I found",
            citations=[{"kind": "issue", "issue_id": "ISS-1"}],
            tokens_used=17,
        ),
    )
    r = client.post(
        f"/assets/{asset_id}/copilot/conversations/{conv_id}/messages",
        json={"question": "what issues are open?"},
        headers=AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "assistant"
    assert body["content"] == "here's what I found"
    assert body["citations"] == [{"kind": "issue", "issue_id": "ISS-1", "path": None, "line": None}]

    listed = client.get(
        f"/assets/{asset_id}/copilot/conversations/{conv_id}/messages", headers=AUTH
    ).json()
    assert [m["role"] for m in listed] == ["user", "assistant"]
    assert listed[0]["content"] == "what issues are open?"


def test_post_message_when_the_model_gives_up_stores_an_honest_fallback(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    conv_id = client.post(
        f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH
    ).json()["id"]

    def _give_up(client: Any, ctx: Any, q: str) -> Any:
        raise CopilotGiveUp("no cited answer produced")

    monkeypatch.setattr("core.copilot.service.ask", _give_up)
    r = client.post(
        f"/assets/{asset_id}/copilot/conversations/{conv_id}/messages",
        json={"question": "what issues are open?"},
        headers=AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "assistant"
    assert "couldn't find a well-grounded answer" in body["content"]
    assert body["citations"] is None


def test_post_message_reuses_the_cached_checkout_across_two_messages(
    env: Any, monkeypatch: pytest.MonkeyPatch, clone_calls: list[str]
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    conv_id = client.post(
        f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH
    ).json()["id"]
    monkeypatch.setattr(
        "core.copilot.service.ask",
        lambda client, ctx, q: CopilotAnswer(answer="ok", citations=[], tokens_used=1),
    )
    for _ in range(2):
        r = client.post(
            f"/assets/{asset_id}/copilot/conversations/{conv_id}/messages",
            json={"question": "q"},
            headers=AUTH,
        )
        assert r.status_code == 200
    assert len(clone_calls) == 1


def test_post_message_to_an_unknown_conversation_returns_404(env: Any) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    r = client.post(
        f"/assets/{asset_id}/copilot/conversations/no-such-conversation/messages",
        json={"question": "q"},
        headers=AUTH,
    )
    assert r.status_code == 404


def test_local_backend_is_rejected_with_a_clear_409(
    sessions: sessionmaker[Session],
    tmp_path: Any,
    fresh_cache: CheckoutCache,
    clone_calls: list[str],
) -> None:
    app_state = AppState(
        _settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber(),
        llm_copilot=NotAnthropicClient(),
    )  # fmt: skip
    client = TestClient(create_app(app_state))
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    conv_id = client.post(
        f"/assets/{asset_id}/copilot/conversations", json={}, headers=AUTH
    ).json()["id"]
    r = client.post(
        f"/assets/{asset_id}/copilot/conversations/{conv_id}/messages",
        json={"question": "q"},
        headers=AUTH,
    )
    assert r.status_code == 409
    assert "hosted model" in r.json()["detail"]
