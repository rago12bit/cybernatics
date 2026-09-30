"""POST/GET /assets/{asset_id}/hypotheses[/generate|/{id}/promote|/{id}/dismiss] (plan §21.4).

`core.gitfetch.clone_repo` is mocked here (its own real tests cover SSRF guards and shallow-clone
behavior); this file is about the API layer's wiring: the off-by-default gate, auth scopes, 404/409
shapes, and that a promoted issue is real and org-scoped.
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
from core.config import Settings
from core.hypotheses.contract import HypothesisResult
from core.hypotheses.facts import Candidate
from core.hypotheses.service import HypothesisAssessment
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


class FakeModel:
    model = "fake-model-1"

    def complete(
        self, system: str, user: str
    ) -> Any:  # never actually called: generate_for_checkout is monkeypatched
        raise AssertionError("should not be called directly in these tests")


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any):  # type: ignore[no-untyped-def]
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    app_state = AppState(
        settings, sessions, lambda sid, org: None, _FakeSubscriber(), llm_hypotheses=FakeModel()
    )
    return TestClient(create_app(app_state)), sessions, app_state


def _seed_asset_with_a_completed_scan(sessions: sessionmaker[Session]) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def _fake_surfaced() -> list[tuple[Candidate, HypothesisAssessment]]:
    from core.codeintel.models import Entrypoint

    route = Entrypoint("app.py:delete_user:20", "flask", "DELETE", "/users/<id>")
    sibling = Entrypoint("app.py:list_users:10", "flask", "GET", "/users", ("login_required",))
    candidate = Candidate(route, "app.py", 20, (sibling,))
    result = HypothesisResult(
        True, "No auth decorator, unlike the sibling route.", "Check it manually.", "medium"
    )
    assessment = HypothesisAssessment(result, "def delete_user(id): ...", "fake-model-1", 12)
    return [(candidate, assessment)]


def test_generate_persists_surfaced_candidates(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    monkeypatch.setattr("core.gitfetch.clone_repo", lambda *a, **k: Path(a[1]))
    monkeypatch.setattr(
        "core.hypotheses.service.generate_for_checkout", lambda checkout, client: _fake_surfaced()
    )
    r = client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["generated"] == 1
    assert body["hypotheses"][0]["route_path"] == "/users/<id>"
    assert body["hypotheses"][0]["status"] == "open"

    listed = client.get(f"/assets/{asset_id}/hypotheses", headers=AUTH).json()
    assert len(listed) == 1


def test_disabled_when_no_model_is_configured(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    client = TestClient(
        create_app(AppState(settings, sessions, lambda sid, org: None, _FakeSubscriber()))
    )
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    r = client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    assert r.status_code == 409


def test_no_completed_scan_is_409(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    with sessions() as s:
        asset_id = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="l", tools=["bandit"]
        ).asset_id
    r = client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    assert r.status_code == 409


def test_promote_creates_a_real_issue(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    monkeypatch.setattr("core.gitfetch.clone_repo", lambda *a, **k: Path(a[1]))
    monkeypatch.setattr(
        "core.hypotheses.service.generate_for_checkout", lambda checkout, client: _fake_surfaced()
    )
    client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    hyp_id = client.get(f"/assets/{asset_id}/hypotheses", headers=AUTH).json()[0]["id"]

    r = client.post(f"/assets/{asset_id}/hypotheses/{hyp_id}/promote", headers=AUTH)
    assert r.status_code == 200
    issue_id = r.json()["issue_id"]

    issue = client.get(f"/assets/{asset_id}/issues/{issue_id}", headers=AUTH).json()
    assert issue["issue"]["id"] == issue_id

    listed = client.get(f"/assets/{asset_id}/hypotheses", headers=AUTH).json()
    assert listed[0]["status"] == "promoted" and listed[0]["promoted_issue_id"] == issue_id


def test_dismiss_marks_it_dismissed(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    monkeypatch.setattr("core.gitfetch.clone_repo", lambda *a, **k: Path(a[1]))
    monkeypatch.setattr(
        "core.hypotheses.service.generate_for_checkout", lambda checkout, client: _fake_surfaced()
    )
    client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    hyp_id = client.get(f"/assets/{asset_id}/hypotheses", headers=AUTH).json()[0]["id"]

    r = client.post(f"/assets/{asset_id}/hypotheses/{hyp_id}/dismiss", headers=AUTH)
    assert r.status_code == 200
    listed = client.get(f"/assets/{asset_id}/hypotheses", headers=AUTH).json()
    assert listed[0]["status"] == "dismissed"


def test_hypothesis_from_another_org_is_not_visible(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    monkeypatch.setattr("core.gitfetch.clone_repo", lambda *a, **k: Path(a[1]))
    monkeypatch.setattr(
        "core.hypotheses.service.generate_for_checkout", lambda checkout, client: _fake_surfaced()
    )
    client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    org_b = {**AUTH, "X-Bulwark-Org": "org-b"}
    assert client.get(f"/assets/{asset_id}/hypotheses", headers=org_b).status_code == 404


def test_requires_the_scans_write_scope_to_promote(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions, _ = env
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    monkeypatch.setattr("core.gitfetch.clone_repo", lambda *a, **k: Path(a[1]))
    monkeypatch.setattr(
        "core.hypotheses.service.generate_for_checkout", lambda checkout, client: _fake_surfaced()
    )
    client.post(f"/assets/{asset_id}/hypotheses/generate", headers=AUTH)
    hyp_id = client.get(f"/assets/{asset_id}/hypotheses", headers=AUTH).json()[0]["id"]
    with sessions() as s:
        _, raw = repo.create_api_token(s, org_id=DEFAULT_ORG_ID, name="ro", scopes=["scans:read"])
    r = client.post(
        f"/assets/{asset_id}/hypotheses/{hyp_id}/promote",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 403
