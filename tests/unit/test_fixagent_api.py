"""POST/GET /assets/{asset_id}/issues/{issue_id}/verified-fix[/approve|/reject] (plan §21.2).
`core.fixagent.client`'s Temporal calls are mocked here -- Temporal's own workflow logic has its own
real tests (test_fixagent_workflow.py, against a real time-skipping engine); this file is about the
API layer's wiring: auth scopes, 404/409/429/422 shapes, and what gets passed through to the
workflow.
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
from core.fixagent import client as fixagent_client
from core.fixagent import store as fixagent_store
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any):  # type: ignore[no-untyped-def]
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, _FakeSubscriber()))
    return TestClient(app), sessions


def _finding(path: str = "app/users.py") -> Finding:
    f = Finding(
        "f1", "SQL injection", "d", Location(path, 2, 2, "snippet"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip
    f.evidence.rule_ids = {"bandit": ["B608"]}
    f.evidence.reported_by = ["bandit"]
    return f


def _seed(sessions: sessionmaker[Session], *, github_linked: bool = False) -> tuple[str, str]:
    """Returns (asset_id, issue_id)."""
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        if github_linked:
            scan.github_repo = "acme/x"
            scan.github_installation_id = "inst-1"
            s.commit()
        f = _finding()
        result = repo.sync_issues_for_scan(s, scan.id, [f])
        repo.add_findings(s, scan.id, [f], issue_updates=result.updates)
        repo.finish_scan(s, scan.id, "completed")
        issue_id = next(u.issue_id for u in result.updates if u.finding_id == "f1")
        asset_id = scan.asset_id
    assert issue_id is not None and asset_id is not None
    return asset_id, issue_id


def _url(asset_id: str, issue_id: str, suffix: str = "") -> str:
    return f"/assets/{asset_id}/issues/{issue_id}/verified-fix{suffix}"


async def _fake_start(*args: Any, **kwargs: Any) -> str:
    return str(args[1])


def test_start_verified_fix_returns_run_and_workflow_ids(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    monkeypatch.setattr(fixagent_client, "start_verified_fix", _fake_start)
    r = client.post(_url(asset_id, issue_id), json={}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["run_id"] and body["workflow_id"].startswith(f"fixagent-{issue_id}")


def test_start_verified_fix_needs_a_completed_scan(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    with sessions() as s:
        asset_id = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="l", tools=["bandit"]
        ).asset_id
    from core.persistence.models import IssueRow

    with sessions() as s:
        issue = IssueRow(
            asset_id=asset_id, fingerprint="fp", state="open", category="sast", severity="HIGH",
            path="a.py", title="t", triage_status="open",
        )  # fmt: skip
        s.add(issue)
        s.commit()
        issue_id = issue.id
    r = client.post(_url(asset_id, issue_id), json={}, headers=AUTH)
    assert r.status_code == 409


def test_start_verified_fix_respects_the_concurrency_cap(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    monkeypatch.setenv("BULWARK_FIXAGENT_MAX_CONCURRENT_PER_ORG", "1")
    with sessions() as s:
        fixagent_store.create_run(s, DEFAULT_ORG_ID, issue_id, "wf-already-running")
    monkeypatch.setattr(fixagent_client, "start_verified_fix", _fake_start)
    r = client.post(_url(asset_id, issue_id), json={}, headers=AUTH)
    assert r.status_code == 429


def test_run_tests_without_a_verified_owner_asset_is_silently_downgraded_not_rejected(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions, github_linked=False)
    captured: dict[str, Any] = {}

    async def capture_start(*args: Any, **kwargs: Any) -> str:
        captured["run_tests"] = args[11]
        return "wf-1"

    monkeypatch.setattr(fixagent_client, "start_verified_fix", capture_start)
    r = client.post(
        _url(asset_id, issue_id),
        json={"run_tests": True, "test_image": "python:3.12", "test_command": "pytest"},
        headers=AUTH,
    )
    assert r.status_code == 200 and captured["run_tests"] is None


def test_run_tests_on_a_verified_owner_asset_needs_image_and_command(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions, github_linked=True)
    monkeypatch.setattr(fixagent_client, "start_verified_fix", _fake_start)
    r = client.post(_url(asset_id, issue_id), json={"run_tests": True}, headers=AUTH)
    assert r.status_code == 422


def test_run_tests_on_a_verified_owner_asset_is_passed_through_when_complete(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions, github_linked=True)
    captured: dict[str, Any] = {}

    async def capture_start(*args: Any, **kwargs: Any) -> str:
        captured["run_tests"] = args[11]
        return "wf-1"

    monkeypatch.setattr(fixagent_client, "start_verified_fix", capture_start)
    r = client.post(
        _url(asset_id, issue_id),
        json={"run_tests": True, "test_image": "python:3.12", "test_command": "pytest -q"},
        headers=AUTH,
    )
    assert r.status_code == 200
    assert captured["run_tests"] == {"image": "python:3.12", "command": "pytest -q"}


def test_get_verified_fix_returns_404_with_no_run(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    r = client.get(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 404


def test_get_verified_fix_returns_the_latest_runs_view(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    with sessions() as s:
        run = fixagent_store.create_run(s, DEFAULT_ORG_ID, issue_id, "wf-1")
        fixagent_store.update_run(s, run, status="awaiting_approval", attempts=1)
    r = client.get(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "awaiting_approval" and body["attempts"] == 1


def test_approve_needs_an_awaiting_approval_run(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    r = client.post(_url(asset_id, issue_id, "/approve"), headers=AUTH)
    assert r.status_code == 409


def test_approve_signals_the_real_workflow_id(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    with sessions() as s:
        run = fixagent_store.create_run(s, DEFAULT_ORG_ID, issue_id, "wf-approve-me")
        fixagent_store.update_run(s, run, status="awaiting_approval")
    signalled = []

    async def fake_approve(workflow_id: str) -> None:
        signalled.append(workflow_id)

    monkeypatch.setattr(fixagent_client, "approve", fake_approve)
    r = client.post(_url(asset_id, issue_id, "/approve"), headers=AUTH)
    assert r.status_code == 200 and signalled == ["wf-approve-me"]


def test_reject_signals_the_real_workflow_id(
    env, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    with sessions() as s:
        run = fixagent_store.create_run(s, DEFAULT_ORG_ID, issue_id, "wf-reject-me")
        fixagent_store.update_run(s, run, status="awaiting_approval")
    signalled = []

    async def fake_reject(workflow_id: str, reason: str = "") -> None:
        signalled.append(workflow_id)

    monkeypatch.setattr(fixagent_client, "reject", fake_reject)
    r = client.post(_url(asset_id, issue_id, "/reject"), headers=AUTH)
    assert r.status_code == 200 and signalled == ["wf-reject-me"]


def test_all_four_endpoints_need_the_token(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    asset_id, issue_id = _seed(sessions)
    assert client.post(_url(asset_id, issue_id), json={}).status_code == 401
    assert client.get(_url(asset_id, issue_id)).status_code == 401
    assert client.post(_url(asset_id, issue_id, "/approve")).status_code == 401
    assert client.post(_url(asset_id, issue_id, "/reject")).status_code == 401
