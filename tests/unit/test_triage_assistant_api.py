"""POST/GET /assets/{asset_id}/issues/{issue_id}/triage-assistant (plan §21.3). The model call
itself is a fake client (its own real tests live in test_triage_assistant_service.py); this file is
about the API layer's wiring: auth scopes, 404/409 shapes, persistence, and that a generated verdict
never touches `triage_status`.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.llm.client import Completion
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}

VALID_REPLY = json.dumps(
    {
        "verdict": "likely_false_positive",
        "confidence": "high",
        "rationale": "The input is parameterized before reaching the sink.",
        "supporting_lines": [2],
    }
)


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


class FakeModel:
    model = "fake-model-1"

    def __init__(self, out: str | Exception = VALID_REPLY) -> None:
        self.out = out
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> Completion:
        self.calls.append((system, user))
        if isinstance(self.out, Exception):
            raise self.out
        return Completion(self.out, 10)


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any):  # type: ignore[no-untyped-def]
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    app_state = AppState(
        settings, sessions, lambda sid, org: None, _FakeSubscriber(), llm_triage=FakeModel()
    )
    return TestClient(create_app(app_state)), sessions, app_state


def _finding(path: str = "app/users.py") -> Finding:
    f = Finding(
        "f1", "SQL injection", "d", Location(path, 2, 2, "snippet"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip
    f.evidence.rule_ids = {"bandit": ["B608"]}
    f.evidence.reported_by = ["bandit"]
    return f


def _seed(sessions: sessionmaker[Session]) -> tuple[str, str]:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        f = _finding()
        result = repo.sync_issues_for_scan(s, scan.id, [f])
        repo.add_findings(s, scan.id, [f], issue_updates=result.updates)
        repo.finish_scan(s, scan.id, "completed")
        issue_id = next(u.issue_id for u in result.updates if u.finding_id == "f1")
        asset_id = scan.asset_id
    assert issue_id is not None and asset_id is not None
    return asset_id, issue_id


def _url(asset_id: str, issue_id: str) -> str:
    return f"/assets/{asset_id}/issues/{issue_id}/triage-assistant"


def test_generates_and_stores_a_verdict(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    r = client.post(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "likely_false_positive"
    assert body["confidence"] == "high"
    assert body["supporting_lines"] == [2]
    assert body["model"] == "fake-model-1"

    # Persisted: a GET without a further model call returns the same verdict.
    got = client.get(_url(asset_id, issue_id), headers=AUTH)
    assert got.status_code == 200 and got.json()["verdict"] == "likely_false_positive"


def test_never_changes_triage_status(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    client.post(_url(asset_id, issue_id), headers=AUTH)
    issue = client.get(f"/assets/{asset_id}/issues/{issue_id}", headers=AUTH).json()
    assert issue["issue"]["triage_status"] == "open"


def test_get_before_any_verdict_is_404(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    r = client.get(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 404


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
    asset_id, issue_id = _seed(sessions)
    r = client.post(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 409


def test_no_completed_scan_is_409(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
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
    r = client.post(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 409


def test_a_reply_that_never_passes_the_contract_is_503(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, app_state = env
    asset_id, issue_id = _seed(sessions)
    app_state.llm_triage = FakeModel("not json")
    r = client.post(_url(asset_id, issue_id), headers=AUTH)
    assert r.status_code == 503


def test_requires_the_scans_write_scope(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    with sessions() as s:
        _, raw = repo.create_api_token(s, org_id=DEFAULT_ORG_ID, name="ro", scopes=["scans:read"])
    r = client.post(_url(asset_id, issue_id), headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 403


def test_org_scoped_issue_is_not_visible_to_another_org(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    r = client.post(_url(asset_id, issue_id), headers={**AUTH, "X-Bulwark-Org": "org-b"})
    assert r.status_code == 404
