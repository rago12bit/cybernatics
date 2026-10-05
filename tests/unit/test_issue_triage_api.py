"""Week 34: the issues table and triage API (plan §28.3) -- /assets/{id}/issues,
/assets/{id}/issues/{issue_id}[/history], and the triage/bulk-triage endpoints.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

import api.main as api_main
from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.gitfetch import validate_git_url
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PUBLIC = lambda host: ["140.82.112.3"]  # noqa: E731


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(api_main, "validate_git_url", lambda url: validate_git_url(url, PUBLIC))
    settings = Settings(
        database_url="sqlite://",
        redis_url="",
        s3_endpoint=None,
        s3_access_key="",
        s3_secret_key="",
        s3_bucket="b",
        api_token=TOKEN,
        workdir=tmp_path,
        upload_dir=tmp_path / "uploads",
        max_upload_bytes=1000,
    )
    app = create_app(AppState(settings, sessions, lambda sid, org: None, _FakeSubscriber()))
    return TestClient(app), sessions, settings


def _finding(fid: str, path: str, sev: Severity, *, rule_id: str = "rule") -> Finding:
    f = Finding(
        fid,
        f"title {fid}",
        "desc",
        Location(path, 1, 1, snippet=f"snippet for {fid}"),
        Taxonomy(Category.SAST),
    )
    f.scoring.normalized_severity = sev
    f.scoring.risk_score = {"CRITICAL": 90, "HIGH": 70, "LOW": 20}[sev.value]
    f.evidence.rule_ids = {"bandit": [f"{rule_id}-{fid}"]}
    f.evidence.reported_by = ["bandit"]
    f.fingerprint = f"fp-{fid}"
    return f


def _seed(sessions: sessionmaker[Session]) -> tuple[str, str]:
    """One asset, one scan, two findings. Returns (asset_id, issue_id_of_f1)."""
    with sessions() as s:
        scan = repo.create_scan(
            s,
            source_type="git",
            source_ref="u",
            source_label="acme/app",
            tools=["bandit"],
            org_id=DEFAULT_ORG_ID,
        )
        findings = [
            _finding("f1", "a.py", Severity.CRITICAL),
            _finding("f2", "b.py", Severity.HIGH),
        ]
        result = repo.sync_issues_for_scan(s, scan.id, findings)
        repo.add_findings(s, scan.id, findings, issue_updates=result.updates)
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
        assert asset_id is not None
        issue_id = next(u.issue_id for u in result.updates if u.finding_id == "f1")
        return asset_id, issue_id


def test_list_issues_default_view_and_history(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)

    page = client.get(f"/assets/{asset_id}/issues", headers=AUTH).json()
    assert page["total"] == 2

    one = client.get(f"/assets/{asset_id}/issues/{issue_id}", headers=AUTH).json()
    assert one["id"] == "f1" and one["issue"]["id"] == issue_id

    history = client.get(f"/assets/{asset_id}/issues/{issue_id}/history", headers=AUTH).json()
    assert [h["label"] for h in history] == ["First seen"]


def test_not_a_risk_requires_a_reason_and_removes_it_from_the_active_queue(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)

    bad = client.post(
        f"/assets/{asset_id}/issues/{issue_id}/triage",
        headers=AUTH,
        json={"action": "not_a_risk"},
    )
    assert bad.status_code == 422

    ok = client.post(
        f"/assets/{asset_id}/issues/{issue_id}/triage",
        headers=AUTH,
        json={"action": "not_a_risk", "reason": "false positive: input is server-generated"},
    )
    assert ok.status_code == 200 and ok.json()["triage_status"] == "not_a_risk"

    active = client.get(f"/assets/{asset_id}/issues", headers=AUTH).json()
    assert active["total"] == 1 and active["items"][0]["id"] == "f2"

    triaged = client.get(f"/assets/{asset_id}/issues?triage=not_a_risk", headers=AUTH).json()
    assert triaged["total"] == 1 and triaged["items"][0]["id"] == "f1"

    history = client.get(f"/assets/{asset_id}/issues/{issue_id}/history", headers=AUTH).json()
    assert [h["label"] for h in history] == ["First seen", "Marked as not a risk"]


def test_accepting_needs_approval_and_an_accepted_issue_reappears_after_expiry(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)

    # Week 62 (plan §44.2): one person can no longer accept a risk through triage; it takes a
    # risk acceptance that someone else approves (tests/unit/test_risk_acceptance.py).
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    refused = client.post(
        f"/assets/{asset_id}/issues/{issue_id}/triage",
        headers=AUTH,
        json={"action": "accepted", "expires_at": future, "reason": "compensating control"},
    )
    assert refused.status_code == 409 and "approval" in refused.json()["detail"]

    # What an approved acceptance writes on the Issue still takes it out of the queue...
    with sessions() as s:
        repo.triage_issue(
            s, issue_id, org_id=DEFAULT_ORG_ID, action="accepted",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30), actor="token:approver",
        )  # fmt: skip
    assert client.get(f"/assets/{asset_id}/issues", headers=AUTH).json()["total"] == 1

    # ...and once its expiry passes it reappears in the active queue automatically (plan §28.3).
    with sessions() as s:
        row = repo.get_issue(s, issue_id)
        assert row is not None
        row.triage_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        s.commit()
    active = client.get(f"/assets/{asset_id}/issues", headers=AUTH).json()
    assert active["total"] == 2


def test_reopen_undoes_a_triage_decision(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    client.post(
        f"/assets/{asset_id}/issues/{issue_id}/triage",
        headers=AUTH,
        json={"action": "not_a_risk", "reason": "x"},
    )
    r = client.post(
        f"/assets/{asset_id}/issues/{issue_id}/triage", headers=AUTH, json={"action": "reopen"}
    )
    assert r.status_code == 200 and r.json()["triage_status"] == "open"
    assert client.get(f"/assets/{asset_id}/issues", headers=AUTH).json()["total"] == 2


def test_bulk_triage_handles_partial_failure(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    r = client.post(
        f"/assets/{asset_id}/issues/bulk-triage",
        headers=AUTH,
        json={
            "issue_ids": [issue_id, "00000000-0000-0000-0000-000000000000"],
            "action": "not_a_risk",
            "reason": "batch dismissal",
        },
    )
    body = r.json()
    assert body["updated"] == [issue_id]
    assert body["failed"] == [
        {"issue_id": "00000000-0000-0000-0000-000000000000", "error": "not found"}
    ]


def test_triage_is_org_scoped(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    org_b = {**AUTH, "X-Bulwark-Org": "org-b"}
    assert (
        client.post(
            f"/assets/{asset_id}/issues/{issue_id}/triage",
            headers=org_b,
            json={"action": "reopen"},
        ).status_code
        == 404
    )


def test_triage_requires_write_scope(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    asset_id, issue_id = _seed(sessions)
    assert (
        client.post(
            f"/assets/{asset_id}/issues/{issue_id}/triage", json={"action": "reopen"}
        ).status_code
        == 401
    )
