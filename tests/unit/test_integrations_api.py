"""GET/PUT /settings/integrations and the two inbound webhook receivers (Week 51 task 2, plan §23).

The GitHub inbound receiver's HMAC check is real crypto (core.github_app.verify_signature), computed
here exactly as a real GitHub webhook delivery would -- fully testable without any external account,
the same way tests/unit/test_api.py must already test the existing App webhook receiver.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


def _settings(tmp_path: Any) -> Settings:
    return Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip


def _client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    app_state = AppState(_settings(tmp_path), sessions, lambda sid, org: None, _FakeSubscriber())
    return TestClient(create_app(app_state))


def test_get_returns_everything_unconfigured_by_default(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).get("/settings/integrations", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["slack_configured"] is False
    assert body["github_configured"] is False
    assert body["jira_configured"] is False


def test_put_then_get_reflects_configured_state_without_echoing_secrets(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    r = client.put(
        "/settings/integrations", headers=AUTH,
        json={"slack_webhook_url": "https://hooks.slack.com/services/x",
              "github_token": "ghp_x", "github_issues_repo": "acme/app"},
    )  # fmt: skip
    assert r.status_code == 200
    body = r.json()
    assert body["slack_configured"] is True
    assert body["github_configured"] is True
    assert "slack_webhook_url" not in body
    assert "github_token" not in body
    assert body["github_issues_repo"] == "acme/app"


def test_put_rejects_a_slack_url_that_fails_ssrf_validation(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).put(
        "/settings/integrations", headers=AUTH, json={"slack_webhook_url": "http://hooks.slack.com/x"}
    )  # fmt: skip
    assert r.status_code == 422


def test_put_is_a_full_replace_clearing_fields_left_out(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    client.put(
        "/settings/integrations", headers=AUTH, json={"slack_webhook_url": "https://hooks.slack.com/x"}
    )  # fmt: skip
    r = client.put("/settings/integrations", headers=AUTH, json={"github_token": "x"})
    assert r.json()["slack_configured"] is False  # cleared by the second, full-replace PUT


def test_two_orgs_have_independent_integration_settings(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    client = _client(sessions, tmp_path)
    hdr_a = {**AUTH, "X-Bulwark-Org": "org-a"}
    hdr_b = {**AUTH, "X-Bulwark-Org": "org-b"}
    client.put(
        "/settings/integrations", headers=hdr_a,
        json={"slack_webhook_url": "https://hooks.slack.com/x"},
    )  # fmt: skip
    assert client.get("/settings/integrations", headers=hdr_a).json()["slack_configured"] is True
    assert client.get("/settings/integrations", headers=hdr_b).json()["slack_configured"] is False


def test_get_requires_auth(sessions: sessionmaker[Session], tmp_path: Any) -> None:
    assert _client(sessions, tmp_path).get("/settings/integrations").status_code == 401


def _github_signed(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _seed_github_link(sessions: sessionmaker[Session], *, secret: str = "whsec") -> str:
    with sessions() as s:
        from core.persistence.models import Asset, IssueRow, Organization

        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", github_token="ghp_x", github_issues_repo="acme/app",
            github_webhook_secret=secret,
        )  # fmt: skip
        asset = Asset(org_id=DEFAULT_ORG_ID, source_type="git", key="k", label="l")
        s.add(asset)
        s.flush()
        issue = IssueRow(
            asset_id=asset.id, fingerprint="f1", state="open", category="sast", severity="HIGH",
            path="a.py", title="t",
        )  # fmt: skip
        s.add(issue)
        s.commit()
        repo.create_external_link(
            s, issue_id=issue.id, org_id=DEFAULT_ORG_ID, provider="github",
            external_id="acme/app#7", external_url="https://x",
        )  # fmt: skip
        return issue.id


def test_github_issues_webhook_closes_the_link_on_a_real_hmac_verified_closed_event(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    issue_id = _seed_github_link(sessions)
    body = json.dumps(
        {"action": "closed", "issue": {"number": 7}, "repository": {"full_name": "acme/app"}}
    ).encode()
    r = _client(sessions, tmp_path).post(
        f"/integrations/github-issues/webhook/{DEFAULT_ORG_ID}",
        content=body,
        headers={
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": _github_signed(body, "whsec"),
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 200 and r.json()["status"] == "ok"
    with sessions() as s:
        link = repo.get_external_link(s, issue_id, "github")
        assert link is not None and link.external_status == "closed"


def test_github_issues_webhook_rejects_a_bad_signature(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    _seed_github_link(sessions)
    body = json.dumps(
        {"action": "closed", "issue": {"number": 7}, "repository": {"full_name": "acme/app"}}
    ).encode()
    r = _client(sessions, tmp_path).post(
        f"/integrations/github-issues/webhook/{DEFAULT_ORG_ID}",
        content=body,
        headers={
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": _github_signed(body, "wrong-secret"),
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 401


def test_github_issues_webhook_404s_when_not_configured(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    r = _client(sessions, tmp_path).post(
        f"/integrations/github-issues/webhook/{DEFAULT_ORG_ID}",
        content=b"{}",
        headers={"X-GitHub-Event": "issues", "X-Hub-Signature-256": "sha256=x"},
    )
    assert r.status_code == 404


def test_github_issues_webhook_ignores_a_non_issues_event(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    _seed_github_link(sessions)
    body = b"{}"
    r = _client(sessions, tmp_path).post(
        f"/integrations/github-issues/webhook/{DEFAULT_ORG_ID}",
        content=body,
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": _github_signed(body, "whsec"),
        },
    )
    assert r.status_code == 200 and r.json()["status"] == "ignored"


def _seed_jira_link(sessions: sessionmaker[Session], *, secret: str = "jsecret") -> str:
    with sessions() as s:
        from core.persistence.models import Asset, IssueRow, Organization

        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", jira_base_url="https://acme.atlassian.net",
            jira_email="e", jira_api_token="t", jira_project_key="SEC", jira_webhook_secret=secret,
        )  # fmt: skip
        asset = Asset(org_id=DEFAULT_ORG_ID, source_type="git", key="k", label="l")
        s.add(asset)
        s.flush()
        issue = IssueRow(
            asset_id=asset.id, fingerprint="f1", state="open", category="sast", severity="HIGH",
            path="a.py", title="t",
        )  # fmt: skip
        s.add(issue)
        s.commit()
        repo.create_external_link(
            s, issue_id=issue.id, org_id=DEFAULT_ORG_ID, provider="jira",
            external_id="SEC-9", external_url="https://x",
        )  # fmt: skip
        return issue.id


def test_jira_webhook_closes_the_link_when_status_category_is_done(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    issue_id = _seed_jira_link(sessions)
    payload = {
        "webhookEvent": "jira:issue_updated",
        "issue": {"key": "SEC-9", "fields": {"status": {"statusCategory": {"key": "done"}}}},
    }
    r = _client(sessions, tmp_path).post(
        f"/integrations/jira/webhook/{DEFAULT_ORG_ID}/jsecret", json=payload
    )
    assert r.status_code == 200 and r.json()["status"] == "ok"
    with sessions() as s:
        link = repo.get_external_link(s, issue_id, "jira")
        assert link is not None and link.external_status == "closed"


def test_jira_webhook_rejects_the_wrong_secret(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    _seed_jira_link(sessions)
    payload = {"webhookEvent": "jira:issue_updated", "issue": {"key": "SEC-9"}}
    r = _client(sessions, tmp_path).post(
        f"/integrations/jira/webhook/{DEFAULT_ORG_ID}/wrong-secret", json=payload
    )
    assert r.status_code == 401


def test_jira_webhook_ignores_a_non_issue_updated_event(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    _seed_jira_link(sessions)
    payload = {"webhookEvent": "jira:issue_created", "issue": {"key": "SEC-9"}}
    r = _client(sessions, tmp_path).post(
        f"/integrations/jira/webhook/{DEFAULT_ORG_ID}/jsecret", json=payload
    )
    assert r.status_code == 200 and r.json()["status"] == "ignored"


def test_a_token_that_may_only_run_scans_cannot_redirect_where_findings_go(
    sessions: sessionmaker[Session], tmp_path: Any
) -> None:
    """These settings decide where every scan's findings and tickets are sent: a CI token
    (scans:write) or a Member must not be able to point them at an address of their own."""
    with sessions() as s:
        _, member = repo.create_api_token(s, org_id=DEFAULT_ORG_ID, name="ci",
                                          scopes=["scans:read", "scans:write"])  # fmt: skip
        _, admin = repo.create_api_token(s, org_id=DEFAULT_ORG_ID, name="admin", scopes=["org:admin"])
    client = _client(sessions, tmp_path)
    body = {"github_token": "ghp_x", "github_issues_repo": "attacker/inbox"}
    r = client.put("/settings/integrations", headers={"Authorization": f"Bearer {member}"}, json=body)
    assert r.status_code == 403
    assert "org:admin" in r.json()["detail"]
    r = client.put("/settings/integrations", headers={"Authorization": f"Bearer {admin}"}, json=body)
    assert r.status_code == 200
    assert r.json()["github_issues_repo"] == "attacker/inbox"
