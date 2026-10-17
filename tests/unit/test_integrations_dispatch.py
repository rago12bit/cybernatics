"""core.integrations.dispatch.notify_scan_result's own orchestration logic: which integrations fire,
in what order, and that one's failure never blocks another's. Each integration's own wire-level
behavior (Slack/Discord formatting, GitHub/Jira API calls) is unit-tested in its own
tests/unit/test_integrations_*.py file; this file monkeypatches those modules' entry points
entirely, so it's purely about dispatch's own decisions.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.integrations import dispatch
from core.issues import IssueUpdate, SyncResult
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.persistence.models import Asset, IssueRow, Organization
from core.tenancy import DEFAULT_ORG_ID


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid, title="SQL injection", description="d",
        location=Location("a.py", 1, 1, "code", "h"), taxonomy=Taxonomy(Category.SAST),
    )  # fmt: skip


def _setup_issue(s: Session) -> str:
    s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
    asset = Asset(org_id=DEFAULT_ORG_ID, source_type="git", key="k", label="l")
    s.add(asset)
    s.flush()
    issue = IssueRow(
        asset_id=asset.id, fingerprint="f1", state="new", category="sast", severity="HIGH",
        path="a.py", title="SQL injection",
    )  # fmt: skip
    s.add(issue)
    s.commit()
    return issue.id


def test_no_settings_row_means_nothing_fires(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(dispatch.slack, "send", lambda *a, **kw: calls.append("slack"))
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        sync = SyncResult(new_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", sync, {})
    assert calls == []


def test_slack_fires_when_configured_discord_does_not_when_unset(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(dispatch.slack, "send", lambda *a, **kw: calls.append("slack"))
    monkeypatch.setattr(dispatch.discord, "send", lambda *a, **kw: calls.append("discord"))
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", slack_webhook_url="https://hooks.example.com/x"
        )
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", SyncResult(), {})
    assert calls == ["slack"]


def test_one_integration_failing_does_not_block_another(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def boom(*a: Any, **kw: Any) -> None:
        raise RuntimeError("slack is down")

    monkeypatch.setattr(dispatch.slack, "send", boom)
    monkeypatch.setattr(dispatch.discord, "send", lambda *a, **kw: calls.append("discord"))
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a",
            slack_webhook_url="https://hooks.example.com/x",
            discord_webhook_url="https://discord.com/api/webhooks/x",
        )  # fmt: skip
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", SyncResult(), {})
    assert calls == ["discord"]  # slack's failure never stopped discord from firing


def test_outbound_webhook_fires_only_when_both_url_and_secret_are_set(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(dispatch, "deliver_signed", lambda *a, **kw: calls.append("webhook"))
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", outbound_webhook_url="https://receiver.example.com/x"
        )  # no secret set
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", SyncResult(), {})
    assert calls == []


def test_github_sync_creates_an_issue_for_a_new_issue_and_links_it(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    created = {}

    def fake_create_issue(repo_name: str, title: str, body: str, token: str, **kw: Any) -> Any:
        created["args"] = (repo_name, title, token)
        from core.integrations.github_issues import CreatedIssue

        return CreatedIssue(number=7, url="https://github.com/acme/app/issues/7")

    monkeypatch.setattr(dispatch.github_issues, "create_issue", fake_create_issue)
    with sessions() as s:
        issue_id = _setup_issue(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", github_token="ghp_x", github_issues_repo="acme/app"
        )
        f = _finding("bandit:a.py:1")
        update = IssueUpdate(
            finding_id=f.id, issue_id=issue_id, state="new", is_new_issue=True, fingerprint="f1"
        )
        sync = SyncResult(updates=[update], new_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", sync, {f.id: f})
    assert created["args"][0] == "acme/app"
    assert created["args"][2] == "ghp_x"
    with sessions() as s:
        link = repo.get_external_link(s, issue_id, "github")
        assert link is not None
        assert link.external_id == "acme/app#7"
        assert link.external_status == "open"


def test_github_sync_closes_the_linked_issue_when_fixed(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    closed = []
    monkeypatch.setattr(
        dispatch.github_issues, "set_issue_state",
        lambda repo_name, number, state, token, **kw: closed.append((repo_name, number, state)),
    )  # fmt: skip
    with sessions() as s:
        issue_id = _setup_issue(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", github_token="ghp_x", github_issues_repo="acme/app"
        )
        repo.create_external_link(
            s, issue_id=issue_id, org_id=DEFAULT_ORG_ID, provider="github",
            external_id="acme/app#7", external_url="https://x",
        )  # fmt: skip
        sync = SyncResult(fixed_issue_ids=[issue_id], fixed_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s2", sync, {})
    assert closed == [("acme/app", 7, "closed")]
    with sessions() as s:
        link = repo.get_external_link(s, issue_id, "github")
        assert link is not None and link.external_status == "closed"


def test_github_sync_skips_a_fixed_issue_that_was_already_marked_closed(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        dispatch.github_issues, "set_issue_state", lambda *a, **kw: calls.append("closed")
    )
    with sessions() as s:
        issue_id = _setup_issue(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", github_token="ghp_x", github_issues_repo="acme/app"
        )
        link = repo.create_external_link(
            s, issue_id=issue_id, org_id=DEFAULT_ORG_ID, provider="github",
            external_id="acme/app#7", external_url="https://x",
        )  # fmt: skip
        repo.set_external_link_status(s, link.id, "closed")
        sync = SyncResult(fixed_issue_ids=[issue_id], fixed_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s2", sync, {})
    assert calls == []  # never re-closes an already-closed link


def test_jira_sync_creates_a_ticket_for_a_new_issue_and_links_it(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_create_ticket(
        base: str, email: str, token: str, project: str, *a: Any, **kw: Any
    ) -> Any:
        from core.integrations.jira import CreatedTicket

        return CreatedTicket(key="SEC-9", url=f"{base}/browse/SEC-9")

    monkeypatch.setattr(dispatch.jira, "create_ticket", fake_create_ticket)
    monkeypatch.setattr(dispatch, "RESOLVER", lambda host: ["104.192.141.1"])
    with sessions() as s:
        issue_id = _setup_issue(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", jira_base_url="https://acme.atlassian.net",
            jira_email="ops@acme.com", jira_api_token="tok", jira_project_key="SEC",
        )  # fmt: skip
        f = _finding("bandit:a.py:1")
        update = IssueUpdate(
            finding_id=f.id, issue_id=issue_id, state="new", is_new_issue=True, fingerprint="f1"
        )
        sync = SyncResult(updates=[update], new_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", sync, {f.id: f})
    with sessions() as s:
        link = repo.get_external_link(s, issue_id, "jira")
        assert link is not None and link.external_id == "SEC-9"


def test_jira_sync_requires_all_four_jira_fields_to_be_set(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(dispatch.jira, "create_ticket", lambda *a, **kw: calls.append("x"))
    with sessions() as s:
        issue_id = _setup_issue(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", jira_base_url="https://acme.atlassian.net"
        )  # missing email/token/project
        f = _finding("bandit:a.py:1")
        update = IssueUpdate(
            finding_id=f.id, issue_id=issue_id, state="new", is_new_issue=True, fingerprint="f1"
        )
        sync = SyncResult(updates=[update], new_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", sync, {f.id: f})
    assert calls == []


def test_a_jira_address_that_now_points_inside_the_network_files_nothing(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The address was checked when it was saved, but a name can point elsewhere since: it is
    checked again before the credentials are sent to it."""
    calls: list[str] = []
    monkeypatch.setattr(dispatch.jira, "create_ticket", lambda *a, **kw: calls.append("x"))
    monkeypatch.setattr(dispatch, "RESOLVER", lambda host: ["169.254.169.254"])
    with sessions() as s:
        issue_id = _setup_issue(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="a", jira_base_url="https://acme.atlassian.net",
            jira_email="ops@acme.com", jira_api_token="tok", jira_project_key="SEC",
        )  # fmt: skip
        f = _finding("bandit:a.py:1")
        update = IssueUpdate(
            finding_id=f.id, issue_id=issue_id, state="new", is_new_issue=True, fingerprint="f1"
        )
        sync = SyncResult(updates=[update], new_count=1)
        dispatch.notify_scan_result(s, DEFAULT_ORG_ID, "acme/app", "s1", sync, {f.id: f})
        assert repo.get_external_link(s, issue_id, "jira") is None
    assert calls == []
