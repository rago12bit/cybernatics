"""core.persistence.repo's integration-settings and external-issue-link functions (Week 51 task 2,
plan §23)."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import AuditEntry, Organization
from core.tenancy import DEFAULT_ORG_ID


def _org(s: Session) -> None:
    s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
    s.commit()


def test_get_integration_settings_is_none_when_never_set(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        assert repo.get_integration_settings(s, DEFAULT_ORG_ID) is None


def test_set_then_get_reflects_the_new_values(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        _org(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="token:a",
            slack_webhook_url="https://hooks.slack.com/x", github_issues_repo="acme/app",
        )  # fmt: skip
    with sessions() as s:
        row = repo.get_integration_settings(s, DEFAULT_ORG_ID)
        assert row is not None
        assert row.slack_webhook_url == "https://hooks.slack.com/x"
        assert row.github_issues_repo == "acme/app"
        assert row.discord_webhook_url is None  # untouched field stays unset


def test_set_integration_settings_can_clear_a_field_with_none(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _org(s)
        repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="a", slack_webhook_url="https://x")
        repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="a", slack_webhook_url=None)
    with sessions() as s:
        row = repo.get_integration_settings(s, DEFAULT_ORG_ID)
        assert row is not None and row.slack_webhook_url is None


def test_set_integration_settings_updates_in_place_not_duplicating_rows(
    sessions: sessionmaker[Session],
) -> None:
    from core.persistence.models import IntegrationSettingsRow

    with sessions() as s:
        _org(s)
        repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="a", slack_webhook_url="https://1")
        repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="a", slack_webhook_url="https://2")
    with sessions() as s:
        rows = list(s.scalars(select(IntegrationSettingsRow)))
    assert len(rows) == 1
    assert rows[0].slack_webhook_url == "https://2"


def test_set_integration_settings_rejects_an_unknown_field(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _org(s)
        with pytest.raises(ValueError, match="unknown integration setting"):
            repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="a", not_a_real_field="x")  # type: ignore[call-arg]


def test_set_integration_settings_appends_an_audit_entry_naming_fields_but_not_values(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _org(s)
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="token:abc", jira_api_token="super-secret-value"
        )
    with sessions() as s:
        [entry] = list(s.scalars(select(AuditEntry)))
    assert entry.action == "integrations.settings_updated"
    assert entry.actor == "token:abc"
    assert entry.payload_digest  # the payload is hashed, not stored in the clear either way


def _issue(s: Session) -> str:
    from core.persistence.models import Asset, IssueRow

    asset = Asset(org_id=DEFAULT_ORG_ID, source_type="git", key="k", label="l")
    s.add(asset)
    s.flush()
    issue = IssueRow(
        asset_id=asset.id, fingerprint="f1", state="new", category="sast", severity="HIGH",
        path="app.py", title="SQL injection",
    )  # fmt: skip
    s.add(issue)
    s.commit()
    return issue.id


def test_create_and_get_external_link(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        _org(s)
        issue_id = _issue(s)
        repo.create_external_link(
            s, issue_id=issue_id, org_id=DEFAULT_ORG_ID, provider="github",
            external_id="acme/app#5", external_url="https://github.com/acme/app/issues/5",
        )  # fmt: skip
    with sessions() as s:
        link = repo.get_external_link(s, issue_id, "github")
        assert link is not None and link.external_id == "acme/app#5"
        assert link.external_status == "open"


def test_get_external_link_by_external_id_is_how_inbound_sync_finds_the_issue(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _org(s)
        issue_id = _issue(s)
        repo.create_external_link(
            s, issue_id=issue_id, org_id=DEFAULT_ORG_ID, provider="jira",
            external_id="SEC-42", external_url="https://acme.atlassian.net/browse/SEC-42",
        )  # fmt: skip
    with sessions() as s:
        link = repo.get_external_link_by_external_id(s, DEFAULT_ORG_ID, "jira", "SEC-42")
        assert link is not None and link.issue_id == issue_id
        assert repo.get_external_link_by_external_id(s, "other-org", "jira", "SEC-42") is None


def test_set_external_link_status_never_touches_issue_state(
    sessions: sessionmaker[Session],
) -> None:
    """ExternalIssueLinkRow.external_status is sync metadata only -- the authoritative
    IssueRow.state must be untouched by an inbound close/reopen event."""
    from core.persistence.models import IssueRow

    with sessions() as s:
        _org(s)
        issue_id = _issue(s)
        link = repo.create_external_link(
            s, issue_id=issue_id, org_id=DEFAULT_ORG_ID, provider="github",
            external_id="acme/app#5", external_url="https://x",
        )  # fmt: skip
        repo.set_external_link_status(s, link.id, "closed")
    with sessions() as s:
        refreshed = repo.get_external_link(s, issue_id, "github")
        assert refreshed is not None and refreshed.external_status == "closed"
        issue = s.get(IssueRow, issue_id)
        assert issue is not None and issue.state == "new"  # untouched
