"""core.persistence.repo's plugin allowlist functions (Week 51 task 1, plan §23)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import AuditEntry, Organization
from core.tenancy import DEFAULT_ORG_ID


def test_is_plugin_allowed_defaults_to_false_when_no_row_exists(
    sessions: sessionmaker[Session],
) -> None:
    """The opposite default sense of get_retention_days: no row means "not allowed," never a
    fallback-allowed default -- a plugin must be explicitly trusted before it ever runs."""
    with sessions() as s:
        assert repo.is_plugin_allowed(s, DEFAULT_ORG_ID, "some-plugin") is False


def test_set_then_get_reflects_the_new_value(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(
            s, DEFAULT_ORG_ID, "acme-trivy-plus", enabled=True, allowed_by="token:abc"
        )
    with sessions() as s:
        assert repo.is_plugin_allowed(s, DEFAULT_ORG_ID, "acme-trivy-plus") is True


def test_set_plugin_allowed_updates_in_place_not_duplicating_rows(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin", enabled=True, allowed_by="a")
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin", enabled=False, allowed_by="b")
    with sessions() as s:
        rows = repo.list_plugin_allowlist(s, DEFAULT_ORG_ID)
    assert len(rows) == 1
    assert rows[0].enabled is False and rows[0].allowed_by == "b"


def test_revoking_sets_enabled_false_rather_than_deleting_the_row(
    sessions: sessionmaker[Session],
) -> None:
    """Keeps a record of who revoked it and when -- an organization's trust decisions are audit
    history, not something that disappears when reversed."""
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin", enabled=True, allowed_by="a")
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin", enabled=False, allowed_by="a")
    with sessions() as s:
        assert repo.is_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin") is False
        [row] = repo.list_plugin_allowlist(s, DEFAULT_ORG_ID)
        assert row.plugin_name == "acme-plugin"


def test_two_orgs_have_independent_allowlists(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        s.add_all([Organization(id="org-a", name="A"), Organization(id="org-b", name="B")])
        s.commit()
        repo.set_plugin_allowed(s, "org-a", "acme-plugin", enabled=True, allowed_by="a")
    with sessions() as s:
        assert repo.is_plugin_allowed(s, "org-a", "acme-plugin") is True
        assert repo.is_plugin_allowed(s, "org-b", "acme-plugin") is False


def test_allowing_a_plugin_appends_an_audit_entry(sessions: sessionmaker[Session]) -> None:
    """Trusting code to run in the sandbox is security-relevant -- same audit trail every other
    security-relevant action in this project already goes through (core.persistence.repo.
    append_audit_entry), not a side channel of its own."""
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(
            s, DEFAULT_ORG_ID, "acme-plugin", enabled=True, allowed_by="token:abc"
        )
    with sessions() as s:
        entries = list(s.scalars(select(AuditEntry)))
    assert len(entries) == 1
    assert entries[0].action == "plugin.allow"
    assert entries[0].target == "acme-plugin"
    assert entries[0].actor == "token:abc"


def test_revoking_a_plugin_records_a_distinct_audit_action(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin", enabled=True, allowed_by="a")
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "acme-plugin", enabled=False, allowed_by="a")
    with sessions() as s:
        actions = [e.action for e in s.scalars(select(AuditEntry).order_by(AuditEntry.seq))]
    assert actions == ["plugin.allow", "plugin.revoke"]


def test_list_plugin_allowlist_is_ordered_and_scoped_to_one_org(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "zzz-plugin", enabled=True, allowed_by="a")
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "aaa-plugin", enabled=True, allowed_by="a")
    with sessions() as s:
        names = [row.plugin_name for row in repo.list_plugin_allowlist(s, DEFAULT_ORG_ID)]
    assert names == ["aaa-plugin", "zzz-plugin"]
