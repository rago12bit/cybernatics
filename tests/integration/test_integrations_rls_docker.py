"""integration_settings and external_issue_links (migration 0025), against REAL Postgres with real
RLS -- not the SQLite application-level tests in tests/unit/test_persistence_integrations.py, which
cannot exercise whether FORCE ROW LEVEL SECURITY actually stops one org's session from seeing
another's integration credentials or ticket links (Week 51 task 2, plan §23).

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as the non-superuser `bulwark_worker` role (ADR-0033) -- exactly the connection the real worker uses.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import set_session_org


def _rls_test_db_url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _postgres_ready() -> bool:
    url = _rls_test_db_url()
    if not url:
        return False
    try:
        create_engine(url).connect().close()
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_ready(),
    reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable -- see "
    ".github/workflows/ci.yml's tenancy-rls job",
)


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    a, b = f"integ-rls-a-{uuid.uuid4().hex[:8]}", f"integ-rls-b-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a, "n": "A"}, {"id": b, "n": "B"}],
        )
        s.commit()
    yield a, b
    with sessions() as s:
        for org in (a, b):
            set_session_org(s, org)
            s.execute(text("DELETE FROM external_issue_links WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM integration_settings WHERE org_id = :o"), {"o": org})
            s.execute(
                text(
                    "DELETE FROM issues WHERE asset_id IN (SELECT id FROM assets WHERE org_id = :o)"
                ),
                {"o": org},
            )
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def test_an_orgs_integration_settings_are_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.set_integration_settings(
            s, org_a, actor="token:a", github_token="ghp_secret", jira_api_token="atlassian_secret"
        )
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_integration_settings(s, org_b) is None
    with sessions() as s:
        set_session_org(s, org_a)
        row = repo.get_integration_settings(s, org_a)
        assert row is not None and row.github_token == "ghp_secret"


def _seed_issue(s: Session, org_id: str) -> str:
    from core.persistence.models import Asset, IssueRow

    asset = Asset(org_id=org_id, source_type="git", key=f"k-{org_id}", label="l")
    s.add(asset)
    s.flush()
    issue = IssueRow(
        asset_id=asset.id, fingerprint="f1", state="open", category="sast", severity="HIGH",
        path="a.py", title="t",
    )  # fmt: skip
    s.add(issue)
    s.commit()
    return issue.id


def test_an_orgs_external_issue_link_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        issue_id = _seed_issue(s, org_a)
        repo.create_external_link(
            s, issue_id=issue_id, org_id=org_a, provider="github",
            external_id="acme/app#7", external_url="https://x",
        )  # fmt: skip

    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_external_link_by_external_id(s, org_b, "github", "acme/app#7") is None

    with sessions() as s:
        set_session_org(s, org_a)
        link = repo.get_external_link_by_external_id(s, org_a, "github", "acme/app#7")
        assert link is not None and link.issue_id == issue_id


def test_a_fresh_connection_with_no_org_context_sees_no_integration_settings_at_all(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """An unset app.current_org must read as "see nothing," not "see everything" -- the same
    fail-closed guarantee every other RLS-protected table in this project has. A brand-new
    connection, never one reused from the pooled `sessions` fixture (core.tenancy.set_session_org's
    docstring explains why a pooled connection legitimately keeps a *previous* logical session's
    value -- this claim is specifically about a connection that never had any value set)."""
    org_a, _ = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.set_integration_settings(s, org_a, actor="token:a", github_token="ghp_secret")

    fresh_engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    try:
        with fresh_engine.connect() as conn:
            rows = list(conn.execute(text("SELECT * FROM integration_settings")))
    finally:
        fresh_engine.dispose()
    assert rows == []
