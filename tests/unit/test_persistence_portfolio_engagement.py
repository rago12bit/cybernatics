"""core.persistence.repo's Portfolio/Engagement functions (Week 53 task 3, plan §40 change C11,
ADR-0039). "Test" (plan §40/§42) is not a new table here -- see ToolRun.engagement_id's own
docstring -- so these tests also cover add_tool_run's new auto-engagement wiring."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import Organization
from core.tenancy import DEFAULT_ORG_ID


def _seed_asset(s: Session) -> str:
    s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
    s.commit()
    asset = repo.get_or_create_asset(
        s, source_type="git", source_label="a/b", org_id=DEFAULT_ORG_ID
    )
    return asset.id


def test_get_or_create_ci_engagement_creates_one_named_after_the_asset(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id = _seed_asset(s)
        engagement = repo.get_or_create_ci_engagement(s, asset_id=asset_id, org_id=DEFAULT_ORG_ID)
        assert engagement.engagement_type == "ci"
        assert engagement.status == "active"
        assert engagement.asset_id == asset_id
        assert "a/b" in engagement.name


def test_get_or_create_ci_engagement_is_idempotent(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id = _seed_asset(s)
        first = repo.get_or_create_ci_engagement(s, asset_id=asset_id, org_id=DEFAULT_ORG_ID)
        second = repo.get_or_create_ci_engagement(s, asset_id=asset_id, org_id=DEFAULT_ORG_ID)
        assert first.id == second.id
        all_engagements = repo.list_engagements_for_asset(s, asset_id, DEFAULT_ORG_ID)
        assert len(all_engagements) == 1


def test_create_engagement_refuses_the_reserved_ci_type(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id = _seed_asset(s)
        try:
            repo.create_engagement(
                s, org_id=DEFAULT_ORG_ID, asset_id=asset_id, name="x", engagement_type="ci"
            )
            raise AssertionError("expected ValueError")
        except ValueError as exc:
            assert "reserved" in str(exc)


def test_create_engagement_allows_pentest_and_audit_alongside_the_ci_one(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id = _seed_asset(s)
        repo.get_or_create_ci_engagement(s, asset_id=asset_id, org_id=DEFAULT_ORG_ID)
        pentest = repo.create_engagement(
            s,
            org_id=DEFAULT_ORG_ID,
            asset_id=asset_id,
            name="Q4 pentest",
            engagement_type="pentest",
        )
        assert pentest.engagement_type == "pentest"
        types = {
            e.engagement_type for e in repo.list_engagements_for_asset(s, asset_id, DEFAULT_ORG_ID)
        }
        assert types == {"ci", "pentest"}


def test_portfolio_create_list_get(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        p = repo.create_portfolio(s, org_id=DEFAULT_ORG_ID, name="Payments", description="d")
        assert repo.get_portfolio(s, p.id, DEFAULT_ORG_ID) is not None
        assert repo.get_portfolio(s, "nonexistent", DEFAULT_ORG_ID) is None
        assert [x.name for x in repo.list_portfolios(s, DEFAULT_ORG_ID)] == ["Payments"]


def test_add_tool_run_attaches_the_assets_ci_engagement_automatically(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://x", source_label="a/b",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.add_tool_run(s, scan.id, "bandit", {"status": "ok", "findings": 3})
        engagement = repo.get_or_create_ci_engagement(
            s, asset_id=scan.asset_id, org_id=DEFAULT_ORG_ID
        )
        tests = repo.list_tool_runs_for_engagement(s, engagement.id, DEFAULT_ORG_ID)
        assert [t.tool for t in tests] == ["bandit"]


def test_two_scans_of_the_same_asset_share_one_ci_engagement(
    sessions: sessionmaker[Session],
) -> None:
    """ "One CI engagement per project with one Test per scanner" (the plan's own words, Week 53
    task 3) -- a second scan of the same asset must not create a second "ci" engagement."""
    with sessions() as s:
        scan1 = repo.create_scan(
            s, source_type="git", source_ref="https://x", source_label="a/b",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.add_tool_run(s, scan1.id, "bandit", {"status": "ok", "findings": 1})
        scan2 = repo.create_scan(
            s, source_type="git", source_ref="https://x", source_label="a/b",
            tools=["semgrep"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        assert scan2.asset_id == scan1.asset_id  # same repo, same Asset identity
        repo.add_tool_run(s, scan2.id, "semgrep", {"status": "ok", "findings": 2})

        engagements = repo.list_engagements_for_asset(s, scan1.asset_id, DEFAULT_ORG_ID)
        assert len(engagements) == 1
        tests = repo.list_tool_runs_for_engagement(s, engagements[0].id, DEFAULT_ORG_ID)
        assert {t.tool for t in tests} == {"bandit", "semgrep"}


def test_list_tool_runs_for_engagement_never_leaks_another_orgs_tests(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        s.add(Organization(id="org-a", name="A"))
        s.add(Organization(id="org-b", name="B"))
        s.commit()
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://x", source_label="a/b",
            tools=["bandit"], org_id="org-a",
        )  # fmt: skip
        repo.add_tool_run(s, scan.id, "bandit", {"status": "ok", "findings": 1})
        engagement = repo.get_or_create_ci_engagement(s, asset_id=scan.asset_id, org_id="org-a")
        # Org B can't read org A's Test rows even with the right engagement id in hand.
        assert repo.list_tool_runs_for_engagement(s, engagement.id, "org-b") == []
        assert repo.get_engagement(s, engagement.id, "org-b") is None
        assert repo.get_engagement(s, engagement.id, "org-a") is not None
