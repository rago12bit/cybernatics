"""Web asset registration and ownership verification persistence (Week 49 task 1, ADR-0035)."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo


def test_register_web_asset_creates_a_pending_verification(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset, verification = repo.register_web_asset(
            s, domain="example.com", method="dns_txt", org_id="org-a"
        )
        assert asset.source_type == "web"
        assert asset.key == "example.com"
        assert verification.asset_id == asset.id
        assert verification.method == "dns_txt"
        assert verification.status == "pending"
        assert verification.token
        assert verification.verified_at is None


def test_registering_the_same_domain_twice_reuses_the_asset_but_issues_a_new_token(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset1, v1 = repo.register_web_asset(s, domain="example.com", method="dns_txt", org_id="o")
        first_token = v1.token  # `merge()` returns the same tracked instance on the 2nd call too,
        # so this must be captured as a plain string before re-registering mutates it in place.
        asset2, v2 = repo.register_web_asset(
            s, domain="example.com", method="well_known", org_id="o"
        )
        assert asset1.id == asset2.id
        assert v2.token != first_token
        assert v2.method == "well_known"
        assert v2.status == "pending"


def test_two_orgs_registering_the_same_domain_get_separate_assets(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_a, _ = repo.register_web_asset(s, domain="example.com", method="dns_txt", org_id="a")
        asset_b, _ = repo.register_web_asset(s, domain="example.com", method="dns_txt", org_id="b")
        assert asset_a.id != asset_b.id


def test_record_verification_check_marks_verified_and_sets_verified_at_once(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset, verification = repo.register_web_asset(
            s, domain="example.com", method="dns_txt", org_id="o"
        )
        updated = repo.record_verification_check(s, verification, ok=True, error=None)
        assert updated.status == "verified"
        assert updated.verified_at is not None
        first_verified_at = updated.verified_at

        # a later re-check that still passes doesn't move verified_at forward
        updated2 = repo.record_verification_check(s, updated, ok=True, error=None)
        assert updated2.verified_at == first_verified_at


def test_record_verification_check_marks_failed_with_error(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, verification = repo.register_web_asset(
            s, domain="example.com", method="dns_txt", org_id="o"
        )
        updated = repo.record_verification_check(s, verification, ok=False, error="no record")
        assert updated.status == "failed"
        assert updated.last_error == "no record"
        assert updated.verified_at is None


def test_is_asset_verified_reflects_stored_status(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset, verification = repo.register_web_asset(
            s, domain="example.com", method="dns_txt", org_id="o"
        )
        assert repo.is_asset_verified(s, asset.id, org_id="o") is False
        repo.record_verification_check(s, verification, ok=True, error=None)
        assert repo.is_asset_verified(s, asset.id, org_id="o") is True


def test_get_asset_verification_is_org_scoped(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset, _ = repo.register_web_asset(s, domain="example.com", method="dns_txt", org_id="a")
        assert repo.get_asset_verification(s, asset.id, org_id="a") is not None
        assert repo.get_asset_verification(s, asset.id, org_id="b") is None
