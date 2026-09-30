"""core.persistence.repo.get_threat_model/save_threat_model (Week 45 task 3, plan §21.7)."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID


def _asset(sessions: sessionmaker[Session], label: str = "acme/x") -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref=f"https://example.com/{label}.git",
            source_label=label, tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def test_get_returns_none_when_nothing_saved_yet(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        assert repo.get_threat_model(s, asset_id) is None


def test_first_save_creates_version_1_with_the_given_source(
    sessions: sessionmaker[Session],
) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        row = repo.save_threat_model(
            s, asset_id, "flowchart LR\n    user([User])", [{"element": "User"}],
            source="generated", actor=None,
        )  # fmt: skip
    assert row.version == 1
    assert row.source == "generated"
    assert row.updated_by is None
    with sessions() as s:
        fetched = repo.get_threat_model(s, asset_id)
        assert fetched is not None
        assert fetched.mermaid == "flowchart LR\n    user([User])"
        assert fetched.stride == [{"element": "User"}]


def test_second_save_replaces_content_and_bumps_version(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        repo.save_threat_model(
            s, asset_id, "flowchart LR\n    user([User])", [{"element": "User"}],
            source="generated", actor=None,
        )  # fmt: skip
    with sessions() as s:
        row = repo.save_threat_model(
            s, asset_id, "flowchart LR\n    user([User])\n    x", [{"element": "x"}],
            source="edited", actor="alice",
        )  # fmt: skip
    assert row.version == 2
    assert row.source == "edited"
    assert row.updated_by == "alice"
    with sessions() as s:
        fetched = repo.get_threat_model(s, asset_id)
        assert fetched is not None
        assert fetched.stride == [{"element": "x"}]
        assert fetched.version == 2


def test_a_second_asset_never_sees_the_first_assets_draft(
    sessions: sessionmaker[Session],
) -> None:
    a1, a2 = _asset(sessions, "acme/x"), _asset(sessions, "acme/y")
    with sessions() as s:
        repo.save_threat_model(
            s, a1, "flowchart LR\n    user([User])", [], source="generated", actor=None
        )
    with sessions() as s:
        assert repo.get_threat_model(s, a2) is None
