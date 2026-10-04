"""Deduplication settings under REAL Row-Level Security (migration 0029, Week 58, ADR-0042): another
org cannot read, enumerate or version a project's settings, nor write one into a project it does not
own. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from core.dedup.settings import current_settings, history, save_setting
from core.persistence import repo
from core.tenancy import set_session_org


def _url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _ready() -> bool:
    if not _url():
        return False
    try:
        create_engine(_url()).connect().close()  # type: ignore[arg-type]
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="BULWARK_RLS_TEST_DATABASE_URL not reachable")


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    a, b = f"dd-a-{uuid.uuid4().hex[:8]}", f"dd-b-{uuid.uuid4().hex[:8]}"
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
            s.execute(text("DELETE FROM dedup_settings WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _project(sessions: sessionmaker[Session], org: str) -> str:
    with sessions() as s:
        set_session_org(s, org)
        return repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org).id


def test_another_org_cannot_read_a_projects_settings(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    a, b = two_orgs
    asset = _project(sessions, a)
    with sessions() as s:
        set_session_org(s, a)
        save_setting(s, org_id=a, asset_id=asset, source="nessus", strategy="tool_id")
        save_setting(s, org_id=a, asset_id=asset, source="nessus", strategy="hash_fields",
                     fields=("title",))  # fmt: skip
        s.commit()
    with sessions() as s:
        set_session_org(s, b)
        assert current_settings(s, asset) == {} and history(s, asset) == []
    with sessions() as s:
        set_session_org(s, a)
        assert current_settings(s, asset)["nessus"].version == 2


def test_another_org_cannot_write_a_setting_into_a_project_it_does_not_own(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    a, b = two_orgs
    asset = _project(sessions, a)
    with sessions() as s:
        set_session_org(s, b)
        with pytest.raises(DBAPIError):  # org B's row-level policy refuses a row labelled org A
            save_setting(s, org_id=a, asset_id=asset, source="zap", strategy="tool_id")
            s.commit()
