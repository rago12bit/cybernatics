"""Several transactions creating the same project, standing engagement or Test at once, on real
Postgres as `bulwark_worker` under row-level security (migration 0052).

Every thread looks the row up, finds nothing, and only then -- once all of them have looked --
inserts. Before the fix all but one failed with a unique violation (the project, the Test) or made
a duplicate (the standing engagement). Now every thread gets the same row, and there is one.
Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import Asset, Engagement, EngagementTest
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

THREADS = 6


def _all_at_once(
    sessions: sessionmaker[Session],  # noqa: F811
    org: str,
    monkeypatch: pytest.MonkeyPatch,
    create: Callable[[Session], Any],
) -> list[str]:
    looked = threading.Barrier(THREADS, timeout=30)
    real = repo._add_unless_taken

    def insert_once_everyone_has_looked(s: Session, row: Any, found: Any) -> Any:
        looked.wait()
        return real(s, row, found)

    monkeypatch.setattr(repo, "_add_unless_taken", insert_once_everyone_has_looked)
    ids: list[str] = []
    errors: list[BaseException] = []

    def one() -> None:
        try:
            with sessions() as s:
                set_session_org(s, org)
                ids.append(create(s).id)
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=one) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors
    assert len(ids) == THREADS
    return ids


def _count(sessions: sessionmaker[Session], org: str, model: Any, *where: Any) -> int:  # noqa: F811
    with sessions() as s:
        set_session_org(s, org)
        return int(s.scalar(select(func.count()).select_from(model).where(*where)) or 0)


def test_first_scans_at_once_share_one_project(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a, b = two_orgs
    ids = _all_at_once(sessions, a, monkeypatch, lambda s: SimpleNamespace(id=repo.create_scan(
        s, source_type="git", source_ref="https://github.com/acme/web",
        source_label="https://github.com/acme/web", tools=[], org_id=a,
    ).asset_id))  # fmt: skip
    assert len(set(ids)) == 1
    assert _count(sessions, a, Asset) == 1
    assert _count(sessions, b, Asset) == 0  # and nothing leaked into the other organization


@pytest.mark.parametrize("kind", ["ci", "import"])
def test_one_standing_engagement_when_created_at_once(
    kind: str,
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a, _ = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        asset_id = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=a).id
    get = getattr(repo, f"get_or_create_{kind}_engagement")
    ids = _all_at_once(sessions, a, monkeypatch, lambda s: get(s, asset_id=asset_id, org_id=a))
    assert len(set(ids)) == 1
    assert _count(sessions, a, Engagement, Engagement.engagement_type == kind) == 1


def test_first_uploads_at_once_share_one_test(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a, _ = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        asset_id = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=a).id
        eng = repo.get_or_create_import_engagement(s, asset_id=asset_id, org_id=a).id
    ids = _all_at_once(sessions, a, monkeypatch, lambda s: repo.get_or_create_engagement_test(
        s, org_id=a, engagement_id=eng, name="Nessus"))  # fmt: skip
    assert len(set(ids)) == 1
    assert _count(sessions, a, EngagementTest) == 1
