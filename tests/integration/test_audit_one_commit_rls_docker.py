"""A rule run's actions and audit entries in one commit (`repo.audit_in_one_commit`), on real
Postgres as `bulwark_worker`: another writer taking the chain's next `seq` first makes the block
chain its entries again on the new tip, and the ledger still verifies; and Row-Level Security still
holds inside the savepoints each action runs in, which no longer re-apply the org (they are inside a
transaction that already did). Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.audit import verify_chain
from core.persistence import repo
from core.persistence.models import Asset, AuditEntry
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401


def test_a_concurrent_append_makes_the_block_chain_again_on_the_new_tip(
    sessions: sessionmaker[Session],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tag = uuid.uuid4().hex[:8]
    real = repo.stage_audit_entries
    attempts: list[int] = []

    def stage_then_lose_the_race(s: Session, entries: list[dict[str, Any]], **kw: Any) -> None:
        real(s, entries, **kw)
        attempts.append(len(entries))
        if len(attempts) == 1:  # someone else commits the next seq before this block flushes
            with sessions() as other:
                repo.append_audit_entry(other, actor="t", action="test.other",
                                        target=f"other-{tag}", payload={})  # fmt: skip

    monkeypatch.setattr(repo, "stage_audit_entries", stage_then_lose_the_race)
    with sessions() as s:
        with repo.audit_in_one_commit(s):
            for i in range(3):
                staged = repo.append_audit_entry(s, actor="t", action="test.mine",
                                                 target=f"mine-{tag}-{i}", payload={"i": i})  # fmt: skip
                assert staged is None  # staged, not written
            assert repo.audit_deferred(s) == 3
        assert repo.audit_deferred(s) is None
    assert attempts == [3, 3]
    with sessions() as s:
        mine = list(s.scalars(select(AuditEntry).where(AuditEntry.target.like(f"%-{tag}%"))
                              .order_by(AuditEntry.seq)))  # fmt: skip
        assert [e.target for e in mine] == [f"other-{tag}", *(f"mine-{tag}-{i}" for i in range(3))]
        assert [e.seq for e in mine] == list(range(mine[0].seq, mine[0].seq + 4))
        everything = list(s.scalars(select(AuditEntry).order_by(AuditEntry.seq)))
        assert verify_chain(everything).ok


def test_nothing_is_written_when_the_block_raises(sessions: sessionmaker[Session]) -> None:  # noqa: F811
    tag = uuid.uuid4().hex[:8]
    with sessions() as s:
        with pytest.raises(RuntimeError), repo.audit_in_one_commit(s):
            repo.append_audit_entry(s, actor="t", action="test.lost", target=f"lost-{tag}",
                                    payload={})  # fmt: skip
            raise RuntimeError("an action blew up")
        s.rollback()
        assert repo.audit_deferred(s) is None
        assert s.scalar(select(func.count()).select_from(AuditEntry)
                        .where(AuditEntry.target == f"lost-{tag}")) == 0  # fmt: skip


def test_row_level_security_holds_inside_savepoints(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    for org in (a, b):
        with sessions() as s:
            set_session_org(s, org)
            repo.create_scan(s, source_type="git", source_ref=f"https://example.com/{org}/x",
                             source_label=f"{org}/x", tools=["semgrep"], org_id=org)  # fmt: skip
    with sessions() as s:
        set_session_org(s, a)

        def visible() -> set[str]:
            return set(s.scalars(select(Asset.org_id)))

        assert visible() == {a}
        with s.begin_nested():
            assert visible() == {a}
            with s.begin_nested():
                assert visible() == {a}
        savepoint = s.begin_nested()
        assert visible() == {a}
        savepoint.rollback()  # an action that failed
        assert visible() == {a}
        s.commit()
        with s.begin_nested():  # the first statement of a new transaction is inside a savepoint
            assert visible() == {a}
