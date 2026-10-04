"""A deduplication change against REAL Postgres as the non-superuser worker role under Row-Level
Security (Week 58, ADR-0042): merging and splitting Issues satisfies the foreign keys and the
(project, category, fingerprint) uniqueness, and another org can neither preview nor apply a change
to a project it does not own. Needs `BULWARK_RLS_TEST_DATABASE_URL`."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.correlation import correlate
from core.dedup.service import DedupError, apply_change, preview_change
from core.dedup.settings import current_settings, history
from core.imports.service import apply_import
from core.persistence import repo
from core.persistence.models import FindingRow, IssueRow
from core.tenancy import set_session_org
from tests.unit.test_dedup_strategies import code


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
    a, b = f"dds-a-{uuid.uuid4().hex[:8]}", f"dds-b-{uuid.uuid4().hex[:8]}"
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
            for table in ("dedup_settings", "outbox_events", "import_records", "engagement_tests"):
                s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM findings WHERE scan_id IN "
                           "(SELECT id FROM scans WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM issues WHERE asset_id IN "
                           "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _imported(sessions: sessionmaker[Session], org: str) -> str:
    """A project whose semgrep import left three Issues (one rule, one file, three lines)."""
    findings = correlate([code(line=10, snippet="a(x)"), code(line=20, snippet="b(x, y)"),
                          code(line=30, snippet="c(x, y, z)")])[0]  # fmt: skip
    with sessions() as s:
        set_session_org(s, org)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org)
        eng = repo.create_engagement(
            s, org_id=org, asset_id=asset.id, name="Q", engagement_type="import"
        )
        test = repo.get_or_create_engagement_test(
            s, org_id=org, engagement_id=eng.id, name="Semgrep"
        )
        apply_import(s, org_id=org, test_id=test.id, findings=findings, parser="semgrep",
                     file_digest="a" * 64, file_name="r.sarif")  # fmt: skip
        return asset.id


def test_a_merge_and_its_inverse_split_work_on_postgres_under_rls(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org, _ = two_orgs
    asset = _imported(sessions, org)
    with sessions() as s:
        set_session_org(s, org)
        p = preview_change(s, org_id=org, asset_id=asset, source="semgrep", strategy="tool_id")
        assert (p.plan.issues_before, p.plan.issues_after, p.plan.merged_away) == (3, 1, 2)
        apply_change(s, org_id=org, asset_id=asset, source="semgrep", strategy="tool_id",
                     expected_digest=p.plan.digest, created_by="ana")  # fmt: skip
        assert len(list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset)))) == 1
        assert s.scalar(select(func.count()).select_from(FindingRow)) == 3
    with sessions() as s:
        set_session_org(s, org)
        back = preview_change(
            s, org_id=org, asset_id=asset, source="semgrep", strategy="fingerprint_v2"
        )
        assert back.plan.created_by_split == 2
        apply_change(s, org_id=org, asset_id=asset, source="semgrep", strategy="fingerprint_v2",
                     expected_digest=back.plan.digest)  # fmt: skip
        assert len(list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset)))) == 3
        assert [h.version for h in history(s, asset)] == [2, 1]
        assert current_settings(s, asset)["semgrep"].strategy == "fingerprint_v2"


def test_another_org_cannot_preview_or_apply_a_change_to_a_project_it_does_not_own(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    a, b = two_orgs
    asset = _imported(sessions, a)
    with sessions() as s:
        set_session_org(s, b)
        with pytest.raises(DedupError, match="project not found"):
            preview_change(s, org_id=b, asset_id=asset, source="semgrep", strategy="tool_id")
        with pytest.raises(DedupError, match="project not found"):
            apply_change(s, org_id=b, asset_id=asset, source="semgrep", strategy="tool_id",
                         expected_digest="x")  # fmt: skip
    with sessions() as s:
        set_session_org(s, a)
        assert len(list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset)))) == 3
        assert history(s, asset) == []
