"""Manual findings and evidence under REAL Row-Level Security (migration 0031, Week 59, ADR-0044):
another org cannot read a finding or its evidence, and undoing the import that recorded a finding
takes the finding and its evidence with it (the foreign-key cascade SQLite tests cannot exercise).
Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.imports.service import revert_latest_import
from core.manual import attachments, service
from core.persistence import repo
from core.persistence.models import EvidenceAttachment, ManualFinding
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:  # noqa: F811
    a, b = f"man-a-{uuid.uuid4().hex[:8]}", f"man-b-{uuid.uuid4().hex[:8]}"
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
            for table in ("evidence_attachments", "manual_findings", "outbox_events",
                          "import_records", "engagement_tests"):  # fmt: skip
                s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM findings WHERE scan_id IN "
                           "(SELECT id FROM scans WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM issues WHERE asset_id IN "
                           "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM engagements WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _record(sessions: sessionmaker[Session], org: str) -> tuple[str, str, str, str]:
    with sessions() as s:
        set_session_org(s, org)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org)
        done = service.record(
            s,
            org_id=org,
            asset_id=asset.id,
            body=service.ManualFindingIn(
                title="IDOR on GET /orders/{id}",
                cwe="639",
                route="/orders/{id}",
                method="GET",
                cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            ),
            created_by="test",
        )
        att = attachments.store(s, manual=done.manual, data=PNG, file_name="a.png",
                                declared_type="image/png", created_by="test")  # fmt: skip
        return asset.id, done.manual.id, att.id, done.manual.test_id


def test_another_org_cannot_read_a_manual_finding_or_its_evidence(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    asset, manual_id, att_id, _ = _record(sessions, a)
    with sessions() as s:
        set_session_org(s, b)
        assert service.get(s, manual_id, a) is None and attachments.get(s, att_id, a) is None
        assert s.scalar(select(func.count()).select_from(ManualFinding)) == 0
        assert s.scalar(select(func.count()).select_from(EvidenceAttachment)) == 0
        assert service.for_project(s, asset, a) == []
    with sessions() as s:
        set_session_org(s, a)
        row = attachments.get(s, att_id, a)
        assert row is not None and attachments.read(row) == PNG


def test_undoing_the_import_removes_the_finding_and_its_evidence(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, _ = two_orgs
    _, manual_id, att_id, test_id = _record(sessions, a)
    with sessions() as s:
        set_session_org(s, a)
        out = revert_latest_import(s, org_id=a, test_id=test_id)
        assert out.deleted == 1
    with sessions() as s:
        set_session_org(s, a)
        assert service.get(s, manual_id, a) is None and attachments.get(s, att_id, a) is None
