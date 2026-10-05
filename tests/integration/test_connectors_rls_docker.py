"""Connectors under REAL Row-Level Security (migration 0032, Week 60, ADR-0045): another org cannot
list, read or run a connector -- and so cannot reach its credential -- nor see its run history, and
the scheduler's per-org pass only ever finds an org's own due connectors. Needs
`BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.connectors import service
from core.connectors.http import Response
from core.persistence import repo
from core.persistence.models import Connector, ConnectorRun, GithubInstallation, IssueRow
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.unit.test_connectors import CS_URL, cs_alert


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:  # noqa: F811
    a, b = f"con-a-{uuid.uuid4().hex[:8]}", f"con-b-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a, "n": "A"}, {"id": b, "n": "B"}],
        )
        s.execute(
            text("INSERT INTO github_installations (id, account_login, org_id, created_at) "
                 "VALUES (:i, 'acme', :o, now())"),
            {"i": a[-8:], "o": a},
        )  # fmt: skip
        s.commit()
    yield a, b
    with sessions() as s:
        for org in (a, b):
            set_session_org(s, org)
            for table in ("connector_runs", "connectors", "outbox_events", "import_records",
                          "engagement_tests"):  # fmt: skip
                s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM findings WHERE scan_id IN "
                           "(SELECT id FROM scans WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM issues WHERE asset_id IN "
                           "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM engagements WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM github_installations WHERE org_id = :o"), {"o": a})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _settings() -> Settings:
    return Settings(database_url="", redis_url="", s3_endpoint=None, s3_access_key="",
                    s3_secret_key="", s3_bucket="b", api_token="t", workdir=__import__("pathlib").Path("/tmp"),
                    upload_dir=__import__("pathlib").Path("/tmp"), max_upload_bytes=1)  # fmt: skip


def test_a_connector_and_its_runs_belong_to_one_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="acme/web", org_id=a)

        c = service.create(
            s, org_id=a, asset_id=asset.id, kind="github_code_scanning", name="Web",
            config={"repo": "acme/web", "installation_id": a[-8:]}, credential=None,
            settings=_settings(),
        )  # fmt: skip
        def fake(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Response:
            return Response(200, {}, [cs_alert(1)]) if url == CS_URL else Response(404, {}, None)

        out = service.run(s, c, _settings(), transport=fake, github_token=lambda i, st: "t")
        assert out.run.outcome == "ok"
        assert s.scalar(select(func.count()).select_from(IssueRow)) == 1
        cid = c.id
    with sessions() as s:
        set_session_org(s, b)
        assert service.get(s, cid, a) is None and service.list_for(s, b) == []
        assert s.scalar(select(func.count()).select_from(Connector)) == 0
        assert s.scalar(select(func.count()).select_from(ConnectorRun)) == 0
        assert service.due(s, b) == []
        # B cannot use A's GitHub App installation either.
        with pytest.raises(service.ConnectorConfigError):
            service.validate_config(
                s, b, "github_dependabot", {"repo": "acme/web", "installation_id": a[-8:]}
            )
        assert (
            s.scalar(select(func.count()).select_from(GithubInstallation)) >= 1
        )  # visible, but not B's
    with sessions() as s:
        set_session_org(s, a)
        assert [r.outcome for r in service.runs(s, cid, a)] == ["ok"]
