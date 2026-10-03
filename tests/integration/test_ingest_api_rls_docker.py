"""The ingest API end to end against REAL infrastructure (Week 54 task 7, ADR-0040): HTTP requests,
a worker job under Row-Level Security as the non-superuser `bulwark_worker` role, and the report
parsed inside the real sandbox container -- the production path, with nothing mocked.

Needs `BULWARK_RLS_TEST_DATABASE_URL` (a Postgres migrated to head) and Docker.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.imports.jobs import process_import
from core.imports.parsers.sandbox import IngestParseAdapter
from core.persistence import repo
from core.persistence.models import FindingRow, ImportRecord, IssueRow
from core.tenancy import scoped_sessions, set_session_org
from tests.unit.test_api import FakeSubscriber

ROOT = Path(__file__).resolve().parents[2]
SARIF = (ROOT / "tests" / "golden" / "semgrep" / "raw.json").read_bytes()
TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _ready() -> bool:
    if not _url() or not shutil.which("docker"):
        return False
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return False
    try:
        create_engine(_url()).connect().close()  # type: ignore[arg-type]
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="needs Postgres (RLS) and Docker")


@pytest.fixture(scope="module", autouse=True)
def parser_image() -> None:
    subprocess.run(
        ["docker", "build", "-q", "-f", "docker/ingest-parser/Dockerfile",
         "-t", IngestParseAdapter.spec.image, "."],
        cwd=ROOT, check=True, capture_output=True,
    )  # fmt: skip


def sarif_without_last_result() -> bytes:
    doc = json.loads(SARIF)
    doc["runs"][0]["results"] = doc["runs"][0]["results"][:-1]
    return json.dumps(doc).encode()


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.engine = create_engine(_url(), pool_size=4, max_overflow=0)  # type: ignore[arg-type]
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        self.queue: list[tuple[str, str]] = []
        self.settings = Settings(
            database_url="", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
            s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "uploads",
            max_upload_bytes=10_000_000, ingest_sandbox=True,  # the real container
        )  # fmt: skip
        app = create_app(
            AppState(
                self.settings, self.sessions, lambda *_: None, FakeSubscriber(),
                enqueue_import=lambda iid, org: self.queue.append((iid, org)),
            )
        )  # fmt: skip
        self.client = TestClient(app)
        self.org_a, self.org_b = f"ing-a-{uuid.uuid4().hex[:8]}", f"ing-b-{uuid.uuid4().hex[:8]}"
        with self.sessions() as s:
            s.execute(
                text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
                [{"id": self.org_a, "n": "A"}, {"id": self.org_b, "n": "B"}],
            )
            s.commit()
        self.asset = {org: self._asset(org) for org in (self.org_a, self.org_b)}

    def _asset(self, org: str) -> str:
        with self.sessions() as s:
            set_session_org(s, org)
            return repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org).id

    def headers(self, org: str) -> dict[str, str]:
        return {**AUTH, "X-Bulwark-Org": org}

    def drain(self) -> None:
        """What the Celery worker does: one scoped session per job, as that org."""
        while self.queue:
            import_id, org = self.queue.pop(0)
            with scoped_sessions(self.sessions, org)() as s:
                process_import(s, import_id, org, self.settings)

    def post(self, org: str, data: bytes, **form: Any) -> Any:
        form.setdefault("project", self.asset[org])
        return self.client.post(
            "/v2/ingest", data=form, files={"file": ("r.sarif", data)}, headers=self.headers(org)
        )

    def view(self, org: str, import_id: str) -> Any:
        return self.client.get(f"/v2/imports/{import_id}", headers=self.headers(org))

    def import_and_get(self, org: str, data: bytes, **form: Any) -> dict[str, Any]:
        r = self.post(org, data, **form)
        assert r.status_code in (200, 202), r.text
        self.drain()
        v = self.view(org, r.json()["import_id"])
        assert v.status_code == 200, v.text
        return v.json()  # type: ignore[no-any-return]

    def teardown(self) -> None:
        with self.sessions() as s:
            for org in (self.org_a, self.org_b):
                set_session_org(s, org)
                for table in ("outbox_events", "import_records", "engagement_tests"):
                    s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
                s.execute(text("DELETE FROM findings WHERE scan_id IN "
                               "(SELECT id FROM scans WHERE org_id = :o)"), {"o": org})  # fmt: skip
                s.execute(text("DELETE FROM issues WHERE asset_id IN "
                               "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
                s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
                s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
            s.execute(
                text("DELETE FROM organizations WHERE id IN (:a, :b)"),
                {"a": self.org_a, "b": self.org_b},
            )
            s.commit()
        self.engine.dispose()


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    yield r
    r.teardown()


def counts_in(rig: Rig, org: str) -> tuple[int, int, int]:
    with rig.sessions() as s:
        set_session_org(s, org)
        return (
            s.scalar(select(func.count()).select_from(ImportRecord)) or 0,
            s.scalar(select(func.count()).select_from(IssueRow)) or 0,
            s.scalar(select(func.count()).select_from(FindingRow)) or 0,
        )


def test_import_reimport_and_revert_over_http_with_sandboxed_parsing_under_rls(rig: Rig) -> None:
    a = rig.org_a
    first = rig.import_and_get(a, SARIF)
    assert first["status"] == "applied", first
    assert first["counts"] == {"new": 3, "unchanged": 0, "reopened": 0, "closed": 0, "detached": 0}

    second = rig.import_and_get(a, sarif_without_last_result())
    assert second["counts"] == {"new": 0, "unchanged": 2, "reopened": 0, "closed": 1, "detached": 0}

    dup = rig.post(a, sarif_without_last_result())
    assert dup.status_code == 200 and dup.json()["duplicate"] is True  # nothing queued
    assert rig.queue == []

    r = rig.client.post(f"/v2/imports/{second['id']}/revert", headers=rig.headers(a))
    assert r.status_code == 200 and r.json()["status"] == "reverted"
    with rig.sessions() as s:
        set_session_org(s, a)
        assert "fixed" not in [i.state for i in s.scalars(select(IssueRow))]


def test_a_truncated_report_fails_in_the_container_and_changes_nothing(rig: Rig) -> None:
    a = rig.org_a
    rig.import_and_get(a, SARIF)
    before = counts_in(rig, a)
    cut = rig.import_and_get(a, SARIF[: len(SARIF) // 2], parser="sarif")
    assert cut["status"] == "failed" and "valid JSON" in cut["error"]
    assert counts_in(rig, a)[1:] == before[1:]  # no issue closed or added


def test_xml_with_an_entity_is_refused_in_the_container_end_to_end(rig: Rig) -> None:
    evil = (
        b'<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component type="library">'
        b"<name>&x;</name><version>1</version></component></components></bom>"
    )
    v = rig.import_and_get(rig.org_a, evil, parser="cyclonedx")
    assert v["status"] == "failed" and ("DTD" in v["error"] or "entity" in v["error"])
    assert "root:" not in json.dumps(v)


def test_another_org_cannot_see_touch_or_import_into_this_orgs_imports(rig: Rig) -> None:
    a, b = rig.org_a, rig.org_b
    view = rig.import_and_get(a, SARIF)
    iid, tid = view["id"], view["test_id"]
    c = rig.client
    assert rig.view(b, iid).status_code == 404
    assert c.get(f"/v2/tests/{tid}/imports", headers=rig.headers(b)).status_code == 404
    for action in ("confirm", "cancel", "revert"):
        assert c.post(f"/v2/imports/{iid}/{action}", headers=rig.headers(b)).status_code == 404
    files = {"file": ("r.sarif", SARIF)}
    assert c.post("/v2/ingest", data={"project": rig.asset[a]}, files=files,
                  headers=rig.headers(b)).status_code == 404  # fmt: skip
    assert c.post("/v2/ingest", data={"test_id": tid}, files=files,
                  headers=rig.headers(b)).status_code == 404  # fmt: skip
    assert counts_in(rig, b) == (0, 0, 0)  # nothing of A's is visible to B at all
    assert counts_in(rig, a)[0] == 1


def test_two_orgs_importing_at_once_never_see_each_others_data(rig: Rig) -> None:
    """Queue one import per org, then run the jobs interleaved on a small shared pool -- the
    situation the tenancy fix exists for (core.tenancy._reapply_org_on_every_transaction)."""
    ra = rig.post(rig.org_a, SARIF)
    rb = rig.post(rig.org_b, sarif_without_last_result())
    assert ra.status_code == rb.status_code == 202
    rig.drain()
    va = rig.view(rig.org_a, ra.json()["import_id"]).json()
    vb = rig.view(rig.org_b, rb.json()["import_id"]).json()
    assert va["status"] == vb["status"] == "applied"
    assert va["counts"]["new"] == 3 and vb["counts"]["new"] == 2
    assert counts_in(rig, rig.org_a)[1] == 3 and counts_in(rig, rig.org_b)[1] == 2
