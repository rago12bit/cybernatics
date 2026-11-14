"""Routes that block do not run on the event loop.

An `async def` route runs on the event loop, and everything in this API that touches the database,
a file, the queue or a container blocks. While such a route runs, nothing else in its process is
served: not another request, not the health check, not the live-scan sockets. The upload and import
routes were `async def` only to `await file.read()`; one of them ran a sandbox container, up to
twenty seconds. They are plain `def` now (FastAPI runs those in a worker thread), and this test
names the few routes that must be async, so a new one is a decision rather than a habit."""

from __future__ import annotations

import inspect
from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from tests.unit.test_api import AUTH, TOKEN, FakeSubscriber

#: Async because they must be: they read the raw body themselves (a webhook's signature is over
#: its bytes; SCIM and SAML answer in their own formats) or await a Temporal client.
ASYNC_ROUTES = {
    "/integrations/github/webhook",
    "/integrations/github-issues/webhook/{org_id}",
    "/integrations/jira/webhook/{org_id}/{secret}",
    "/auth/saml/{provider_id}/acs",
    "/scim/v2/Users",
    "/scim/v2/Users/{user_id}",
    "/assets/{asset_id}/issues/{issue_id}/verified-fix",
    "/assets/{asset_id}/issues/{issue_id}/verified-fix/approve",
    "/assets/{asset_id}/issues/{issue_id}/verified-fix/reject",
}


def _app(sessions: sessionmaker[Session], tmp_path: Path) -> TestClient:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=10_000,
    )  # fmt: skip
    return TestClient(create_app(AppState(settings, sessions, lambda *_: None, FakeSubscriber())))


def test_only_the_routes_that_must_be_are_async(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    app = _app(sessions, tmp_path).app
    found = {
        r.path
        for r in app.routes  # type: ignore[attr-defined]
        if isinstance(r, APIRoute) and inspect.iscoroutinefunction(r.endpoint)
    }
    assert found == ASYNC_ROUTES


def test_an_upload_still_arrives_whole(sessions: sessionmaker[Session], tmp_path: Path) -> None:
    client = _app(sessions, tmp_path)
    body = bytes(range(256)) * 20
    r = client.post("/scans/upload", headers=AUTH, files={"archive": ("src.zip", body)})
    assert r.status_code == 202, r.text
    (stored,) = (tmp_path / "uploads").iterdir()
    assert stored.read_bytes() == body
