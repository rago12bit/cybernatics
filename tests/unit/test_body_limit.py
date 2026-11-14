"""Every request body has a size limit, applied before it is read (api.body_limit).

FastAPI reads a body before it checks who is asking, so without the limit an anonymous caller could
make the API hold gigabytes in memory (JSON) or on its temporary disk (a multipart upload)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api import body_limit
from api.body_limit import JSON_MAX_BYTES, BodyLimitMiddleware
from api.deps import AppState
from api.main import create_app
from core.config import Settings
from tests.unit.test_api import AUTH, TOKEN, FakeSubscriber

MAX_UPLOAD = 1000


@pytest.fixture
def client(sessions: sessionmaker[Session], tmp_path: Path) -> TestClient:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=MAX_UPLOAD,
    )  # fmt: skip
    return TestClient(create_app(AppState(settings, sessions, lambda *_: None, FakeSubscriber())))


def chunks(total: int, size: int = 64 * 1024) -> Iterator[bytes]:
    for _ in range(total // size + 1):
        yield b"x" * size


def test_a_declared_body_over_the_limit_is_refused_unread_whoever_sends_it(
    client: TestClient,
) -> None:
    big = b"x" * (JSON_MAX_BYTES + 1)
    r = client.post("/scans", content=big, headers={"Content-Type": "application/json",
                                                    "Origin": "http://localhost:3000"})  # fmt: skip
    assert (
        r.status_code == 413 and r.json()["detail"] == f"request body over {JSON_MAX_BYTES} bytes"
    )
    # Inside CORS, so the web app can read the answer.
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"
    # At the limit it is read, and refused for what it is (not JSON) rather than for its size.
    ok = client.post("/scans", content=big[:-1], headers={"Content-Type": "application/json"})
    assert ok.status_code == 422


def test_a_body_that_declares_no_length_is_cut_off_at_the_limit(client: TestClient) -> None:
    r = client.post("/scans", content=chunks(JSON_MAX_BYTES + 200_000),
                    headers={"Content-Type": "application/json", **AUTH})  # fmt: skip
    assert r.status_code == 413


def test_the_app_never_sees_more_than_the_limit() -> None:
    """The stream stops there: what came after is not handed to anyone."""
    import asyncio

    received = 0

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal received
        while True:
            message = await receive()
            received += len(message.get("body", b""))
            if not message.get("more_body"):
                return

    sent = iter([b"a" * 600, b"b" * 600, b"c" * 600])

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": next(sent), "more_body": True}

    async def send(_message: Any) -> None:
        raise AssertionError("nothing is sent by the middleware once the stream has started")

    limited = BodyLimitMiddleware(app, lambda _method, _path: 1000)
    scope = {"type": "http", "method": "POST", "path": "/x", "headers": []}
    with pytest.raises(Exception) as caught:  # noqa: PT011 - the HTTPException FastAPI answers with
        asyncio.run(limited(scope, receive, send))
    assert getattr(caught.value, "status_code", None) == 413 and received == 600


def test_upload_routes_take_what_their_own_check_allows(client: TestClient) -> None:
    # A little over the upload limit: read, and refused by the route itself, in its own words.
    r = client.post("/scans/upload", headers=AUTH,
                    files={"archive": ("a.zip", b"x" * (MAX_UPLOAD + 500))})  # fmt: skip
    assert r.status_code == 413 and "archive exceeds" in r.json()["detail"]
    # Far over it: refused before it is spooled to disk, signed in or not.
    huge = b"x" * (max(MAX_UPLOAD + body_limit.FORM_OVERHEAD_BYTES, JSON_MAX_BYTES) + 4096)
    r = client.post("/scans/upload", files={"archive": ("a.zip", huge)})
    assert r.status_code == 413 and "request body over" in r.json()["detail"]


def test_each_kind_of_route_has_its_limit() -> None:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=Path("."),
        upload_dir=Path("."), max_upload_bytes=100 * 1024 * 1024,
    )  # fmt: skip
    limit_for = body_limit.limits(settings)
    mib = 1024 * 1024
    assert limit_for("POST", "/scans") == limit_for("PUT", "/scans/upload") == 8 * mib
    assert limit_for("POST", "/scans/upload") == limit_for("POST", "/v2/ingest") == 101 * mib
    assert limit_for("POST", "/integrations/github/webhook") == 25 * mib
    assert limit_for("POST", "/auth/saml/p/acs") == 2 * mib
    for path in ("/v2/notes/n/attachments", "/v2/manual-findings/m/attachments",
                 "/v2/risk-acceptances/a/attachments"):  # fmt: skip
        assert limit_for("POST", path) == 11 * mib, path


def test_the_saml_callback_does_not_read_an_endless_form(client: TestClient) -> None:
    form = b"SAMLResponse=" + b"A" * (3 * 1024 * 1024)
    r = client.post("/auth/saml/p/acs", content=form,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})  # fmt: skip
    assert r.status_code == 413
