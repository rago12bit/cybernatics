"""GitHub App webhook receiver (Week 30, ADR-0017): signature verification, the events it acts on,
and that it correctly resolves/creates the org an installation maps to before writing anything
tenant-scoped. Live delivery from a real GitHub App is not exercised here (see
docs/v2-week30-verification.md) -- this is the application-level behavior, on SQLite.
"""

from __future__ import annotations

import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.persistence.models import GithubInstallation, Organization, Scan

TOKEN = "t" * 32
SECRET = "webhook-secret"


class FakeSubscriber:
    async def subscribe(self, scan_id: str):  # pragma: no cover - not exercised here
        return
        yield  # makes this an async generator; never reached


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, "sha256").hexdigest()


@pytest.fixture
def client(sessions: sessionmaker[Session], tmp_path: Path) -> tuple[TestClient, list[Any]]:
    enqueued: list[tuple[str, str]] = []
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "up", max_upload_bytes=1000, github_webhook_secret=SECRET,
    )  # fmt: skip
    app = create_app(
        AppState(settings, sessions, lambda sid, org: enqueued.append((sid, org)), FakeSubscriber())
    )
    return TestClient(app), enqueued


def post(client: TestClient, event: str, payload: dict[str, Any], secret: str = SECRET):  # type: ignore[no-untyped-def]
    body = json.dumps(payload).encode()
    return client.post(
        "/integrations/github/webhook",
        content=body,
        headers={"X-GitHub-Event": event, "X-Hub-Signature-256": sign(body, secret)},
    )


def _pr_payload(
    action: str = "opened", installation_id: int = 42, pr_number: int = 7
) -> dict[str, Any]:
    return {
        "action": action,
        "installation": {"id": installation_id},
        "repository": {
            "owner": {"login": "acme"},
            "full_name": "acme/widgets",
            "clone_url": "https://github.com/acme/widgets.git",
        },
        "pull_request": {"number": pr_number},
    }


def test_webhook_404s_when_the_integration_is_not_configured(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "up", max_upload_bytes=1000,  # github_webhook_secret left blank
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, FakeSubscriber()))
    body = json.dumps({"zen": "hi"}).encode()
    r = TestClient(app).post(
        "/integrations/github/webhook",
        content=body,
        headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": sign(body, "irrelevant")},
    )
    assert r.status_code == 404


def test_bad_signature_is_rejected(client: tuple[TestClient, list[Any]]) -> None:
    c, _ = client
    r = post(c, "ping", {"zen": "hi"}, secret="wrong-secret")
    assert r.status_code == 401


def test_ping_is_acknowledged(client: tuple[TestClient, list[Any]]) -> None:
    c, _ = client
    r = post(c, "ping", {"zen": "hi"})
    assert r.status_code == 200 and r.json()["status"] == "pong"


def test_installation_created_makes_a_new_org_and_is_idempotent_on_redelivery(
    client: tuple[TestClient, list[Any]], sessions: sessionmaker[Session]
) -> None:
    c, _ = client
    payload = {"action": "created", "installation": {"id": 55, "account": {"login": "acme"}}}
    assert post(c, "installation", payload).status_code == 200
    assert post(c, "installation", payload).status_code == 200  # GitHub retries deliveries
    with sessions() as s:
        installs = list(s.query(GithubInstallation).all())
        orgs = list(s.query(Organization).all())
    assert len(installs) == 1  # redelivery did not create a second mapping
    assert installs[0].id == "55" and installs[0].account_login == "acme"
    assert any(o.id == installs[0].org_id for o in orgs)  # a real org backs the mapping


def test_installation_deleted_removes_the_mapping_but_not_the_org(
    client: tuple[TestClient, list[Any]], sessions: sessionmaker[Session]
) -> None:
    c, _ = client
    post(
        c,
        "installation",
        {"action": "created", "installation": {"id": 9, "account": {"login": "x"}}},
    )
    with sessions() as s:
        org_id = s.query(GithubInstallation).one().org_id
    assert (
        post(c, "installation", {"action": "deleted", "installation": {"id": 9}}).status_code == 200
    )
    with sessions() as s:
        assert s.query(GithubInstallation).count() == 0
        assert s.get(Organization, org_id) is not None  # durable, like every other org (ADR-0013)


def test_pull_request_opened_queues_a_scan_scoped_to_the_installations_org(
    client: tuple[TestClient, list[Any]], sessions: sessionmaker[Session]
) -> None:
    c, enqueued = client
    r = post(c, "pull_request", _pr_payload())
    assert r.status_code == 200 and r.json()["status"] == "queued"
    scan_id = r.json()["scan_id"]
    with sessions() as s:
        scan = s.get(Scan, scan_id)
        assert scan is not None
        assert scan.ref == "refs/pull/7/head"
        assert scan.github_repo == "acme/widgets"
        assert scan.github_pr_number == 7
        assert scan.github_installation_id == "42"
        install = s.query(GithubInstallation).filter_by(id="42").one()
        assert (
            scan.org_id == install.org_id != ""
        )  # a real, resolved org -- not the bootstrap default
    assert enqueued == [(scan_id, scan.org_id)]


def test_pull_request_reuses_the_same_org_across_multiple_prs(
    client: tuple[TestClient, list[Any]], sessions: sessionmaker[Session]
) -> None:
    c, _ = client
    first = post(c, "pull_request", _pr_payload(pr_number=1)).json()["scan_id"]
    second = post(c, "pull_request", _pr_payload(pr_number=2)).json()["scan_id"]
    with sessions() as s:
        a, b = s.get(Scan, first), s.get(Scan, second)
        assert a is not None and b is not None
        assert a.org_id == b.org_id  # same installation -> same org, every time


@pytest.mark.parametrize("action", ["closed", "labeled", "edited"])
def test_pull_request_ignores_actions_we_dont_scan_for(
    client: tuple[TestClient, list[Any]], action: str
) -> None:
    c, enqueued = client
    r = post(c, "pull_request", _pr_payload(action=action))
    assert r.status_code == 200 and r.json()["status"] == "ignored"
    assert enqueued == []


def test_unrecognized_event_is_ignored_not_an_error(client: tuple[TestClient, list[Any]]) -> None:
    c, _ = client
    r = post(c, "star", {"action": "created"})
    assert r.status_code == 200 and r.json()["status"] == "ignored"
