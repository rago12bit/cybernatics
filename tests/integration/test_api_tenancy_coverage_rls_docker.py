"""Closes the real gap Week 53's own pre-Phase-13 gate (plan §39.5) found: "the two-tenant RLS test
passes on every endpoint" turned out to mean 4 of this API's 50+ endpoints
(`tests/integration/test_tenancy_rls_docker.py`'s own original scope, from Week 29/30 when the API
was that small). Every `/assets/{asset_id}/...` endpoint added since -- DAST, dependencies,
attack-paths, threat model, hypotheses, triage assistant, verified fixes, Copilot -- had never been
checked against a real cross-org request, only against SQLite-backed unit tests (no RLS to enforce)
or the repository layer directly (proves the database enforces isolation, not that every HTTP route
actually reaches it correctly).

Against REAL Postgres with real Row-Level Security, connected as `bulwark_app` -- exactly the
connection the real API uses. Skips everywhere else, the same way the other `*_rls_docker.py` tests
do.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.tenancy import set_session_org

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _rls_test_db_url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _postgres_ready() -> bool:
    url = _rls_test_db_url()
    if not url:
        return False
    try:
        create_engine(url).connect().close()
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_ready(),
    reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable -- see "
    ".github/workflows/ci.yml's tenancy-rls job",
)


class FakeSubscriber:
    async def subscribe(self, scan_id: str):  # pragma: no cover - not exercised here
        return
        yield  # makes this an async generator; never reached


class _StubLLMClient:
    """Satisfies `AppState.llm`/`llm_triage`/`llm_hypotheses`'s own `is None` on/off switch
    (core.llm.client.LLMClient is a Protocol -- nothing here needs to actually answer, because every
    endpoint this unlocks checks the requesting org's access to the asset before it would ever call
    a method on this object; org B's probe always 404s first."""


def _stub_copilot_client() -> Any:
    """`post_copilot_message` additionally requires `isinstance(client, AnthropicClient)` (tool
    calling isn't supported for local models, ADR-0027) -- a plain stub fails that check before ever
    reaching the org lookup. A real `AnthropicClient` with a fake key satisfies it: constructing one
    makes no network call, and org B's probe 404s long before any method on it would be called."""
    from core.llm.client import AnthropicClient, LLMConfig

    return AnthropicClient(LLMConfig(api_key="sk-ant-fake-for-test"))


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def client(sessions: sessionmaker[Session], tmp_path: Any) -> TestClient:
    settings = Settings(
        database_url=_rls_test_db_url(), redis_url="", s3_endpoint=None, s3_access_key="",  # type: ignore[arg-type]
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "up", max_upload_bytes=1000,
    )  # fmt: skip
    stub = _StubLLMClient()
    app = create_app(
        AppState(
            settings, sessions, lambda sid, org: None, FakeSubscriber(),
            llm=stub, llm_triage=stub, llm_hypotheses=stub,  # type: ignore[arg-type]
            llm_copilot=_stub_copilot_client(),
        )
    )  # fmt: skip
    return TestClient(app)


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    a, b = f"cov-rls-a-{uuid.uuid4().hex[:8]}", f"cov-rls-b-{uuid.uuid4().hex[:8]}"
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
            # issues/hypotheses/copilot_conversations (and copilot_messages, cascading from those)
            # all FK ondelete="CASCADE" from assets.id -- deleting the asset is enough.
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


@pytest.fixture
def org_a_fixtures(sessions: sessionmaker[Session], two_orgs: tuple[str, str]) -> dict[str, str]:
    """One asset, one issue, one hypothesis, one copilot conversation, and one scan -- all under
    org A. Deliberately created by direct ORM insert (not a real scan pipeline run): every endpoint
    under test checks org membership before it does anything else with the resource, so a minimal,
    real database row is enough to prove the org boundary without needing a live scan, a live model,
    or live DNS."""
    from core.persistence.models import Asset, CopilotConversationRow, HypothesisRow, IssueRow, Scan

    org_a, _ = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        asset = Asset(org_id=org_a, source_type="git", key="k-cov", label="l")
        s.add(asset)
        s.flush()
        issue = IssueRow(
            asset_id=asset.id, fingerprint="f1", state="open", category="sast", severity="HIGH",
            path="a.py", title="t",
        )  # fmt: skip
        s.add(issue)
        hyp = HypothesisRow(
            asset_id=asset.id, route_method="POST", route_path="/x", file="a.py", line=1,
            evidence="e", suggested_check="c", confidence="medium", snippet="s", model="m",
        )  # fmt: skip
        s.add(hyp)
        convo = CopilotConversationRow(asset_id=asset.id)
        s.add(convo)
        scan = Scan(
            org_id=org_a, asset_id=asset.id, source_type="git", source_ref="https://github.com/a/b",
            source_label="a/b", status="completed", tools=["bandit"],
        )  # fmt: skip
        s.add(scan)
        s.commit()
        return {
            "asset_id": asset.id, "issue_id": issue.id, "hypothesis_id": hyp.id,
            "conversation_id": convo.id, "scan_id": scan.id,
        }  # fmt: skip


def _hdr(org: str) -> dict[str, str]:
    return {**AUTH, "X-Bulwark-Org": org}


# (method, path template, json body or None) -- path templates are filled with org A's real ids,
# then requested with org B's header. Every one of these must 404: org B must never learn the
# resource exists, let alone see its data. Grouped exactly as the endpoints are grouped in
# api/main.py, in the same order, so a future endpoint added to one group is easy to also add here.
ASSET_ONLY_GET = [
    "/assets/{asset_id}/overview",
    "/assets/{asset_id}/verification",
    "/assets/{asset_id}/dependencies",
    "/assets/{asset_id}/attack-paths",
    "/assets/{asset_id}/threat-model",
    "/assets/{asset_id}/campaigns",
    "/assets/{asset_id}/hypotheses",
    "/assets/{asset_id}/issues",
]
ASSET_ISSUE_GET = [
    "/assets/{asset_id}/issues/{issue_id}",
    "/assets/{asset_id}/issues/{issue_id}/history",
    "/assets/{asset_id}/issues/{issue_id}/triage-assistant",
    "/assets/{asset_id}/issues/{issue_id}/verified-fix",
]
ASSET_CONVERSATION_GET = ["/assets/{asset_id}/copilot/conversations/{conversation_id}/messages"]
SCAN_GET = [
    # `against` only needs to be a syntactically valid query param here: _get_scan(scan_id) is
    # checked before _get_scan(against), so org B's probe 404s on scan_id regardless of this value.
    "/scans/{scan_id}/compare?against={scan_id}",
    "/scans/{scan_id}/cost",
]

ASSET_ONLY_POST = [
    ("/assets/{asset_id}/verify", None),
    ("/assets/{asset_id}/campaigns", {"mode": "passive"}),
    ("/assets/{asset_id}/issues/bulk-triage", {"issue_ids": ["x"], "action": "not_a_risk"}),
    ("/assets/{asset_id}/threat-model/regenerate", None),
    ("/assets/{asset_id}/hypotheses/generate", None),
    ("/assets/{asset_id}/copilot/conversations", {}),
]
ASSET_ISSUE_POST = [
    ("/assets/{asset_id}/issues/{issue_id}/triage", {"action": "not_a_risk"}),
    ("/assets/{asset_id}/issues/{issue_id}/triage-assistant", None),
    ("/assets/{asset_id}/issues/{issue_id}/verified-fix", {}),
    ("/assets/{asset_id}/issues/{issue_id}/verified-fix/approve", None),
    ("/assets/{asset_id}/issues/{issue_id}/verified-fix/reject", None),
]
ASSET_HYPOTHESIS_POST = [
    ("/assets/{asset_id}/hypotheses/{hypothesis_id}/promote", None),
    ("/assets/{asset_id}/hypotheses/{hypothesis_id}/dismiss", None),
]
ASSET_CONVERSATION_POST = [
    ("/assets/{asset_id}/copilot/conversations/{conversation_id}/messages", {"question": "q"}),
]
SCAN_POST = [("/scans/{scan_id}/suggestion", {"finding_id": "x"})]
ASSET_ONLY_PUT = [("/assets/{asset_id}/threat-model", {"mermaid": "graph TD;", "stride": []})]


def test_every_asset_and_scan_scoped_get_endpoint_404s_for_another_org(
    client: TestClient, two_orgs: tuple[str, str], org_a_fixtures: dict[str, str]
) -> None:
    _, org_b = two_orgs
    hdr_b = _hdr(org_b)
    paths = [*ASSET_ONLY_GET, *ASSET_ISSUE_GET, *ASSET_CONVERSATION_GET, *SCAN_GET]
    failures = []
    for template in paths:
        path = template.format(**org_a_fixtures)
        r = client.get(path, headers=hdr_b)
        if r.status_code != 404:
            failures.append(f"GET {path} -> {r.status_code}")
    assert not failures, "leaked (not 404) for org B: " + "; ".join(failures)


def test_every_asset_and_scan_scoped_write_endpoint_404s_for_another_org(
    client: TestClient, two_orgs: tuple[str, str], org_a_fixtures: dict[str, str]
) -> None:
    _, org_b = two_orgs
    hdr_b = _hdr(org_b)
    posts = [
        *ASSET_ONLY_POST, *ASSET_ISSUE_POST, *ASSET_HYPOTHESIS_POST, *ASSET_CONVERSATION_POST,
        *SCAN_POST,
    ]  # fmt: skip
    failures = []
    for template, body in posts:
        path = template.format(**org_a_fixtures)
        r = client.post(path, headers=hdr_b, json=body)
        if r.status_code != 404:
            failures.append(f"POST {path} -> {r.status_code}")
    for template, body in ASSET_ONLY_PUT:
        path = template.format(**org_a_fixtures)
        r = client.put(path, headers=hdr_b, json=body)
        if r.status_code != 404:
            failures.append(f"PUT {path} -> {r.status_code}")
    assert not failures, "leaked (not 404) for org B: " + "; ".join(failures)


def test_this_is_not_just_everything_404ing_org_a_can_reach_its_own_resources(
    client: TestClient, two_orgs: tuple[str, str], org_a_fixtures: dict[str, str]
) -> None:
    org_a, _ = two_orgs
    hdr_a = _hdr(org_a)
    assert (
        client.get(f"/assets/{org_a_fixtures['asset_id']}/overview", headers=hdr_a).status_code
        == 200
    )
    assert (
        client.get(f"/assets/{org_a_fixtures['asset_id']}/issues", headers=hdr_a).status_code == 200
    )
    r = client.get(f"/assets/{org_a_fixtures['asset_id']}/hypotheses", headers=hdr_a)
    assert r.status_code == 200
    assert org_a_fixtures["hypothesis_id"] in {h["id"] for h in r.json()}
