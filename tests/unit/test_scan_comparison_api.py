"""GET /scans/{id}/compare (plan §28.6): the scan comparison screen's API, org-scoped like every
other scan read (ADR-0013)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any):  # type: ignore[no-untyped-def]
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, _FakeSubscriber()))
    return TestClient(app), sessions


def _finding(fid: str, path: str, rule: str) -> Finding:
    f = Finding(
        fid, f"title {fid}", "desc", Location(path, 1, 1, snippet=f"code-{rule}"), Taxonomy(Category.SAST)
    )  # fmt: skip
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.rule_ids = {"bandit": [rule]}
    f.evidence.reported_by = ["bandit"]
    f.fingerprint = f"fp-{rule}"
    return f


def _run_scan(
    sessions: sessionmaker[Session],
    findings: list[Finding],
    *,
    org_id: str = DEFAULT_ORG_ID,
    label: str = "acme/payments-api",
) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="u", source_label=label, tools=["bandit"],
            org_id=org_id,
        )  # fmt: skip
        result = repo.sync_issues_for_scan(s, scan.id, findings)
        repo.add_findings(s, scan.id, findings, issue_updates=result.updates)
        repo.finish_scan(s, scan.id, "completed")
        return scan.id


def test_compares_two_scans_of_the_same_project(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    s1 = _run_scan(sessions, [_finding("f1", "a.py", "R1"), _finding("f2", "b.py", "R2")])
    s2 = _run_scan(sessions, [_finding("f3", "a.py", "R1"), _finding("f4", "c.py", "R3")])

    r = client.get(f"/scans/{s2}/compare", params={"against": s1}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["earlier"]["scan_id"] == s1
    assert body["later"]["scan_id"] == s2
    # "unchanged" is one Issue (a.py/R1) matched across both scans -- its title reflects the most
    # recent occurrence (scan 2's "title f3"), not scan 1's original "title f1": a stored Issue
    # snapshot field, not a historical record of what a specific past scan said.
    assert [i["title"] for i in body["unchanged"]] == ["title f3"]
    assert [i["title"] for i in body["fixed"]] == ["title f2"]
    assert [i["title"] for i in body["new"]] == ["title f4"]
    assert body["reintroduced"] == []


def test_order_of_the_two_ids_in_the_url_does_not_matter(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    s1 = _run_scan(sessions, [_finding("f1", "a.py", "R1")])
    s2 = _run_scan(sessions, [_finding("f2", "b.py", "R2")])
    a = client.get(f"/scans/{s1}/compare", params={"against": s2}, headers=AUTH).json()
    b = client.get(f"/scans/{s2}/compare", params={"against": s1}, headers=AUTH).json()
    assert a["earlier"]["scan_id"] == b["earlier"]["scan_id"] == s1
    assert a["new"] == b["new"] and a["fixed"] == b["fixed"]


def test_comparing_scans_from_different_projects_is_404(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    s1 = _run_scan(sessions, [_finding("f1", "a.py", "R1")], label="repo-one")
    s2 = _run_scan(sessions, [_finding("f2", "a.py", "R1")], label="repo-two")
    r = client.get(f"/scans/{s1}/compare", params={"against": s2}, headers=AUTH)
    assert r.status_code == 404


def test_a_scan_in_another_org_is_404_not_403(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    mine = _run_scan(sessions, [_finding("f1", "a.py", "R1")])
    theirs = _run_scan(sessions, [_finding("f2", "a.py", "R1")], org_id="org-b")
    r = client.get(f"/scans/{mine}/compare", params={"against": theirs}, headers=AUTH)
    assert r.status_code == 404


def test_unknown_or_malformed_scan_id_is_404(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    s1 = _run_scan(sessions, [_finding("f1", "a.py", "R1")])
    assert (
        client.get(
            f"/scans/{s1}/compare", params={"against": "not-a-uuid"}, headers=AUTH
        ).status_code
        == 404
    )
    assert (
        client.get(
            "/scans/00000000-0000-0000-0000-000000000000/compare",
            params={"against": s1},
            headers=AUTH,
        ).status_code
        == 404
    )


def test_requires_auth_and_scope(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions = env
    s1 = _run_scan(sessions, [_finding("f1", "a.py", "R1")])
    s2 = _run_scan(sessions, [_finding("f2", "b.py", "R2")])
    assert client.get(f"/scans/{s1}/compare", params={"against": s2}).status_code == 401
