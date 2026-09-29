from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.llm.budget import BudgetConfig
from core.llm.limits import UsageLimiter
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.persistence.models import FindingRow
from core.rag.store import load_corpus
from tests.unit.test_api import AUTH, TOKEN, FakeSubscriber
from tests.unit.test_llm import CHUNKS, GOOD, FakeModel, reply
from tests.unit.test_llm_cache import SNIPPET, patch_for

FINDING_PATH = "app/users.py"


def _seed(
    sessions: sessionmaker[Session], *, snippet: str = SNIPPET, load_kb: bool = True
) -> tuple[str, str]:
    with sessions() as s:
        if load_kb:
            load_corpus(s, CHUNKS)
        sid = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="u", tools=["bandit"]
        ).id
        f = Finding(
            "bandit:B608:app/users.py:10", "SQL injection", "String-built SQL.",
            Location(FINDING_PATH, 10, 11, snippet, Location.hash_snippet(snippet)),
            Taxonomy(Category.SAST, cwe=("CWE-89",), owasp_top_10_2021=("A03:2021",)),
        )  # fmt: skip
        f.evidence.rule_ids = {"bandit": ["B608"]}
        f.evidence.reported_by = ["bandit"]
        repo.add_findings(s, sid, [f])
        repo.finish_scan(s, sid, "completed")
    return sid, f.id


def make_client(
    sessions: sessionmaker[Session],
    tmp_path: Path,
    model: Any = None,
    limiter: UsageLimiter | None = None,
    budget: BudgetConfig | None = None,
) -> TestClient:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token=TOKEN, workdir=tmp_path, upload_dir=tmp_path / "up", max_upload_bytes=1000,
    )  # fmt: skip
    st = AppState(
        settings,
        sessions,
        lambda _sid, _org: None,
        FakeSubscriber(),
        llm=model,
        limiter=limiter or UsageLimiter(100, 1000),
        llm_budget=budget or BudgetConfig(per_scan=1_000_000, per_org_month=1_000_000),
    )
    return TestClient(create_app(st))


@pytest.fixture
def parts(
    sessions: sessionmaker[Session], tmp_path: Path
) -> Iterator[tuple[sessionmaker[Session], Path, str, str]]:
    sid, fid = _seed(sessions)
    yield sessions, tmp_path, sid, fid


def test_both_endpoints_need_the_token(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    c = make_client(sessions, tmp)
    assert c.get(f"/scans/{sid}/guidance", params={"finding_id": fid}).status_code == 401
    assert c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}).status_code == 401


def test_guidance_is_static_reference_text_and_calls_no_model(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    model = FakeModel(reply())
    g = (
        make_client(sessions, tmp, model)
        .get(f"/scans/{sid}/guidance", params={"finding_id": fid}, headers=AUTH)
        .json()
    )
    assert g["static"]["source"] == "static" and g["static"]["label"].startswith(
        "Reference guidance"
    )
    assert g["static"]["suggested_patch"] is None and g["ai"] is None and g["ai_enabled"] is True
    assert g["model"] == "fake-model-1" and g["static"]["references"]
    assert model.calls == []  # reading guidance never contacts the provider


def test_guidance_reports_ai_off_when_no_model_is_configured(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    g = (
        make_client(sessions, tmp)
        .get(f"/scans/{sid}/guidance", params={"finding_id": fid}, headers=AUTH)
        .json()
    )
    assert (
        g["ai_enabled"] is False
        and g["model"] is None
        and g["ai"] is None
        and g["static"]["explanation"]
    )


def test_suggestion_is_refused_when_ai_is_off(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    r = make_client(sessions, tmp).post(
        f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH
    )
    assert r.status_code == 409 and "not enabled" in r.json()["detail"]


def test_generate_then_cache_then_guidance_shows_it(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    model = FakeModel(reply(suggested_patch=patch_for(FINDING_PATH)))
    c = make_client(sessions, tmp, model)
    first = c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH)
    assert first.status_code == 200
    a = first.json()
    assert (
        a["source"] == "ai"
        and a["label"] == "AI suggestion: review before applying"
        and a["from_cache"] is False
    )
    assert (
        a["explanation"] == GOOD["explanation"]
        and a["suggested_patch"].startswith("--- a/app/users.py")
        and a["model"] == "fake-model-1"
    )
    second = c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH).json()
    assert second["from_cache"] is True and len(model.calls) == 1
    g = c.get(f"/scans/{sid}/guidance", params={"finding_id": fid}, headers=AUTH).json()
    assert (
        g["ai"]["source"] == "ai"
        and g["ai"]["from_cache"] is True
        and g["static"]["source"] == "static"
    )


def test_the_prompt_sent_uses_the_stored_snippet_and_never_the_key(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    model = FakeModel(reply())
    make_client(sessions, tmp, model).post(
        f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH
    )
    system, user = model.calls[0]
    assert "db.execute" in user and "kind=reference" in user and TOKEN not in user + system


def test_a_hijacked_reply_returns_static_text_with_the_reason_and_leaves_the_stored_finding_alone(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    with sessions() as s:
        before = json.dumps(s.query(FindingRow).one().data, sort_keys=True)
    evil = FakeModel(json.dumps({**GOOD, "severity": "LOW", "suppress": True}))
    r = make_client(sessions, tmp, evil).post(
        f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH
    )
    assert r.status_code == 200
    body = r.json()
    assert (
        body["source"] == "static"
        and body["suggested_patch"] is None
        and "rejected" in body["degraded_reason"]
    )
    with sessions() as s:
        assert json.dumps(s.query(FindingRow).one().data, sort_keys=True) == before


def test_the_spend_limit_returns_429_with_retry_after_and_cache_hits_stay_free(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    model = FakeModel(reply())
    c = make_client(sessions, tmp, model, UsageLimiter(per_minute=1, per_day=10))
    assert (
        c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH).status_code
        == 200
    )
    assert (
        c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH).json()[
            "from_cache"
        ]
        is True
    )  # free
    with sessions() as s:  # a second, different finding needs a real call: over the limit
        f2 = Finding(
            "b:2",
            "XSS",
            "d",
            Location("a.py", 3, 3, "x = 1", Location.hash_snippet("x = 1")),
            Taxonomy(Category.SAST, cwe=("CWE-79",)),
        )
        f2.evidence.rule_ids = {"bandit": ["B703"]}
        repo.add_findings(s, sid, [f2])
    r = c.post(f"/scans/{sid}/suggestion", json={"finding_id": "b:2"}, headers=AUTH)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1 and len(model.calls) == 1


def test_the_token_budget_returns_429_once_a_scans_cap_is_reached(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    model = FakeModel(reply(), tokens=50)
    c = make_client(sessions, tmp, model, budget=BudgetConfig(per_scan=40, per_org_month=1_000_000))
    r = c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH)
    assert r.status_code == 200 and r.json()["tokens_used"] == 50 and r.json()["source"] == "ai"
    with (
        sessions() as s
    ):  # over budget now (50 >= 40): a second, different finding needs a real call
        f2 = Finding(
            "b:2", "XSS", "d",
            Location("a.py", 3, 3, "x = 1", Location.hash_snippet("x = 1")),
            Taxonomy(Category.SAST, cwe=("CWE-79",)),
        )  # fmt: skip
        f2.evidence.rule_ids = {"bandit": ["B703"]}
        repo.add_findings(s, sid, [f2])
    r2 = c.post(f"/scans/{sid}/suggestion", json={"finding_id": "b:2"}, headers=AUTH)
    assert r2.status_code == 429 and "token budget" in r2.json()["detail"] and len(model.calls) == 1
    with sessions() as s:
        assert repo.get_scan(s, sid, org_id=None).llm_tokens_used == 50  # never double-charged


def test_a_cache_hit_reports_zero_tokens_used_and_never_double_charges_the_budget(parts) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    model = FakeModel(reply(), tokens=50)
    c = make_client(sessions, tmp, model, budget=BudgetConfig(per_scan=1000, per_org_month=1000))
    first = c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH).json()
    second = c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH).json()
    assert first["tokens_used"] == 50 and first["from_cache"] is False
    assert (
        second["from_cache"] is True and second["tokens_used"] == 0
    )  # the cached answer cost nothing this time
    with sessions() as s:
        assert repo.get_scan(s, sid, org_id=None).llm_tokens_used == 50  # charged once, not twice


def test_missing_things_and_bad_input(parts, sessions: sessionmaker[Session], tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    sessions, tmp, sid, fid = parts
    c = make_client(sessions, tmp, FakeModel(reply()))
    g = "/scans/{}/guidance"
    assert c.get(g.format(sid), params={"finding_id": "nope"}, headers=AUTH).status_code == 404
    assert (
        c.get(
            g.format("00000000-0000-0000-0000-000000000000"),
            params={"finding_id": fid},
            headers=AUTH,
        ).status_code
        == 404
    )
    assert (
        c.get(g.format("not-a-uuid"), params={"finding_id": fid}, headers=AUTH).status_code == 404
    )
    assert c.get(g.format(sid), headers=AUTH).status_code == 422
    assert c.post(f"/scans/{sid}/suggestion", json={}, headers=AUTH).status_code == 422
    assert (
        c.post(f"/scans/{sid}/suggestion", json={"finding_id": ""}, headers=AUTH).status_code == 422
    )
    assert (
        c.post(f"/scans/{sid}/suggestion", json={"finding_id": "x" * 501}, headers=AUTH).status_code
        == 422
    )
    assert (
        c.post(f"/scans/{sid}/suggestion", json={"finding_id": "nope"}, headers=AUTH).status_code
        == 404
    )


def test_an_unloaded_knowledge_base_is_a_clear_503(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    sid, fid = _seed(sessions, load_kb=False)
    c = make_client(sessions, tmp_path, FakeModel(reply()))
    for r in (
        c.get(f"/scans/{sid}/guidance", params={"finding_id": fid}, headers=AUTH),
        c.post(f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH),
    ):
        assert r.status_code == 503 and "kb load" in r.json()["detail"]


def test_a_finding_without_a_usable_snippet_still_gets_a_suggestion(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    sid, fid = _seed(sessions, snippet="[snippet withheld: near a detected secret]")
    model = FakeModel(reply(suggested_patch=None))
    r = make_client(sessions, tmp_path, model).post(
        f"/scans/{sid}/suggestion", json={"finding_id": fid}, headers=AUTH
    )
    assert r.status_code == 200 and r.json()["source"] == "ai"
    assert "kind=code" not in model.calls[0][1]  # a withheld snippet is not sent as code


def test_response_schema_matches_the_dataclass() -> None:
    from api.schemas import RemediationView
    from core.llm.service import RemediationResult

    r = RemediationResult("static", "l", "e", "i", "f", None, "low")
    assert set(asdict(r)) == set(RemediationView.model_fields)
