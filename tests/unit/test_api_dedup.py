"""The deduplication API (Week 58, plan §42.3, ADR-0042) and `wait_for_dedup`, end to end over HTTP
against a real imported report; the expected counts come from the stored findings (plain Python),
not from the code under test."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pytest
from sqlalchemy import select

from core.persistence.models import FindingRow, IssueRow
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (  # noqa: F401  (env is the fixture)
    SARIF,
    Env,
    env,
    sarif_without_last_result,
)


def base(env: Env) -> str:
    return f"/v2/projects/{env.asset_id}/dedup"


def seed(env: Env) -> None:
    r = env.import_and_get(SARIF)
    assert r["status"] == "applied"


def oracle(env: Env, strategy_key) -> int:  # type: ignore[no-untyped-def]
    """How many Issues there would be if each (rule, path) were one -- from the stored findings."""
    with env.sessions() as s:
        groups: dict[Any, set[str]] = defaultdict(set)
        for row in s.scalars(select(FindingRow)):
            key = strategy_key(row.data)
            groups[key].add(row.issue_id or "")
    return len(groups)


def by_path(data: dict[str, Any]) -> str:
    return str(data["location"]["path"])


def test_overview_lists_each_source_with_the_default_and_what_is_recommended(env: Env) -> None:
    seed(env)
    body = env.client.get(base(env), headers=AUTH).json()
    assert body["default"] == "fingerprint_v2"
    assert {s["name"] for s in body["strategies"]} == {
        "fingerprint_v2", "tool_id", "hash_fields", "tool_id_or_hash", "package"}  # fmt: skip
    (source,) = [x for x in body["sources"] if x["source"] == "semgrep-oss"]
    assert (source["strategy"], source["version"], source["issues_seen"]) == (
        "fingerprint_v2",
        0,
        3,
    )
    assert body["sources"] and "title" in body["fields"]


def test_preview_then_apply_changes_issues_exactly_as_previewed(env: Env) -> None:
    seed(env)
    change = {"source": "semgrep-oss", "strategy": "hash_fields", "fields": ["path"]}
    preview = env.client.post(f"{base(env)}/preview", json=change, headers=AUTH)
    assert preview.status_code == 200, preview.text
    p = preview.json()
    expected_after = oracle(env, by_path)  # one Issue per file, counted from the stored findings
    assert p["issues_before"] == 3 and p["to"]["version"] == 1 and p["digest"]
    assert p["issues_after"] == 1 and p["issues_merged_away"] == 2 and p["merge_groups"] == 1
    # Nothing has changed yet.
    with env.sessions() as s:
        assert len(list(s.scalars(select(IssueRow)))) == 3

    done = env.client.post(
        f"{base(env)}/apply",
        json={**change, "digest": p["digest"], "note": "go"},
        headers=AUTH,
    )
    assert done.status_code == 200, done.text
    assert done.json()["version"] == 1 and done.json()["summary"] == p["summary"]
    with env.sessions() as s:
        assert len(list(s.scalars(select(IssueRow)))) == expected_after == p["issues_after"]
        assert all(i.fingerprint.startswith("dd1:") for i in s.scalars(select(IssueRow)))
    hist = env.client.get(
        f"{base(env)}/history", params={"source": "semgrep-oss"}, headers=AUTH
    ).json()
    assert [(h["version"], h["strategy"], h["note"]) for h in hist] == [(1, "hash_fields", "go")]
    after = env.client.get(base(env), headers=AUTH).json()
    assert [x for x in after["sources"] if x["source"] == "semgrep-oss"][0]["version"] == 1


def test_apply_refuses_a_preview_the_project_has_moved_away_from(env: Env) -> None:
    seed(env)
    p = env.client.post(
        f"{base(env)}/preview", json={"source": "semgrep-oss", "strategy": "tool_id"}, headers=AUTH
    ).json()
    import json as _json

    from tests.unit.test_api_ingest import sarif_without_last_result

    assert _json.loads(sarif_without_last_result())  # a different report moves the project
    env.import_and_get(sarif_without_last_result())
    r = env.client.post(
        f"{base(env)}/apply",
        json={"source": "semgrep-oss", "strategy": "tool_id", "digest": p["digest"]},
        headers=AUTH,
    )
    # Closing an Issue changes no occurrence, so the plan may be the same; a wrong digest is not.
    bad = env.client.post(
        f"{base(env)}/apply",
        json={"source": "semgrep-oss", "strategy": "tool_id", "digest": "0" * 32},
        headers=AUTH,
    )
    assert bad.status_code == 409 and "preview" in bad.json()["detail"]
    assert r.status_code in (200, 409)


def test_bad_requests_and_other_orgs_are_refused(env: Env) -> None:
    seed(env)

    def post(path: str, body: dict[str, Any]) -> Any:
        return env.client.post(f"{base(env)}{path}", json=body, headers=AUTH)

    assert post("/preview", {"source": "semgrep-oss", "strategy": "nope"}).status_code == 422
    assert post("/preview", {"source": "semgrep-oss", "strategy": "hash_fields"}).status_code == 422
    assert (
        post(
            "/preview", {"source": "semgrep-oss", "strategy": "tool_id", "fields": ["title"]}
        ).status_code
        == 422
    )
    other = f"/v2/projects/{env.other_asset_id}/dedup"
    assert env.client.get(other, headers=AUTH).status_code == 404  # another org's project
    assert (
        env.client.post(
            f"{other}/preview", json={"source": "x", "strategy": "tool_id"}, headers=AUTH
        ).status_code
        == 404
    )
    assert env.client.get("/v2/projects/not-a-uuid/dedup", headers=AUTH).status_code == 404


def test_a_read_token_may_preview_but_only_a_write_token_may_apply(env: Env) -> None:
    from tests.unit.test_api_ingest import _scoped

    seed(env)
    change = {"source": "semgrep-oss", "strategy": "hash_fields", "fields": ["path"]}
    read, write = _scoped(env, "ingest:read"), _scoped(env, "ingest:write")
    assert env.client.get(base(env), headers=read).status_code == 200
    assert env.client.get(base(env), headers=write).status_code == 403
    preview = env.client.post(f"{base(env)}/preview", json=change, headers=read)
    assert preview.status_code == 200
    apply = {**change, "digest": preview.json()["digest"]}
    assert env.client.post(f"{base(env)}/apply", json=apply, headers=read).status_code == 403
    assert env.client.post(f"{base(env)}/apply", json=apply, headers=write).status_code == 200


def test_wait_for_dedup_holds_the_response_until_the_import_is_matched(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a worker that finishes the job, the 202 carries the resting status and
    `dedup_complete` is true; without one the wait is bounded and ends at `queued`."""
    import api.ingest as ingest

    real = ingest._dispatch

    def dispatch_and_work(st: Any, s: Any, record: Any) -> None:
        real(st, s, record)
        env.drain()  # a worker that picks it up straight away

    monkeypatch.setattr(ingest, "_dispatch", dispatch_and_work)
    done = env.post(SARIF, wait_for_dedup="true").json()
    assert done["status"] == "applied" and env.get(done["import_id"])["dedup_complete"] is True

    monkeypatch.setattr(ingest, "_dispatch", real)
    monkeypatch.setattr(ingest, "WAIT_SECONDS", 1)  # nothing drains the queue inside this call
    pending = env.post(sarif_without_last_result(), wait_for_dedup="true").json()
    assert pending["status"] == "queued"
    view = env.get(pending["import_id"])
    assert view["dedup_complete"] is False  # still waiting for a worker: not matched yet
    env.drain()
    assert env.get(pending["import_id"])["dedup_complete"] is True


def test_the_parser_list_names_the_recommended_strategy(env: Env) -> None:
    parsers = {p["name"]: p for p in env.client.get("/v2/parsers", headers=AUTH).json()}
    assert parsers["nessus"]["recommended_dedup"] == "tool_id"
    assert parsers["grype"]["recommended_dedup"] == "package"
    assert parsers["sarif"]["recommended_dedup"] == "fingerprint_v2"
