"""The universal mapper over HTTP (Week 59, plan §42.4): sample -> draft -> preview -> save -> import
with `parser=universal:<id>`, then reimport. Expected counts come from the test's own records."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.deps import AppState
from api.main import create_app
from core.llm.budget import BudgetConfig
from core.llm.client import Completion
from core.persistence.models import AuditEntry, FindingRow, IssueRow
from tests.unit.test_api import AUTH, FakeSubscriber
from tests.unit.test_api_ingest import OTHER_ORG, Env, env  # noqa: F401  (env is the fixture)

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


def report(names: list[str]) -> bytes:
    return json.dumps(
        {
            "generator": "acme-scanner 3.1",
            "issues": [
                {"Issue Name": n, "Risk": "P1" if i == 0 else "low", "PluginID": f"AC-{i}",
                 "Location": {"File": f"src/{n.lower().replace(' ', '_')}.py", "Line": i + 1},
                 "CWE": "CWE-89"}
                for i, n in enumerate(names)
            ],
        }  # fmt: skip
    ).encode()


NAMES = ["SQL injection", "Path traversal", "Weak hash", "Open redirect"]


def analyze(env: Env, data: bytes, **form: Any) -> Any:
    return env.client.post(
        "/v2/mappings/analyze",
        files={"file": ("acme-scan.json", data)},
        data={"use_model": "true", **form},
        headers=AUTH,
    )


def save(env: Env, spec: dict[str, Any], name: str = "Acme scanner", headers: Any = AUTH) -> Any:
    return env.client.post(
        "/v2/mappings", json={"name": name, "spec": spec, "proposed_by": "heuristic"},
        headers=headers,
    )  # fmt: skip


def drafted(env: Env) -> dict[str, Any]:
    r = analyze(env, report(NAMES))
    assert r.status_code == 200, r.text
    return dict(r.json()["proposal"]["spec"])


def test_a_sample_is_described_and_a_draft_proposed(env: Env) -> None:
    body = analyze(env, report(NAMES)).json()
    assert body["analysis"]["format"] == "json" and body["analysis"]["error"] is None
    top = body["analysis"]["candidates"][0]
    assert top["records"] == "$.issues[*]" and top["count"] == len(NAMES)
    assert body["suggested_source"] == "acme-scan" and body["model_available"] is False
    proposal = body["proposal"]
    assert proposal["proposed_by"] == "heuristic"
    assert proposal["spec"]["fields"]["title"] == '$["Issue Name"]'
    assert "title" in body["fields"] and len(body["sample_digest"]) == 64
    assert list(env.settings.ingest_dir.glob("samples/*")) == []  # the sample is not kept


def test_preview_shows_what_a_mapping_makes_of_the_sample_without_saving(env: Env) -> None:
    spec = drafted(env)
    r = env.client.post(
        "/v2/mappings/preview",
        files={"file": ("s.json", report(NAMES))},
        data={"spec": json.dumps(spec)},
        headers=AUTH,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == len(NAMES) and body["error"] is None
    assert [i["title"] for i in body["issues"]] == NAMES
    assert (
        body["issues"][0]["severity"] == "CRITICAL" and body["issues"][0]["native_severity"] == "P1"
    )
    assert body["by_severity"] == {"CRITICAL": 1, "LOW": 3}
    assert body["issues"][0]["location"] == "src/sql_injection.py:1"
    with env.sessions() as s:
        assert list(s.scalars(select(IssueRow))) == []


def test_preview_refuses_a_mapping_that_cannot_run(env: Env) -> None:
    r = env.client.post(
        "/v2/mappings/preview",
        files={"file": ("s.json", report(NAMES))},
        data={"spec": json.dumps({"format": "json", "source": "acme", "records": "$.issues",
                                  "fields": {"title": "$.x"}})},  # fmt: skip
        headers=AUTH,
    )
    assert r.status_code == 422 and "[*]" in r.json()["detail"]


def test_a_saved_mapping_imports_and_reimports_like_any_parser(env: Env) -> None:
    saved = save(env, drafted(env))
    assert saved.status_code == 201, saved.text
    m = saved.json()
    assert m["version"] == 1 and m["parser"] == f"universal:{m['id']}"

    first = env.import_and_get(report(NAMES), parser=m["parser"], filename="acme-1.json")
    assert first["status"] == "applied", first
    assert first["counts"]["new"] == len(NAMES) and first["parser"] == m["parser"]
    with env.sessions() as s:
        rows = list(s.scalars(select(FindingRow)))
        assert {r.data["evidence"]["reported_by"][0] for r in rows} == {"acme-scan"}

    second = env.import_and_get(report(NAMES[:-1]), parser=m["parser"], filename="acme-2.json")
    assert second["status"] == "applied"
    assert (second["counts"]["unchanged"], second["counts"]["closed"]) == (len(NAMES) - 1, 1)


def test_saving_again_under_a_name_adds_a_version(env: Env) -> None:
    spec = drafted(env)
    one = save(env, spec).json()
    two = save(env, {**spec, "severity_map": {"p1": "HIGH"}}).json()
    assert (one["version"], two["version"]) == (1, 2) and one["id"] != two["id"]
    assert [v["version"] for v in two["versions"]] == [2, 1]
    listed = env.client.get("/v2/mappings", headers=AUTH).json()
    assert [(m["name"], m["version"]) for m in listed] == [("Acme scanner", 2)]
    # The first version is still readable: it is what read any import made with it.
    assert env.client.get(f"/v2/mappings/{one['id']}", headers=AUTH).json()["version"] == 1


def test_saving_is_audit_logged(env: Env) -> None:
    m = save(env, drafted(env)).json()
    with env.sessions() as s:
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "mapping.saved")).one()
        assert entry.target == f"mapping:{m['id']}"


def test_a_built_in_name_cannot_be_a_mapped_source(env: Env) -> None:
    r = save(env, {**drafted(env), "source": "nessus"})
    assert r.status_code == 422 and "built-in" in r.json()["detail"]


def test_an_unrecognised_file_suggests_a_saved_mapping_but_does_not_pick_it(env: Env) -> None:
    m = save(env, drafted(env)).json()
    r = env.post(report(NAMES))
    assert r.status_code == 422
    detected = r.json()["detail"]["detected"]
    assert detected[0]["parser"] == m["parser"] and detected[0]["confidence"] >= 0.9
    assert detected[0]["label"] == "Acme scanner"


def test_another_org_cannot_see_or_use_a_mapping(env: Env) -> None:
    m = save(env, drafted(env)).json()
    assert env.client.get(f"/v2/mappings/{m['id']}", headers=OTHER).status_code == 404
    assert env.client.get("/v2/mappings", headers=OTHER).json() == []
    r = env.client.post(
        "/v2/ingest",
        data={"project": env.other_asset_id, "parser": m["parser"]},
        files={"file": ("r.json", report(NAMES))},
        headers=OTHER,
    )
    assert r.status_code == 422 and "unknown mapping" in r.text


def test_a_sample_over_the_limit_is_refused(env: Env) -> None:
    r = analyze(env, b"[" + b" " * (2 * 1024 * 1024) + b"]")
    assert r.status_code == 413


def test_a_mapping_that_was_deleted_fails_the_queued_import_with_a_reason(env: Env) -> None:
    from core.persistence.models import IngestMapping

    m = save(env, drafted(env)).json()
    r = env.post(report(NAMES), parser=m["parser"])
    assert r.status_code == 202
    with env.sessions() as s:
        s.delete(s.get(IngestMapping, m["id"]))
        s.commit()
    env.drain()
    view = env.get(r.json()["import_id"])
    assert view["status"] == "failed" and "unknown mapping" in view["error"]


# --- with a model ---------------------------------------------------------------------------


@dataclass
class FakeModel:
    reply: str
    model: str = "fake-mapper"

    def complete(self, system: str, user: str) -> Completion:
        return Completion(self.reply, tokens=500)


def model_client(env: Env, model: Any, budget: BudgetConfig | None = None) -> TestClient:
    st = AppState(
        env.settings, env.sessions, lambda *_: None, FakeSubscriber(),
        llm_mapper=model, llm_budget=budget or BudgetConfig(),
    )  # fmt: skip
    return TestClient(create_app(st))


def test_with_a_model_the_draft_is_the_models_after_checking(env: Env) -> None:
    reply = {"records": "$.issues[*]", "category": "sast",
             "fields": {"title": '$["Issue Name"]', "severity": "$.Risk", "path": "$.Made.Up"},
             "severity_map": {"p1": "CRITICAL"}}  # fmt: skip
    client = model_client(env, FakeModel(json.dumps(reply)))
    body = client.post(
        "/v2/mappings/analyze", files={"file": ("a.json", report(NAMES))}, headers=AUTH
    ).json()
    assert body["model_available"] is True
    proposal = body["proposal"]
    assert proposal["proposed_by"] == "model:fake-mapper"
    assert "path" not in proposal["spec"]["fields"] and any(
        "$.Made.Up" in n for n in proposal["notes"]
    )


@pytest.mark.parametrize("reply", ["no json here"])
def test_an_unusable_model_draft_falls_back_to_name_matching_and_says_so(
    env: Env, reply: str
) -> None:
    client = model_client(env, FakeModel(reply))
    proposal = client.post(
        "/v2/mappings/analyze", files={"file": ("a.json", report(NAMES))}, headers=AUTH
    ).json()["proposal"]
    assert proposal["proposed_by"] == "heuristic"
    assert "could not be used" in proposal["notes"][0]


def test_the_org_token_budget_stops_the_model_call(env: Env) -> None:
    client = model_client(env, FakeModel("{}"), BudgetConfig(per_scan=1, per_org_month=0))
    proposal = client.post(
        "/v2/mappings/analyze", files={"file": ("a.json", report(NAMES))}, headers=AUTH
    ).json()["proposal"]
    assert proposal["proposed_by"] == "heuristic" and "budget" in proposal["notes"][0]
