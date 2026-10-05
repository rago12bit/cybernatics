"""The DefectDojo round trip against a REAL DefectDojo (M13, ADR-0045): findings DefectDojo's own
parsers produced are pulled into Bulwark over several pages and closed when DefectDojo closes them;
Bulwark's open Issues are exported as SARIF, imported by DefectDojo, reimported into the same Test
with what Bulwark closed closed there too; and the export pulled back into Bulwark lands on the same
files and lines it left from.

Needs a running DefectDojo and an API v2 key for a user who can create products:

    BULWARK_DD_URL=http://localhost:8180 BULWARK_DD_TOKEN=... pytest tests/integration/test_defectdojo_live.py

Every run makes its own products (named `bulwark-rt-<random>`), so it can run against the same
instance repeatedly. Run on 2026-10-05 against DefectDojo 3.3.300 (docs/v2-week59-60-verification.md).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.connectors import defectdojo, service
from core.models import Category
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    SARIF,
    Env,
    env,  # noqa: F401  (the fixture)
    sarif_without_last_result,
)

DD_URL = os.environ.get("BULWARK_DD_URL", "").rstrip("/")
DD_TOKEN = os.environ.get("BULWARK_DD_TOKEN", "")
SAMPLES = Path("tests/golden/ingest/defectdojo")

pytestmark = pytest.mark.skipif(
    not (DD_URL and DD_TOKEN), reason="BULWARK_DD_URL and BULWARK_DD_TOKEN are not set"
)

# DefectDojo's own sample reports, read by DefectDojo's own parsers: code, packages and a web scan.
REPORTS = [
    ("Bandit Scan", Path("tests/golden/bandit/raw.json")),
    ("Anchore Grype", SAMPLES / "grype/check_all_fields.json"),
    ("ZAP Scan", SAMPLES / "zap/5_zap_sample_one.xml"),
]


def dd(method: str, path: str, **kw: Any) -> Any:
    r = httpx.request(
        method,
        f"{DD_URL}/api/v2/{path}",
        headers={"Authorization": f"Token {DD_TOKEN}", "Accept": "application/json"},
        timeout=120,
        **kw,
    )
    assert r.status_code < 300, f"{method} {path}: {r.status_code} {r.text[:500]}"
    return r.json() if r.content else None


def dd_findings(**filters: Any) -> list[dict[str, Any]]:
    out, offset = [], 0
    while True:
        page = dd("GET", "findings/", params={**filters, "limit": 100, "offset": offset})
        out += page["results"]
        if not page["next"]:
            return out
        offset += 100


def add(env: Env, kind: str, name: str, config: dict[str, Any], project: str) -> dict[str, Any]:
    body = {"project_id": project, "kind": kind, "name": name, "config": config,
            "credential": DD_TOKEN}  # fmt: skip
    r = env.client.post("/v2/connectors", json=body, headers=AUTH)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def run(env: Env, cid: str) -> dict[str, Any]:
    r = env.client.post(f"/v2/connectors/{cid}/run", headers=AUTH)
    assert r.status_code == 202, r.text
    out: dict[str, Any] = r.json()
    assert out["status"] in ("ok", "empty"), out["last_error"]
    return out


def open_findings(env: Env, asset_id: str) -> list[dict[str, Any]]:
    with env.sessions() as s:
        return service.open_issue_findings(s, asset_id, [])


@pytest.fixture
def live(env: Env, monkeypatch: pytest.MonkeyPatch) -> Env:  # noqa: F811
    monkeypatch.setenv("BULWARK_CONNECTOR_ALLOW_PRIVATE", "1")
    # Small pages, so a handful of findings is several pages of DefectDojo's own `next` links.
    monkeypatch.setattr(defectdojo, "PER_PAGE", 3)
    return env


def test_pull_from_defectdojo_pages_maps_and_closes(live: Env) -> None:
    env, tag = live, f"bulwark-rt-{uuid.uuid4().hex[:8]}"
    product_id = None
    for scan_type, path in REPORTS:
        res = dd("POST", "import-scan/", data={
            "scan_type": scan_type, "product_type_name": "Bulwark round trip",
            "product_name": tag, "engagement_name": "From scanners", "auto_create_context": "true",
            "active": "true", "verified": "false", "minimum_severity": "Info",
        }, files={"file": (path.name, path.read_bytes())})  # fmt: skip
        product_id = res["product_id"]
    listed = dd_findings(test__engagement__product=product_id, active="true", duplicate="false")
    assert len(listed) > 6  # enough for several pages of 3

    c = add(env, "defectdojo_import", "From Dojo",
            {"base_url": DD_URL, "product_id": product_id}, env.asset_id)  # fmt: skip
    first = run(env, c["id"])
    got = first["runs"][0]
    assert got["items"] == len(listed)
    assert got["requests"] == 1 + -(-len(listed) // 3)  # the product, then every page by `next`
    assert got["counts"]["new"] == len(open_findings(env, env.asset_id))
    kinds = {f["taxonomy"]["category"] for f in open_findings(env, env.asset_id)}
    assert {Category.SAST.value, Category.SCA.value, Category.DAST.value} <= kinds

    # Each DefectDojo finding is read as the kind of finding it is.
    by_rule = {
        f["evidence"]["rule_ids"]["defectdojo"][0]: f for f in open_findings(env, env.asset_id)
    }
    for d in listed:
        f = by_rule.get(f"dd-{d['id']}")
        if f is None:  # merged into another Issue by correlation; its id is still a rule there
            continue
        if d.get("file_path") and d.get("static_finding") and not d.get("component_name"):
            assert f["location"]["path"] == d["file_path"]
            assert f["location"]["start_line"] == (d["line"] or 1)
        if d.get("component_name") and d.get("vulnerability_ids"):
            assert f["package"]["name"] == d["component_name"]
            assert set(f["taxonomy"]["cve"]) <= {
                v["vulnerability_id"].upper() for v in d["vulnerability_ids"]
            }
        assert f["scoring"]["native_severity"]["defectdojo"] == d["severity"].upper()

    # Pulled again, nothing changed (the same pull is not applied twice); DefectDojo closes one,
    # and Bulwark closes it on the next pull.
    again = run(env, c["id"])["runs"][0]
    assert again["counts"]["duplicate"] is True and again["items"] == len(listed)
    gone = next(d for d in listed if d["static_finding"] and d.get("file_path"))
    dd("PATCH", f"findings/{gone['id']}/", json={"active": False, "is_mitigated": True})
    third = run(env, c["id"])["runs"][0]
    assert third["items"] == len(listed) - 1 and third["counts"]["closed"] == 1
    assert sum(1 for f in open_findings(env, env.asset_id)) == got["counts"]["new"] - 1
    print(f"\npulled {len(listed)} DefectDojo findings in {got['requests']} requests ->"
          f" {got['counts']['new']} Issues ({sorted(kinds)}); one closed in DefectDojo ->"
          f" closed {third['counts']['closed']}")  # fmt: skip


def test_a_product_that_is_not_there_is_not_found(live: Env) -> None:
    env = live
    c = add(env, "defectdojo_import", "Nowhere", {"base_url": DD_URL, "product_id": 999999},
            env.asset_id)  # fmt: skip
    r = env.client.post(f"/v2/connectors/{c['id']}/run", headers=AUTH).json()
    assert r["status"] == "failing" and "product 999999: not found" in r["last_error"]


def test_export_to_defectdojo_reimports_and_comes_back_on_the_same_lines(live: Env) -> None:
    env, tag = live, f"bulwark-rt-{uuid.uuid4().hex[:8]}"
    assert env.import_and_get(SARIF)["status"] == "applied"
    sent = open_findings(env, env.asset_id)
    assert len(sent) >= 2

    out = add(env, "defectdojo_export", "To Dojo",
              {"base_url": DD_URL, "product_type_name": "Bulwark round trip",
               "product_name": tag, "engagement_name": "From Bulwark"}, env.asset_id)  # fmt: skip
    pushed = run(env, out["id"])["runs"][0]
    test_id = pushed["counts"]["defectdojo_test_id"]
    assert pushed["counts"]["exported"] == len(sent)
    in_dd = dd_findings(test=test_id, active="true")
    assert len(in_dd) == len(sent)
    assert {(d["file_path"], d["line"]) for d in in_dd} == {
        (f["location"]["path"], f["location"]["start_line"]) for f in sent
    }

    # Bulwark closes one; the next export reimports into the same Test, and DefectDojo closes it.
    assert env.import_and_get(sarif_without_last_result())["status"] == "applied"
    remaining = open_findings(env, env.asset_id)
    assert len(remaining) == len(sent) - 1
    again = run(env, out["id"])["runs"][0]
    assert again["counts"]["defectdojo_test_id"] == test_id
    assert len(dd_findings(test=test_id, active="true")) == len(remaining)

    # Back again: pulled from that product into a second project, they land where they started.
    product_id = dd("GET", f"engagements/{dd('GET', f'tests/{test_id}/')['engagement']}/")[
        "product"
    ]
    with env.sessions() as s:
        back_asset = repo.get_or_create_asset(
            s, source_type="git", source_label="rt/back", org_id=DEFAULT_ORG_ID
        ).id
    back = add(env, "defectdojo_import", "Back from Dojo",
               {"base_url": DD_URL, "product_id": product_id}, back_asset)  # fmt: skip
    assert run(env, back["id"])["runs"][0]["items"] == len(remaining)
    returned = open_findings(env, back_asset)
    assert {(f["location"]["path"], f["location"]["start_line"]) for f in returned} == {
        (f["location"]["path"], f["location"]["start_line"]) for f in remaining
    }
    assert {f["scoring"]["normalized_severity"] for f in returned} == {
        f["scoring"]["normalized_severity"] for f in remaining
    }
    # ...and are not exported to DefectDojo again from there (no echo).
    with env.sessions() as s:
        assert service.open_issue_findings(s, back_asset, [defectdojo.SOURCE]) == []
    print(f"\nexported {len(sent)} to DefectDojo test {test_id}; after Bulwark closed one,"
          f" {len(remaining)} active there; {len(returned)} pulled back onto the same lines")  # fmt: skip
