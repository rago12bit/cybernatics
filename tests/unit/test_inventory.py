"""The component inventory (plan §46.1): every package of every SBOM, by library and version, per
project -- from Bulwark's own scans and from imported CycloneDX and SPDX files -- and the search
that answers "where do we use this?"."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core import inventory
from core.events import MemoryPublisher
from core.persistence import repo
from core.persistence.models import ComponentRow, Library, PriorityPolicy, Scan
from core.persistence.storage import MemoryStore
from core.pipeline import run_scan_job
from core.scan import ToolOutcome
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_pipeline import executor_from, make_scan

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core"


def bom(*components: tuple[str, str], vulnerabilities: bool = False) -> bytes:
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"bom-ref": purl, "name": purl.rsplit("/", 1)[-1].split("@")[0], "version": v,
             "purl": f"{purl}@{v}", "properties": [{"name": "syft:location:0:path", "value": "/requirements.txt"}]}  # fmt: skip
            for purl, v in components
        ],
    }
    if vulnerabilities:
        doc["vulnerabilities"] = []
    return json.dumps(doc).encode()


def current(s: Session, asset_id: str | None = None) -> list[tuple[str, str, str]]:
    q = (
        select(Library.name, ComponentRow.version, ComponentRow.source)
        .join(Library, Library.id == ComponentRow.library_id)
        .where(ComponentRow.current.is_(True))
    )
    if asset_id:
        q = q.where(ComponentRow.asset_id == asset_id)
    return sorted(tuple(r) for r in s.execute(q).all())  # type: ignore[misc]


# ------------------------------------------------------------------ from scans


def test_a_full_scan_records_its_sbom_and_the_next_one_replaces_it(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    (sample_repo / "requirements.txt").write_text("flask\nrequests\n")
    (sample_repo / "app.py").write_text("import flask\n")

    def scan(components: bytes, pr_ref: str | None = None) -> str:
        with sessions() as s:
            sid = make_scan(s, ["syft"], str(sample_repo), pr_ref=pr_ref)
        table = {"syft": ToolOutcome("syft", "ok", [], raw=components)}
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
        return sid

    first = scan(bom(("pkg:pypi/flask", "2.0.0"), ("pkg:pypi/requests", "2.0.0")))
    with sessions() as s:
        assert current(s) == [("flask", "2.0.0", "scan"), ("requests", "2.0.0", "scan")]
        rows = {r.version: r for r in s.scalars(select(ComponentRow))}
        assert rows["2.0.0"].paths == ["requirements.txt"]
        flask = s.scalars(select(ComponentRow).join(Library).where(Library.name == "flask")).one()
        assert flask.reachable is True and "app.py" in flask.reachable_reason
        reqs = s.scalars(select(ComponentRow).join(Library).where(Library.name == "requests")).one()
        assert reqs.reachable is False  # declared, imported by nothing in the application

    scan(bom(("pkg:pypi/flask", "2.3.0")))
    scan(bom(("pkg:pypi/flask", "9.9.9")), pr_ref="refs/pull/1/head")  # a PR: not the project
    with sessions() as s:
        assert current(s) == [("flask", "2.3.0", "scan")]
        history = s.scalars(select(ComponentRow).where(ComponentRow.scan_id == first)).all()
        assert {r.current for r in history} == {False} and len(history) == 2
        assert len(s.scalars(select(Library)).all()) == 2  # flask once, however many versions


def test_merging_identity_and_what_is_skipped(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset = repo.get_or_create_asset(s, source_type="git", source_label="m/n")
        sid = make_scan(s, [], "x", asset_label="m/n")
        out = inventory.record(
            s, org_id=DEFAULT_ORG_ID, asset_id=asset.id, scan_id=sid, source="scan",
            packages=[
                {"purl": "pkg:pypi/Flask_Login@0.6.3", "path": "a/requirements.txt"},
                {"purl": "pkg:pypi/flask-login@0.6.3", "path": "b/poetry.lock", "relation": "direct"},  # fmt: skip
                {"purl": "pkg:npm/%40babel/core@7.1.0"},
                {"purl": "not a purl"},
                {"purl": "pkg:"},
            ],
        )  # fmt: skip
        assert (out.components, out.new_libraries, out.skipped) == (2, 2, 2)
        login = s.scalars(select(ComponentRow).where(ComponentRow.version == "0.6.3")).one()
        assert login.paths == ["a/requirements.txt", "b/poetry.lock"] and login.relation == "direct"
        names = {lib.key: lib.purl for lib in s.scalars(select(Library))}
        assert names == {"pypi:flask-login": "pkg:pypi/Flask_Login", "npm:@babel/core": "pkg:npm/%40babel/core"}  # fmt: skip
        # Recording the same scan again replaces it rather than adding to it.
        inventory.record(
            s, org_id=DEFAULT_ORG_ID, asset_id=asset.id, scan_id=sid, source="scan",
            packages=[{"purl": "pkg:npm/%40babel/core@7.1.0"}],
        )  # fmt: skip
        assert current(s) == [("@babel/core", "7.1.0", "scan")]


def test_backfill_records_sboms_from_before_the_inventory(sessions: sessionmaker[Session]) -> None:
    summary = {"components": 1, "packages": [{"purl": f"{LOG4J}@2.14.1", "relation": "direct"}]}
    with sessions() as s:
        old = make_scan(s, [], "x", asset_label="old/one")
        newer = make_scan(s, [], "x", asset_label="old/one")
        pr = make_scan(s, [], "x", asset_label="old/two", pr_ref="refs/pull/2/head")
        for sid in (old, newer, pr):
            scan = s.get(Scan, sid)
            assert scan is not None
            scan.status, scan.sbom_summary = "completed", summary
        s.commit()
        assert inventory.backfill(s, DEFAULT_ORG_ID) == 1  # the PR scan is not the project
        rows = s.scalars(select(ComponentRow)).all()
        assert [(r.scan_id, r.current) for r in rows] == [(newer, True)]
        assert inventory.backfill(s, DEFAULT_ORG_ID) == 0
        assert inventory.backfill(s, OTHER_ORG) == 0


# ------------------------------------------------------------------ from imports


def test_imported_sbom_files_join_the_inventory_and_a_revert_restores_the_previous(
    env: Env,
) -> None:
    first = env.import_and_get(bom((LOG4J, "2.14.1"), ("pkg:npm/lodash", "4.17.20")), filename="bom.json")  # fmt: skip
    assert first["status"] == "applied", first
    test_id = first["test_id"]
    source = inventory.import_source(test_id)
    with env.sessions() as s:
        assert current(s, env.asset_id) == [
            ("lodash", "4.17.20", source), ("org.apache.logging.log4j:log4j-core", "2.14.1", source)
        ]  # fmt: skip
    second = env.import_and_get(
        bom((LOG4J, "2.17.1"), vulnerabilities=True), filename="bom.json", test_id=test_id
    )
    assert second["status"] == "applied", second
    with env.sessions() as s:
        assert current(s, env.asset_id) == [("org.apache.logging.log4j:log4j-core", "2.17.1", source)]  # fmt: skip
    r = env.client.post(f"/v2/imports/{second['id']}/revert", headers=AUTH)
    assert r.status_code == 200, r.text
    with env.sessions() as s:
        assert current(s, env.asset_id) == [
            ("lodash", "4.17.20", source), ("org.apache.logging.log4j:log4j-core", "2.14.1", source)
        ]  # fmt: skip

    spdx = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
        "packages": [
            {"SPDXID": "SPDXRef-a", "name": "django", "versionInfo": "4.2.0",
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                               "referenceLocator": "pkg:pypi/django@4.2.0"}]},
            {"SPDXID": "SPDXRef-b", "name": "no-purl", "versionInfo": "1"},
        ],
    }  # fmt: skip
    third = env.import_and_get(json.dumps(spdx).encode(), filename="sbom.spdx.json")
    assert third["status"] == "applied", third
    with env.sessions() as s:
        mine = inventory.import_source(third["test_id"])
        assert [n for n, _v, src in current(s, env.asset_id) if src == mine] == ["django"]


# ------------------------------------------------------------------ the search


def seed(env: Env) -> dict[str, str]:
    projects: dict[str, str] = {}
    with env.sessions() as s:
        for label, version, facing, imported in (
            ("payments-api", "2.14.1", True, True),
            ("partner-gateway", "2.0-beta9", True, None),
            ("reporting-svc", "2.14.1", False, False),
            ("billing", "2.17.1", None, None),
            ("legacy", "2.17.2", None, None),
        ):
            asset = repo.get_or_create_asset(
                s, source_type="git", source_label=label, org_id=DEFAULT_ORG_ID
            )
            projects[label] = asset.id
            sid = make_scan(s, [], "x", asset_label=label)
            inventory.record(
                s, org_id=DEFAULT_ORG_ID, asset_id=asset.id, scan_id=sid, source="scan",
                packages=[{"purl": f"{LOG4J}@{version}", "relation": "transitive",
                           "path": "pom.xml", "reachable": imported},
                          {"purl": "pkg:npm/lodash@4.17.21"},
                          {"purl": f"pkg:pypi/requests@{'latest' if label == 'legacy' else '2.31.0'}"}],
            )  # fmt: skip
            if facing is not None:
                s.add(
                    PriorityPolicy(
                        org_id=DEFAULT_ORG_ID, asset_id=asset.id, version=1, weights={},
                        context={"internet_facing": facing}, status="done",
                    )
                )  # fmt: skip
        s.commit()
    return projects


def test_where_do_we_use_this(env: Env) -> None:
    projects = seed(env)
    r = env.client.get("/v2/components", params={"purl": LOG4J, "version": "<2.17.1"}, headers=AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["library"]["name"] == "org.apache.logging.log4j:log4j-core"
    assert body["constraint"] == "<2.17.1"
    assert sorted(u["project"] for u in body["uses"]) == [
        "partner-gateway", "payments-api", "reporting-svc"
    ]  # fmt: skip
    assert body["summary"] == {
        "projects": 3, "portfolios": 0, "internet_facing": 2, "exposure_unset": 0,
        "imported_by_app": 1, "direct": 0, "versions": 2,
    }  # fmt: skip
    versions = {v["version"]: v for v in body["versions"]}
    assert versions["2.14.1"] == {"version": "2.14.1", "projects": 2, "matches": True}
    assert versions["2.17.1"]["matches"] is False
    assert versions["2.17.2"]["matches"] is False and body["uncomparable"] == []
    pay = next(u for u in body["uses"] if u["project"] == "payments-api")
    assert pay["exposure"] == "internet" and pay["paths"] == ["pom.xml"] and pay["reachable"]

    exact = env.client.get("/v2/components", params={"purl": f"{LOG4J}@2.14.1"}, headers=AUTH)
    assert exact.json()["summary"]["projects"] == 2 and exact.json()["constraint"] == "=2.14.1"
    everything = env.client.get("/v2/components", params={"purl": LOG4J}, headers=AUTH).json()
    assert everything["summary"]["projects"] == 5 and everything["uncomparable"] == []
    # "latest" is not a PEP 440 version: it is said, not counted in or out.
    requests = env.client.get(
        "/v2/components", params={"purl": "pkg:pypi/requests", "version": "<2.32.0"}, headers=AUTH
    ).json()
    assert requests["summary"]["projects"] == 4 and requests["uncomparable"] == ["latest"]
    assert {v["version"]: v["matches"] for v in requests["versions"]} == {"2.31.0": True, "latest": None}  # fmt: skip
    one = env.client.get(
        "/v2/components", params={"purl": LOG4J, "project_id": projects["billing"]}, headers=AUTH
    ).json()
    assert [u["project"] for u in one["uses"]] == ["billing"]

    nothing = env.client.get("/v2/components", params={"purl": "pkg:npm/left-pad"}, headers=AUTH)
    assert nothing.json()["library"] is None and nothing.json()["uses"] == []
    bad = env.client.get("/v2/components", params={"purl": "log4j"}, headers=AUTH)
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "purl"
    bad = env.client.get("/v2/components", params={"purl": LOG4J, "version": "<<1"}, headers=AUTH)
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "version"
    other = env.client.get(
        "/v2/components", params={"purl": LOG4J, "project_id": env.other_asset_id}, headers=AUTH
    )
    assert other.status_code == 404


def test_another_organization_sees_none_of_it(env: Env) -> None:
    seed(env)
    r = env.client.get("/v2/components", params={"purl": LOG4J}, headers=OTHER).json()
    assert r["library"] is None and r["uses"] == []
    assert env.client.get("/v2/libraries", headers=OTHER).json() == []


def test_libraries_once_each_most_used_first(env: Env) -> None:
    seed(env)
    rows = env.client.get("/v2/libraries", headers=AUTH).json()
    assert [(r["name"], r["projects"], r["versions"]) for r in rows] == [
        ("lodash", 5, 1), ("org.apache.logging.log4j:log4j-core", 5, 4), ("requests", 5, 2)
    ]  # fmt: skip
    found = env.client.get("/v2/libraries", params={"q": "LOG4J"}, headers=AUTH).json()
    assert [r["name"] for r in found] == ["org.apache.logging.log4j:log4j-core"]
    by_purl = env.client.get("/v2/libraries", params={"q": f"{LOG4J}@1"}, headers=AUTH).json()
    assert len(by_purl) == 1
    assert env.client.get("/v2/libraries", params={"q": "100%_"}, headers=AUTH).json() == []
    assert env.client.get("/v2/libraries", params={"ecosystem": "npm"}, headers=AUTH).json()[0]["name"] == "lodash"  # fmt: skip
