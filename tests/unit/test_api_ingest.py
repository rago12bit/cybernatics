"""The ingest API end to end (Week 54 task 7, plan §42.1, ADR-0040): real files through POST
/v2/ingest, the worker job run by `drain()` (as a real worker would, after the 202), and what lands in
the database. SQLite, so org isolation here is the application layer; tests/integration/
test_ingest_api_rls_docker.py repeats the cross-org cases against real Postgres RLS."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.imports.jobs import process_import
from core.imports.parsers import PARSERS
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.persistence.models import FindingRow, ImportRecord, IssueRow, Organization, Scan
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH, TOKEN, FakeSubscriber

OTHER_ORG = "other-org"
SARIF = Path("tests/golden/semgrep/raw.json").read_bytes()
SBOM = Path("tests/golden/ingest/cyclonedx-sbom.json").read_bytes()


def sarif_without_last_result() -> bytes:
    doc = json.loads(SARIF)
    doc["runs"][0]["results"] = doc["runs"][0]["results"][:-1]
    return json.dumps(doc).encode()


class Env:
    def __init__(
        self,
        client: TestClient,
        sessions: sessionmaker[Session],
        queue: list[tuple[str, str]],
        settings: Settings,
        asset_id: str,
        other_asset_id: str,
    ) -> None:
        self.client, self.sessions, self.queue = client, sessions, queue
        self.settings, self.asset_id, self.other_asset_id = settings, asset_id, other_asset_id

    def drain(self) -> None:
        """Run queued jobs the way the worker would (one session each)."""
        while self.queue:
            import_id, org = self.queue.pop(0)
            with self.sessions() as s:
                process_import(s, import_id, org, self.settings)

    def post(self, data: bytes, **form: Any) -> Any:
        form.setdefault("project", self.asset_id)
        files = {"file": (form.pop("filename", "report.sarif"), data)}
        return self.client.post("/v2/ingest", data=form, files=files, headers=AUTH)

    def get(self, import_id: str, **kw: Any) -> dict[str, Any]:
        r = self.client.get(f"/v2/imports/{import_id}", headers=AUTH)
        assert r.status_code == 200, r.text
        return r.json()  # type: ignore[no-any-return]

    def import_and_get(self, data: bytes, **form: Any) -> dict[str, Any]:
        r = self.post(data, **form)
        assert r.status_code in (200, 202), r.text
        self.drain()
        return self.get(r.json()["import_id"])


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Path) -> Env:
    queue: list[tuple[str, str]] = []
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=1_000_000, ingest_sandbox=False,
    )  # fmt: skip
    app = create_app(
        AppState(
            settings, sessions, lambda sid, org: None, FakeSubscriber(),
            enqueue_import=lambda iid, org: queue.append((iid, org)),
        )
    )  # fmt: skip
    with sessions() as s:
        s.add_all(
            [Organization(id=DEFAULT_ORG_ID, name="default"), Organization(id=OTHER_ORG, name="o")]
        )
        s.commit()
        a = repo.get_or_create_asset(
            s, source_type="git", source_label="a/b", org_id=DEFAULT_ORG_ID
        )
        b = repo.get_or_create_asset(s, source_type="git", source_label="x/y", org_id=OTHER_ORG)
        ids = (a.id, b.id)
    return Env(TestClient(app), sessions, queue, settings, *ids)


def count(env: Env, model: type) -> int:
    with env.sessions() as s:
        return s.scalar(select(func.count()).select_from(model)) or 0


def issue_states(env: Env) -> list[str]:
    with env.sessions() as s:
        return sorted(i.state for i in s.scalars(select(IssueRow)))


def uploads_left(env: Env) -> list[Path]:
    d = env.settings.ingest_dir
    return sorted(d.iterdir()) if d.exists() else []


# --- the plain path -------------------------------------------------------------------------


def test_an_uploaded_report_is_queued_then_applied_with_counts(env: Env) -> None:
    r = env.post(SARIF)
    assert r.status_code == 202
    body = r.json()
    assert body["parser"] == "sarif" and body["confidence"] >= 0.9 and body["duplicate"] is False
    assert env.get(body["import_id"])["status"] == "queued"  # accepted, not yet done

    env.drain()
    view = env.get(body["import_id"])
    assert view["status"] == "applied" and view["error"] is None
    # Four SARIF results, three Issues: two Semgrep rules fired on one line for one weakness, which
    # correlation merges into a single defect exactly as it does for a native scan.
    assert view["counts"] == {"new": 3, "unchanged": 0, "reopened": 0, "closed": 0, "detached": 0}
    assert view["dedup_complete"] is True and view["close_missing"] is True
    assert issue_states(env) == ["new"] * 3
    assert uploads_left(env) == []  # the stored upload is gone once applied


def test_the_first_import_creates_the_standing_import_engagement_and_a_named_test(
    env: Env,
) -> None:
    view = env.import_and_get(SARIF)
    with env.sessions() as s:
        eng = repo.get_engagement(s, view["engagement_id"], DEFAULT_ORG_ID)
        test = repo.get_engagement_test(s, view["test_id"], DEFAULT_ORG_ID)
        assert eng is not None and eng.engagement_type == "import"
        assert test is not None and test.name == "SARIF 2.1.0" and test.parser == "sarif"
    again = env.import_and_get(sarif_without_last_result())
    assert again["engagement_id"] == view["engagement_id"] and again["test_id"] == view["test_id"]


def test_the_same_file_twice_is_a_no_op_that_returns_the_original(env: Env) -> None:
    first = env.post(SARIF).json()
    env.drain()
    again = env.post(SARIF)
    assert again.status_code == 200  # nothing queued
    assert again.json()["duplicate"] is True and again.json()["import_id"] == first["import_id"]
    assert env.queue == [] and count(env, ImportRecord) == 1 and uploads_left(env) == []


def test_a_changed_file_reimports_against_the_previous_one(env: Env) -> None:
    env.import_and_get(SARIF)
    second = env.import_and_get(sarif_without_last_result())
    assert second["counts"] == {"new": 0, "unchanged": 2, "reopened": 0, "closed": 1, "detached": 0}
    assert len(second["closed_issue_ids"]) == 1
    assert (
        issue_states(env) == ["fixed", "new", "new", "new"] or issue_states(env).count("fixed") == 1
    )


def test_a_returning_finding_is_reopened_and_listed_by_id(env: Env) -> None:
    env.import_and_get(SARIF)
    env.import_and_get(sarif_without_last_result())
    third = env.import_and_get(SARIF)  # the dropped one comes back
    assert third["counts"]["reopened"] == 1 and third["counts"]["new"] == 0
    assert len(third["reopened_issue_ids"]) == 1


def test_a_test_s_import_history_lists_each_import_newest_first(env: Env) -> None:
    first = env.import_and_get(SARIF)
    second = env.import_and_get(sarif_without_last_result())
    r = env.client.get(f"/v2/tests/{first['test_id']}/imports", headers=AUTH)
    assert r.status_code == 200
    assert [i["id"] for i in r.json()] == [second["id"], first["id"]]


# --- preview, confirm, cancel ---------------------------------------------------------------


def test_a_preview_saves_nothing_and_confirming_applies_the_same_counts(env: Env) -> None:
    env.import_and_get(SARIF)
    r = env.post(sarif_without_last_result(), preview="true")
    assert r.status_code == 202
    env.drain()
    previewed = env.get(r.json()["import_id"])
    assert previewed["status"] == "previewed" and previewed["mode"] == "preview"
    assert previewed["counts"] == {
        "new": 0,
        "unchanged": 2,
        "reopened": 0,
        "closed": 1,
        "detached": 0,
    }
    assert len(previewed["closed_issue_ids"]) == 1
    assert issue_states(env).count("fixed") == 0 and count(env, Scan) == 1  # nothing applied yet
    assert len(uploads_left(env)) == 1  # the file waits for the person's decision

    c = env.client.post(f"/v2/imports/{previewed['id']}/confirm", headers=AUTH)
    assert c.status_code == 202
    env.drain()
    applied = env.get(previewed["id"])
    assert applied["status"] == "applied" and applied["counts"] == previewed["counts"]
    assert issue_states(env).count("fixed") == 1 and uploads_left(env) == []


def test_cancelling_a_preview_discards_the_file(env: Env) -> None:
    r = env.post(SARIF, preview="true")
    env.drain()
    import_id = r.json()["import_id"]
    c = env.client.post(f"/v2/imports/{import_id}/cancel", headers=AUTH)
    assert c.status_code == 200 and c.json()["status"] == "cancelled"
    assert uploads_left(env) == [] and issue_states(env) == []


def test_only_a_previewed_import_can_be_confirmed_or_cancelled(env: Env) -> None:
    done = env.import_and_get(SARIF)
    for action in ("confirm", "cancel"):
        r = env.client.post(f"/v2/imports/{done['id']}/{action}", headers=AUTH)
        assert r.status_code == 409, action


# --- refusing what cannot be trusted ----------------------------------------------------------


def test_a_truncated_file_fails_and_closes_nothing(env: Env) -> None:
    """The case the whole design guards: a file cut off halfway must not read as "most findings
    are fixed"."""
    env.import_and_get(SARIF)
    before = issue_states(env)
    cut = env.import_and_get(SARIF[: len(SARIF) // 2], filename="cut.sarif", parser="sarif")
    assert cut["status"] == "failed" and "valid JSON" in cut["error"]
    assert cut["counts"] is None
    assert issue_states(env) == before and count(env, Scan) == 1  # nothing closed, nothing added
    assert uploads_left(env) == []


def test_an_inventory_file_never_closes_anything_even_when_asked_to(env: Env) -> None:
    first = env.import_and_get(SARIF)
    sbom = env.import_and_get(SBOM, test_id=first["test_id"], close_missing="true")
    assert sbom["status"] == "applied" and sbom["close_missing"] is False  # what actually happened
    assert any("close_missing was ignored" in w for w in sbom["warnings"])
    assert sbom["counts"]["closed"] == 0
    assert "fixed" not in issue_states(env)


def test_a_file_in_a_format_nothing_recognises_is_refused_with_the_candidates(env: Env) -> None:
    r = env.post(b'{"hello": "world"}', filename="x.json")
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "pass `parser`" in detail["message"] and detail["detected"] == []
    assert sorted(detail["available"]) == sorted(PARSERS)
    assert {"sarif", "cyclonedx", "spdx", "osv", "zap", "nuclei"} <= set(PARSERS)
    assert uploads_left(env) == [] and count(env, ImportRecord) == 0


def test_naming_the_parser_skips_detection(env: Env) -> None:
    r = env.post(b'{"results": []}', parser="osv")
    assert r.status_code == 202 and r.json()["confidence"] is None


def test_an_unknown_parser_an_empty_file_and_bad_options_are_refused(env: Env) -> None:
    assert env.post(SARIF, parser="no-such-parser").status_code == 422
    assert env.post(b"").status_code == 422
    assert env.post(SARIF, scope="galaxy").status_code == 422
    assert env.post(SARIF, source="connector").status_code == 422
    assert env.post(SARIF, engagement_type="pentest").status_code == 422
    assert uploads_left(env) == [] and count(env, ImportRecord) == 0


def test_an_oversized_upload_is_refused_mid_stream_and_leaves_no_file(env: Env) -> None:
    tight = Settings(**{**env.settings.__dict__, "max_upload_bytes": 1000})
    app = create_app(AppState(tight, env.sessions, lambda *_: None, FakeSubscriber()))
    r = TestClient(app).post(
        "/v2/ingest", data={"project": env.asset_id}, files={"file": ("big", SARIF)}, headers=AUTH
    )
    assert r.status_code == 413
    d = tight.ingest_dir
    assert not d.exists() or list(d.iterdir()) == []


def test_the_clients_filename_is_never_used_as_a_path(env: Env) -> None:
    r = env.post(SARIF, filename="../../../etc/passwd")
    assert r.status_code == 202
    env.drain()
    assert env.get(r.json()["import_id"])["file_name"] == "passwd"  # a basename, for display only
    assert not (env.settings.workdir.parent / "etc").exists()


def test_a_queue_outage_fails_the_import_cleanly(env: Env, tmp_path: Path) -> None:
    def broken(*_: Any) -> None:
        raise ConnectionError("broker down")

    app = create_app(
        AppState(
            env.settings, env.sessions, lambda *_: None, FakeSubscriber(), enqueue_import=broken
        )
    )
    r = TestClient(app).post(
        "/v2/ingest", data={"project": env.asset_id}, files={"file": ("r", SARIF)}, headers=AUTH
    )
    assert r.status_code == 503
    with env.sessions() as s:
        rec = s.scalars(select(ImportRecord)).one()
        assert rec.status == "failed" and "queue" in (rec.error or "") and rec.upload_path is None
    assert uploads_left(env) == []


# --- where an import goes ----------------------------------------------------------------------


def test_an_assessment_engagement_needs_a_name_and_gets_its_own_tests(env: Env) -> None:
    assert env.post(SARIF, engagement_type="assessment").status_code == 422
    v = env.import_and_get(
        SARIF, engagement_type="assessment", engagement_name="Q3 pentest", test="Nessus export"
    )
    with env.sessions() as s:
        eng = repo.get_engagement(s, v["engagement_id"], DEFAULT_ORG_ID)
        test = repo.get_engagement_test(s, v["test_id"], DEFAULT_ORG_ID)
        assert eng is not None and (eng.name, eng.engagement_type) == ("Q3 pentest", "assessment")
        assert test is not None and test.name == "Nessus export"


def test_two_named_tests_in_one_engagement_do_not_close_each_others_findings(env: Env) -> None:
    a = env.import_and_get(SARIF, test="tool A")
    b = env.import_and_get(
        sarif_without_last_result(), test="tool B", engagement=a["engagement_id"]
    )
    assert a["engagement_id"] == b["engagement_id"] and a["test_id"] != b["test_id"]
    assert b["counts"]["closed"] == 0 and "fixed" not in issue_states(env)


# --- revert ----------------------------------------------------------------------------------


def test_the_latest_import_can_be_reverted_and_an_older_one_cannot(env: Env) -> None:
    first = env.import_and_get(SARIF)
    second = env.import_and_get(sarif_without_last_result())
    assert env.client.post(f"/v2/imports/{first['id']}/revert", headers=AUTH).status_code == 409
    r = env.client.post(f"/v2/imports/{second['id']}/revert", headers=AUTH)
    assert r.status_code == 200 and r.json()["status"] == "reverted" and r.json()["restored"] >= 1
    assert env.get(second["id"])["status"] == "reverted"
    assert "fixed" not in issue_states(env)  # the closed issue is back
    assert env.client.post(f"/v2/imports/{second['id']}/revert", headers=AUTH).status_code == 409


# --- who may do it ---------------------------------------------------------------------------


def _scoped(env: Env, *scopes: str) -> dict[str, str]:
    with env.sessions() as s:
        _, raw = repo.create_api_token(s, org_id=DEFAULT_ORG_ID, name="t", scopes=list(scopes))
    return {"Authorization": f"Bearer {raw}"}


def test_importing_has_its_own_permission_separate_from_scanning(env: Env) -> None:
    files = {"file": ("r.sarif", SARIF)}
    data = {"project": env.asset_id}
    anon = env.client.post("/v2/ingest", data=data, files=files)
    assert anon.status_code == 401
    for scopes in (("scans:write", "scans:read"), ("ingest:read",)):
        r = env.client.post("/v2/ingest", data=data, files=files, headers=_scoped(env, *scopes))
        assert r.status_code == 403, scopes
    ok = env.client.post("/v2/ingest", data=data, files=files, headers=_scoped(env, "ingest:write"))
    assert ok.status_code == 202


def test_reading_an_import_needs_the_read_scope(env: Env) -> None:
    import_id = env.post(SARIF).json()["import_id"]
    url = f"/v2/imports/{import_id}"
    assert env.client.get(url, headers=_scoped(env, "ingest:write")).status_code == 403
    assert env.client.get(url, headers=_scoped(env, "ingest:read")).status_code == 200


# --- tenancy at the HTTP layer -----------------------------------------------------------------

ORG_B = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


def test_another_org_cannot_read_act_on_or_import_into_this_orgs_resources(env: Env) -> None:
    view = env.import_and_get(SARIF)
    iid, tid = view["id"], view["test_id"]
    c = env.client
    assert c.get(f"/v2/imports/{iid}", headers=ORG_B).status_code == 404
    assert c.get(f"/v2/tests/{tid}/imports", headers=ORG_B).status_code == 404
    for action in ("confirm", "cancel", "revert"):
        assert c.post(f"/v2/imports/{iid}/{action}", headers=ORG_B).status_code == 404, action
    files = {"file": ("r.sarif", SARIF)}
    # B cannot import into A's project, nor into A's Test by its id.
    assert (
        c.post("/v2/ingest", data={"project": env.asset_id}, files=files, headers=ORG_B).status_code
        == 404
    )
    assert (
        c.post("/v2/ingest", data={"test_id": tid}, files=files, headers=ORG_B).status_code == 404
    )
    # A's data is untouched.
    assert env.get(iid)["status"] == "applied" and count(env, ImportRecord) == 1


def test_an_engagement_must_belong_to_the_project_it_is_given_with(env: Env) -> None:
    view = env.import_and_get(SARIF)
    r = env.post(SARIF, engagement=view["engagement_id"], project=env.other_asset_id)
    assert r.status_code == 404  # right engagement id, wrong project (and wrong org)


def test_malformed_ids_are_not_found_not_errors(env: Env) -> None:
    for path in ("/v2/imports/not-a-uuid", "/v2/tests/not-a-uuid/imports"):
        assert env.client.get(path, headers=AUTH).status_code == 404
    assert env.post(SARIF, project="not-a-uuid").status_code == 404


# --- discoverability -----------------------------------------------------------------------------


def test_the_available_parsers_are_listed(env: Env) -> None:
    r = env.client.get("/v2/parsers", headers=AUTH)
    assert r.status_code == 200
    by_name = {p["name"]: p for p in r.json()}
    assert sorted(by_name) == sorted(PARSERS)
    assert by_name["cyclonedx"]["formats"] == ["json", "xml"]
    assert by_name["zap"]["formats"] == ["json", "xml"] and by_name["zap"]["categories"] == ["dast"]
    assert by_name["nuclei"]["formats"] == ["json", "jsonl"]


def test_the_endpoints_are_in_the_published_api_description(env: Env) -> None:
    paths = env.client.get("/openapi.json").json()["paths"]
    for p in (
        "/v2/ingest",
        "/v2/imports/{import_id}",
        "/v2/imports/{import_id}/confirm",
        "/v2/imports/{import_id}/revert",
        "/v2/tests/{test_id}/imports",
        "/v2/parsers",
    ):
        assert p in paths, p


def test_findings_of_an_import_are_stored_against_its_scan(env: Env) -> None:
    view = env.import_and_get(SARIF)
    with env.sessions() as s:
        rec = repo.get_import_record(s, view["id"], DEFAULT_ORG_ID)
        assert rec is not None and rec.scan_id is not None
        n = s.scalar(
            select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == rec.scan_id)
        )
        assert n == 3


def test_secrets_in_an_uploaded_report_never_reach_the_database(env: Env) -> None:
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETVALUE9"
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "gitleaks", "rules": [{"id": "aws"}]}},
                "results": [
                    {
                        "ruleId": "aws",
                        "level": "error",
                        "message": {"text": f"Detected a secret: '{secret}'"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/.env"},
                                    "region": {
                                        "startLine": 2,
                                        "snippet": {"text": f"K='{secret}'"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    view = env.import_and_get(json.dumps(doc).encode(), filename="secrets.sarif")
    assert view["status"] == "applied" and view["counts"]["new"] == 1
    with env.sessions() as s:
        stored = json.dumps([r.data for r in s.scalars(select(FindingRow))])
        titles = [i.title for i in s.scalars(select(IssueRow))]
    assert "SECRETVALUE" not in stored and all("SECRETVALUE" not in t for t in titles)


def test_a_projects_tests_are_listed_with_their_latest_import(env: Env) -> None:
    empty = env.client.get(f"/v2/projects/{env.asset_id}/tests", headers=AUTH)
    assert empty.status_code == 200 and empty.json() == []
    first = env.import_and_get(SARIF)
    env.import_and_get(sarif_without_last_result())
    (t,) = env.client.get(f"/v2/projects/{env.asset_id}/tests", headers=AUTH).json()
    assert (t["id"], t["name"], t["parser"]) == (first["test_id"], "SARIF 2.1.0", "sarif")
    assert t["engagement_type"] == "import" and t["engagement_name"].endswith("imports")
    assert t["last_import"]["counts"]["closed"] == 1  # the second import is the current snapshot


def test_another_orgs_project_tests_are_not_listed(env: Env) -> None:
    env.import_and_get(SARIF)
    assert env.client.get(f"/v2/projects/{env.asset_id}/tests", headers=ORG_B).status_code == 404
    assert env.client.get("/v2/projects/not-a-uuid/tests", headers=AUTH).status_code == 404


def test_an_import_is_not_listed_as_a_recent_scan_but_its_scan_page_still_opens(env: Env) -> None:
    """Imports are stored as scans (ADR-0040) but are files someone uploaded, not scans someone ran."""
    view = env.import_and_get(SARIF)
    assert env.client.get("/scans", headers=AUTH).json() == []
    with env.sessions() as s:
        rec = repo.get_import_record(s, view["id"], DEFAULT_ORG_ID)
        scan_id = rec.scan_id  # type: ignore[union-attr]
    r = env.client.get(f"/scans/{scan_id}", headers=AUTH)
    assert r.status_code == 200 and r.json()["status"] == "completed"
    findings = env.client.get(f"/scans/{scan_id}/findings", headers=AUTH)
    assert findings.status_code == 200 and findings.json()["total"] == 3


def _table(env: Env) -> list[dict[str, Any]]:
    r = env.client.get(f"/assets/{env.asset_id}/issues", headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()["items"]  # type: ignore[no-any-return]


def test_the_projects_issues_table_lists_imported_issues_once_each(env: Env) -> None:
    """Week 74 (journey J6): the table listed only the latest scan's occurrences, so an imported
    report's Issues were missing from the screen the import links to -- and a project with only
    imports showed none at all."""
    env.import_and_get(SARIF)
    rows = _table(env)
    assert len(rows) == 3 and len({r["issue"]["id"] for r in rows}) == 3

    # The same report into a second Test: the same three Issues, still one row each.
    env.import_and_get(SARIF, test="Second pass")
    rows = _table(env)
    assert len(rows) == 3 and len({r["issue"]["id"] for r in rows}) == 3

    # A scan of the project adds its own Issue; the imported ones stay listed beside it.
    with env.sessions() as s:
        scan = repo.create_scan(s, source_type="git", source_ref="https://example.com/a/b",
                                source_label="a/b", tools=["semgrep"], org_id=DEFAULT_ORG_ID)  # fmt: skip
        f = Finding("scan:1", "Found by the scan", "d", Location("app.py", 9, 9, "eval(x)"),
                    Taxonomy(Category.SAST, cwe=("CWE-95",)), fingerprint="scan-only-fp")  # fmt: skip
        sync = repo.sync_issues_for_scan(s, scan.id, [f])
        repo.add_findings(s, scan.id, [f], sync.updates)
        repo.finish_scan(s, scan.id, "completed")
    rows = _table(env)
    assert len(rows) == 4 and "Found by the scan" in {r["title"] for r in rows}
    scan_row = next(r for r in rows if r["title"] == "Found by the scan")
    assert scan_row["scan_id"] == scan.id  # each row says which snapshot it came from
