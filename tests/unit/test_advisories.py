"""The advisory engine (plan §46.2, §55.5): OSV records read and matched the way osv-scanner matches
them, kept as impacts that follow the inventory, the morning list and one advisory's impact view,
Issues (and tickets) in one click that close when an SBOM no longer has the vulnerable version,
the feeds, and nothing of another organization. The records in tests/fixtures/osv are real."""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from core import inventory
from core.advisories import feeds, store
from core.advisories.osv import Advisory, affects, fixed_in, parse, parse_time
from core.dispatch import drain
from core.notify import service as notify
from core.persistence import repo
from core.persistence.models import (
    AdvisoryImpact,
    AdvisoryState,
    FeedState,
    IssueRow,
    KevEntry,
    OutboxEvent,
)
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_pipeline import make_scan
from tests.unit.test_risk_acceptance import token
from tests.unit.test_tickets import Recorder, configure, creds
from tests.unit.test_tickets import rec as rec  # noqa: F401  (the fixture)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "osv"
OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core"


def record(name: str) -> Advisory:
    a = parse((FIXTURES / f"{name}.json").read_bytes())
    assert a is not None
    return a


def load_all(s: Session) -> None:
    store.upsert(s, [record(p.stem) for p in sorted(FIXTURES.glob("*.json"))], source="test")


def sbom(s: Session, asset_id: str, *purls: str, reachable: bool | None = None) -> None:
    sid = make_scan(s, [], "x", asset_label=None)
    scan = repo.get_scan(s, sid)
    assert scan is not None
    scan.asset_id = asset_id
    s.commit()
    inventory.record(
        s, org_id=DEFAULT_ORG_ID, asset_id=asset_id, scan_id=sid, source="scan",
        packages=[{"purl": p, "path": "pom.xml", "reachable": reachable} for p in purls],
    )  # fmt: skip


def project(s: Session, label: str) -> str:
    return repo.get_or_create_asset(
        s, source_type="git", source_label=label, org_id=DEFAULT_ORG_ID
    ).id


# ------------------------------------------------------------------ reading OSV


def test_osv_records_are_read_and_evaluated_as_osv_scanner_does() -> None:
    log4shell = record("GHSA-jfh8-c2jp-5v3q")
    assert log4shell.vuln_key == "CVE-2021-44228" and log4shell.cvss == 10.0
    core = [a for a in log4shell.affected if a.name == "org.apache.logging.log4j:log4j-core"]
    assert len(core) == 3  # one entry per range
    hit = {v: [affects(a, v) for a in core] for v in ("2.14.1", "2.12.1", "2.0-beta9", "2.17.1", "1.2")}  # fmt: skip
    assert {v: any(r) for v, r in hit.items()} == {
        "2.14.1": True, "2.12.1": True, "2.0-beta9": True, "2.17.1": False, "1.2": False
    }  # fmt: skip
    assert {fixed_in(a, "2.14.1") for a in core} == {None, "2.15.0"}

    # A GIT range means the explicit version list alone (what osv-scanner does): 1.7.1 is listed,
    # 1.7.1.post3 is inside the ECOSYSTEM range but not listed. GitHub's record has no GIT range.
    pysec, ghsa = record("PYSEC-2018-19"), record("GHSA-232r-66cg-79px")
    assert pysec.vuln_key == ghsa.vuln_key == "CVE-2018-7750"
    assert affects(pysec.affected[0], "1.7.1") is True
    assert affects(pysec.affected[0], "1.7.1.post3") is False
    assert any(affects(a, "1.7.1.post3") for a in ghsa.affected)

    lodash = record("GHSA-35jh-r3h4-6jhm")
    assert lodash.vuln_key == "CVE-2021-23337"  # the lowest of its two CVE aliases
    entry = next(a for a in lodash.affected if a.name == "lodash")
    assert (affects(entry, "4.17.20"), affects(entry, "4.17.21")) == (True, False)
    assert fixed_in(entry, "4.17.20") == "4.17.21"

    mal = record("MAL-2021-1")
    assert mal.malicious and affects(mal.affected[0], "99.0.0") is True
    assert record("GHSA-22c5-cpvr-cfvq").withdrawn is not None

    go = record("GO-2021-0238")
    x_net = go.affected[0]
    assert affects(x_net, "v0.0.0-20210428140749-89ef3d95e781") is True  # a pseudo-version
    assert affects(x_net, "v0.0.0-20210520170846-37e1c6afe023") is False  # the fix

    assert parse_time("2026-06-08T11:15:07.478696416Z") == datetime(2026, 6, 8, 11, 15, 7, 478696, tzinfo=timezone.utc)  # fmt: skip
    assert parse(b"{}") is None and parse(b"not json") is None
    assert parse(json.dumps({"id": "X-1", "modified": "2024-01-01T00:00:00Z",
                             "affected": [{"package": {"ecosystem": "Debian", "name": "x"}}]})) is None  # fmt: skip


def test_records_are_written_only_when_they_change(env: Env) -> None:
    with env.sessions() as s:
        first = store.upsert(s, [record("GHSA-jfh8-c2jp-5v3q"), record("MAL-2021-1")], source="t")
        again = store.upsert(s, [record("GHSA-jfh8-c2jp-5v3q")], source="t")
        assert first.changed == {"GHSA-jfh8-c2jp-5v3q", "MAL-2021-1"} and again.changed == set()
        raw = json.loads((FIXTURES / "MAL-2021-1.json").read_text())
        raw["modified"] = "2030-01-01T00:00:00Z"
        raw["aliases"] = ["CVE-2030-0001"]
        third = store.upsert(s, [parse(json.dumps(raw))], source="t")  # type: ignore[list-item]
        assert third.changed == {"MAL-2021-1"} and third.vuln_keys == {"CVE-2030-0001"}


# ------------------------------------------------------------------ matching and the views


def seed(env: Env) -> dict[str, str]:
    with env.sessions() as s:
        load_all(s)
        ids = {
            "payments": env.asset_id,
            "billing": project(s, "acme/billing"),
            "legacy": project(s, "acme/legacy"),
            "frontend": project(s, "acme/frontend"),
            "undertow": project(s, "acme/undertow"),
        }
        sbom(s, ids["payments"], f"{LOG4J}@2.14.1", "pkg:npm/lodash@4.17.20", reachable=True)
        sbom(s, ids["billing"], f"{LOG4J}@2.17.1")
        sbom(s, ids["legacy"], "pkg:pypi/paramiko@1.7.1.post3")
        sbom(s, ids["frontend"], "pkg:npm/cxp-jquery@1.0.0", "pkg:npm/lodash@4.17.21")
        sbom(s, ids["undertow"], "pkg:maven/io.undertow/undertow-core@2.2.30.Final")
    return ids


def open_impacts(s: Session) -> set[tuple[str, str, str]]:
    return {
        (i.asset_id, i.vuln_key, ",".join(i.advisory_ids))
        for i in s.scalars(select(AdvisoryImpact).where(AdvisoryImpact.resolved_at.is_(None)))
    }


def test_matching_follows_the_inventory(env: Env) -> None:
    ids = seed(env)
    with env.sessions() as s:
        assert open_impacts(s) == {
            (ids["payments"], "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"),
            (ids["payments"], "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"),
            (ids["legacy"], "CVE-2018-7750", "GHSA-232r-66cg-79px"),  # PYSEC's GIT range: no
            (ids["frontend"], "MAL-2021-1", "MAL-2021-1"),
        }  # billing has 2.17.1; the undertow advisory was withdrawn
        log4j = s.scalars(select(AdvisoryImpact).where(AdvisoryImpact.vuln_key == "CVE-2021-44228")).one()  # fmt: skip
        assert log4j.fixed_version == "2.15.0" and log4j.certain
        states = {st.vuln_key: st.state for st in s.scalars(select(AdvisoryState))}
        assert states == dict.fromkeys(["CVE-2021-44228", "CVE-2021-23337", "CVE-2018-7750", "MAL-2021-1"], "new")  # fmt: skip
        events = [e.payload["vuln_key"] for e in s.scalars(select(OutboxEvent).where(OutboxEvent.event_type == "advisory.matched"))]  # fmt: skip
        assert sorted(events) == sorted(states)  # once each

        sbom(s, ids["payments"], f"{LOG4J}@2.17.1")  # upgraded, and lodash gone
        assert (ids["payments"], "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q") not in open_impacts(s)
        assert {k for _a, k, _i in open_impacts(s)} == {"CVE-2018-7750", "MAL-2021-1"}
        sbom(s, ids["payments"], f"{LOG4J}@2.14.1")  # back again: the same impact reopens
        row = s.scalars(select(AdvisoryImpact).where(AdvisoryImpact.vuln_key == "CVE-2021-44228")).one()  # fmt: skip
        assert row.resolved_at is None
        assert len([e for e in s.scalars(select(OutboxEvent).where(OutboxEvent.event_type == "advisory.matched"))]) == 4  # fmt: skip


def test_the_morning_list_and_the_impact_view(env: Env) -> None:
    ids = seed(env)
    with env.sessions() as s:
        s.add(KevEntry(cve="CVE-2021-44228", date_added="2021-12-10", due_date="2021-12-24",
                       name="Apache Log4j2 Remote Code Execution", ransomware="Known"))  # fmt: skip
        s.commit()
    rows = env.client.get("/v2/advisories", headers=AUTH).json()
    by = {r["vuln_key"]: r for r in rows}
    assert set(by) == {"CVE-2021-44228", "CVE-2021-23337", "CVE-2018-7750", "MAL-2021-1"}
    assert by["CVE-2021-44228"]["kev"] and by["CVE-2021-44228"]["severity"] == "CRITICAL"
    assert by["CVE-2021-44228"]["imported_by_app"] == 1 and by["CVE-2021-44228"]["projects"] == 1
    assert by["MAL-2021-1"]["malicious"] and by["MAL-2021-1"]["severity"] == "CRITICAL"
    assert [r["vuln_key"] for r in env.client.get("/v2/advisories", params={"kev": "true"}, headers=AUTH).json()] == ["CVE-2021-44228"]  # fmt: skip
    assert [r["vuln_key"] for r in env.client.get("/v2/advisories", params={"q": "paramiko"}, headers=AUTH).json()] == ["CVE-2018-7750"]  # fmt: skip

    view = env.client.get("/v2/advisories/CVE-2021-44228", headers=AUTH).json()
    assert view["ids"] == ["GHSA-jfh8-c2jp-5v3q"] and view["kev"]["due_date"] == "2021-12-24"
    [use] = view["uses"]
    assert (use["project_id"], use["version"], use["fixed_version"], use["reachable"]) == (
        ids["payments"], "2.14.1", "2.15.0", True
    )  # fmt: skip
    assert view["summary_counts"]["with_fix"] == 1 and view["state"] == "new"
    found = env.client.get("/v2/components", params={"purl": LOG4J}, headers=AUTH).json()
    assert {v["version"]: v["advisories"] for v in found["versions"]} == {
        "2.14.1": ["CVE-2021-44228"], "2.17.1": []
    }  # fmt: skip
    assert env.client.get("/v2/advisories/CVE-1999-0001", headers=AUTH).status_code == 404
    assert env.client.get("/v2/advisories/..%2F..", headers=AUTH).status_code == 404
    assert env.client.get("/v2/advisories", headers=OTHER).json() == []
    assert env.client.get("/v2/advisories/CVE-2021-44228", headers=OTHER).status_code == 404


# ------------------------------------------------------------------ Issues in one click


def test_issues_in_one_click_close_when_the_sbom_moves_on(
    env: Env, rec: Recorder
) -> None:  # noqa: F811
    ids = seed(env)
    priya = token(env, "Priya N.")
    creds(env)
    assert configure(env).status_code == 200  # payments files to Jira
    r = env.client.put(f"/v2/projects/{ids['payments']}/owner", json={"owner": "@priyan"}, headers=priya)  # fmt: skip
    assert r.status_code == 200 and r.json()["owner_name"] == "Priya N."
    bad = env.client.put(f"/v2/projects/{ids['payments']}/owner", json={"owner": "@nobody"}, headers=AUTH)  # fmt: skip
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "owner"

    out = env.client.post("/v2/advisories/CVE-2021-44228/issues", json={}, headers=AUTH)
    assert out.status_code == 200, out.text
    body = out.json()
    assert (body["projects"], body["issues"], body["tickets"]) == (1, 1, 1)
    [issue_id] = body["issue_ids"][ids["payments"]]
    with env.sessions() as s:
        issue = s.get(IssueRow, issue_id)
        assert issue is not None and issue.title.startswith(
            "org.apache.logging.log4j:log4j-core 2.14.1"
        )
        assert issue.assignee and issue.assignee.startswith("token:")  # the project's owner
        assert issue.group_id is not None
    assert len([c for c in rec.calls if c[0] == "POST"]) == 1  # one Jira ticket
    view = env.client.get("/v2/advisories/CVE-2021-44228", headers=AUTH).json()
    assert view["state"] == "issues" and view["uses"][0]["issues"][0]["id"] == issue_id
    again = env.client.post("/v2/advisories/CVE-2021-44228/issues", json={}, headers=AUTH).json()
    assert again["issues"] == 1 and again["issue_ids"][ids["payments"]] == [issue_id]  # no copy

    with env.sessions() as s:
        sbom(s, ids["payments"], f"{LOG4J}@2.17.1", reachable=True)  # the fix ships
        assert s.get(IssueRow, issue_id).state == "fixed"  # type: ignore[union-attr]
    view = env.client.get("/v2/advisories/CVE-2021-44228", headers=AUTH)
    assert view.json()["uses"] == [] and len(view.json()["no_longer_affected"]) == 1
    with env.sessions() as s:
        sbom(s, ids["payments"], f"{LOG4J}@2.14.1", reachable=True)  # and is rolled back
        assert s.get(IssueRow, issue_id).state != "fixed"  # type: ignore[union-attr]

    assert env.client.post("/v2/advisories/CVE-1999-0001/issues", json={}, headers=AUTH).status_code == 404  # fmt: skip
    assert env.client.post("/v2/advisories/CVE-2021-44228/issues", json={}, headers=OTHER).status_code == 404  # fmt: skip
    read_only = token(env, "Reader", ["scans:read"])
    assert env.client.post("/v2/advisories/CVE-2021-44228/issues", json={}, headers=read_only).status_code == 403  # fmt: skip


def test_owners_and_the_team_hear_of_a_new_advisory(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    sent: list[tuple[str, str]] = []
    import core.rules.notify as rules_notify

    monkeypatch.setattr(rules_notify, "send_rule_message", lambda s, org, text, kind="rules": sent.append((kind, text)) or ["Slack"])  # fmt: skip
    priya = token(env, "Priya N.")
    env.client.put(f"/v2/projects/{env.asset_id}/owner", json={"owner": "@priyan"}, headers=priya)
    seed(env)
    with env.sessions() as s:
        drain(s, DEFAULT_ORG_ID)
        owner = repo.get_asset(s, env.asset_id).owner  # type: ignore[union-attr]
        titles = [n.title for n in notify.inbox(s, DEFAULT_ORG_ID, owner)]  # type: ignore[arg-type]
    assert "New advisory: CVE-2021-44228 (Critical) affects 1 project" in titles
    assert any(k == "advisory" and "CVE-2021-44228" in t for k, t in sent)


# ------------------------------------------------------------------ the feeds


class Feed:
    """Fake HTTPS: OSV's index and records, KEV, NVD."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files, self.calls = files, []  # type: list[str]

    def __call__(self, url: str) -> Any:
        self.calls.append(url)
        for prefix, data in self.files.items():
            if url.startswith(prefix):
                return io.BytesIO(data)
        raise OSError(f"no route to {url}")


def test_osv_runs_full_then_incremental_and_failures_are_recorded(env: Env) -> None:
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-jfh8-c2jp-5v3q.json", (FIXTURES / "GHSA-jfh8-c2jp-5v3q.json").read_bytes())
    base = f"{feeds.OSV_BASE}/Maven"
    first = Feed({f"{base}/modified_id.csv": b"2026-10-06T03:45:03.518588347Z,GHSA-jfh8-c2jp-5v3q\n",
                  f"{base}/all.zip": buf.getvalue()})  # fmt: skip
    with env.sessions() as s:
        run = feeds.update_osv(s, "Maven", opener=first)
        assert (run.mode, run.seen, run.cursor) == ("full", 1, "2026-10-06T03:45:03.518588347Z")
        changed = json.loads((FIXTURES / "GHSA-jfh8-c2jp-5v3q.json").read_text())
        changed["modified"] = "2026-10-07T00:00:00Z"
        later = Feed({
            f"{base}/modified_id.csv": b"2026-10-07T00:00:00Z,GHSA-jfh8-c2jp-5v3q\n2026-10-06T03:45:03.518588347Z,OLD-1\n",
            f"{base}/GHSA-jfh8-c2jp-5v3q.json": json.dumps(changed).encode(),
        })  # fmt: skip
        run = feeds.update_osv(s, "Maven", opener=later)
        assert (run.mode, run.changed) == ("incremental", {"GHSA-jfh8-c2jp-5v3q"})
        assert not any("OLD-1" in c for c in later.calls)  # stopped at the cursor
        assert feeds.update_osv(s, "Maven", opener=later).mode == "unchanged"

        kev = {"vulnerabilities": [{"cveID": f"CVE-2021-{i:05d}", "dateAdded": "2021-11-03"} for i in range(150)]}  # fmt: skip
        nvd_pages = json.dumps({"totalResults": 1, "vulnerabilities": [{"cve": {
            "id": "CVE-2026-0001", "published": "2026-10-05T10:00:00.000",
            "lastModified": "2026-10-06T10:00:00.000",
            "descriptions": [{"lang": "en", "value": "A flaw."}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]})  # fmt: skip
        broken = Feed({feeds.KEV_URL: json.dumps(kev).encode(), feeds.NVD_URL: nvd_pages.encode()})
        result = feeds.update_all(s, opener=broken)
        assert set(result.errors) == {"osv:PyPI", "osv:npm", "osv:Go", "osv:Maven"}  # no route
        states = {f.source: f for f in s.scalars(select(FeedState))}
        assert states["kev"].records == 150 and states["kev"].last_error is None
        assert states["nvd"].records == 1 and "no route" in (states["osv:PyPI"].last_error or "")
        with pytest.raises(ValueError):
            store.load_kev(s, json.dumps({"vulnerabilities": []}).encode())  # never emptied
        assert s.scalar(select(KevEntry.cve).where(KevEntry.cve == "CVE-2021-00001")) is not None
    with pytest.raises(ValueError):
        feeds._open("https://evil.example/all.zip")
    with pytest.raises(ValueError):
        feeds._open("http://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip")
    status = env.client.get("/v2/advisory-feeds", headers=AUTH).json()
    assert status["kev_entries"] == 150 and status["advisories"] == 1


def test_an_advisory_issue_is_the_same_issue_osv_scanner_found(env: Env) -> None:
    """The same package, version and CVE from a scan's osv-scanner and from the advisory engine is
    one Issue, not two."""
    from core.adapters.osv_scanner import OsvScannerAdapter

    report = {"results": [{"source": {"path": "/target/pom.xml"}, "packages": [{
        "package": {"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1",
                    "ecosystem": "Maven"},
        "vulnerabilities": [{"id": "GHSA-jfh8-c2jp-5v3q", "summary": "Log4Shell",
                             "aliases": ["CVE-2021-44228"]}],
        "groups": [{"ids": ["GHSA-jfh8-c2jp-5v3q"], "aliases": ["CVE-2021-44228"],
                    "max_severity": "10.0"}],
    }]}]}  # fmt: skip
    found = OsvScannerAdapter().parse(json.dumps(report).encode())
    with env.sessions() as s:
        load_all(s)
        sc = repo.create_scan(s, source_type="git", source_ref="https://example.com/a/b",
                              source_label="a/b", tools=["osv-scanner"], org_id=DEFAULT_ORG_ID)  # fmt: skip
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        [scanned] = s.scalars(select(IssueRow).where(IssueRow.asset_id == sc.asset_id)).all()
        sbom(s, sc.asset_id, f"{LOG4J}@2.14.1")  # type: ignore[arg-type]
    out = env.client.post("/v2/advisories/CVE-2021-44228/issues", json={}, headers=AUTH).json()
    assert out["issue_ids"][sc.asset_id] == [scanned.id]
    with env.sessions() as s:
        assert len(s.scalars(select(IssueRow).where(IssueRow.asset_id == sc.asset_id)).all()) == 1
