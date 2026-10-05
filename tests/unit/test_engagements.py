"""Assessment engagements (Week 64, plan §43.1, §55.2): scope, people, a lifecycle, an OWASP
checklist, findings from every upload into the engagement (with what else reports them), tests, and
the report written on closing -- escaped, and frozen at that moment."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from core.engagements import checklists, report
from core.persistence.models import AuditEntry, IssueRow, OutboxEvent
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    SARIF,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_manual_findings import finding_body
from tests.unit.test_risk_acceptance import token

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


def create(env: Env, **over: Any) -> dict[str, Any]:
    body = {
        "name": "Q3 external pentest",
        "scope_targets": ["api.acme.example"],
        "scope_routes": ["/v2/"],
        "out_of_scope": "Admin panel, staging",
        "lead": "Priya N.",
        "testers": ["Arjun K.", "Meera S."],
        "starts_at": "2026-09-20T00:00:00Z",
        "ends_at": "2026-10-02T00:00:00Z",
        "checklist": "wstg-4.2",
        **over,
    }
    r = env.client.post(f"/v2/projects/{env.asset_id}/engagements", json=body, headers=AUTH)
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def detail(env: Env, eid: str, headers: Any = AUTH) -> dict[str, Any]:
    r = env.client.get(f"/v2/engagements/{eid}", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def patch(env: Env, eid: str, **body: Any) -> Any:
    return env.client.patch(f"/v2/engagements/{eid}", json=body, headers=AUTH)


def manual(env: Env, eid: str, **over: Any) -> dict[str, Any]:
    r = env.client.post(
        f"/v2/projects/{env.asset_id}/manual-findings",
        json=finding_body(engagement_id=eid, **over), headers=AUTH,
    )  # fmt: skip
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


# --- the checklists ---------------------------------------------------------------------------------


def test_the_owasp_checklists_ship_complete_with_their_levels() -> None:
    c = checklists.catalogue()
    assert {k: len(v.items) for k, v in c.items()} == {
        "wstg-4.2": 114, "asvs-4.0.3-l1": 128, "asvs-4.0.3-l2": 259, "asvs-4.0.3-l3": 278,
    }  # fmt: skip
    wstg = c["wstg-4.2"]
    assert wstg.items[1].id == "WSTG-INFO-02" and wstg.items[1].title == "Fingerprint Web Server"
    assert all(i.level == 1 for i in c["asvs-4.0.3-l1"].items)
    assert {i.id for i in c["asvs-4.0.3-l1"].items} < {i.id for i in c["asvs-4.0.3-l2"].items}
    assert len({i.id for i in c["asvs-4.0.3-l3"].items}) == 278  # ids are unique


# --- creating and editing ---------------------------------------------------------------------------


def test_create_an_engagement_with_scope_people_and_a_checklist(env: Env) -> None:
    e = create(env)
    assert e["status"] == "planned" and e["engagement_type"] == "pentest"
    assert e["scope_targets"] == ["api.acme.example"] and e["testers"] == ["Arjun K.", "Meera S."]
    assert e["checklist"]["total"] == 114 and e["checklist"]["done"] == 0
    assert e["checklist"]["attribution"].startswith("OWASP Foundation")
    listed = env.client.get(f"/v2/projects/{env.asset_id}/engagements", headers=AUTH).json()
    assert [x["id"] for x in listed] == [e["id"]]  # the standing ci/import ones are not listed
    with env.sessions() as s:
        a = s.scalars(select(AuditEntry).where(AuditEntry.action == "engagement.created")).one()
        assert a.target == f"engagement:{e['id']}"


@pytest.mark.parametrize(
    ("over", "field"),
    [
        ({"name": "  "}, "name"),
        ({"checklist": "iso-27001"}, "checklist"),
        ({"ends_at": "2026-09-01T00:00:00Z"}, "ends_at"),
        ({"engagement_type": "ci"}, "engagement_type"),
        ({"status": "closed"}, "status"),
        ({"testers": ["x" * 301]}, "testers"),
    ],
)
def test_bad_input_names_the_field(env: Env, over: dict[str, Any], field: str) -> None:
    body = {"name": "Pentest", **over}
    r = env.client.post(f"/v2/projects/{env.asset_id}/engagements", json=body, headers=AUTH)
    assert r.status_code == 422 and r.json()["detail"]["field"] == field, r.text


def test_the_lifecycle_moves_one_step_at_a_time(env: Env) -> None:
    eid = create(env)["id"]
    assert patch(env, eid, status="reporting").status_code == 422  # planned -> reporting: no
    assert patch(env, eid, status="in_progress").json()["status"] == "in_progress"
    assert patch(env, eid, status="reporting").json()["status"] == "reporting"
    assert patch(env, eid, status="in_progress").json()["status"] == "in_progress"
    bad = patch(env, eid, status="closed")
    assert bad.status_code == 422 and "Close it with" in bad.json()["detail"]["message"]
    assert patch(env, eid, lead="Rahul M.", testers=["A", "A", " B "]).json()["testers"] == [
        "A",
        "B",
    ]
    with env.sessions() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry).order_by(AuditEntry.seq))]
        assert actions.count("engagement.status") == 3 and "engagement.updated" in actions


def test_another_org_sees_nothing(env: Env) -> None:
    eid = create(env)["id"]
    assert env.client.get(f"/v2/engagements/{eid}", headers=OTHER).status_code == 404
    assert patch(env, eid).status_code == 200
    assert env.client.patch(f"/v2/engagements/{eid}", json={"lead": "x"},
                            headers=OTHER).status_code == 404  # fmt: skip
    assert env.client.get(f"/v2/projects/{env.asset_id}/engagements",
                          headers=OTHER).status_code == 404  # fmt: skip
    # the standing engagements are not assessments
    with env.sessions() as s:
        from core.persistence import repo
        from core.tenancy import DEFAULT_ORG_ID

        ci = repo.get_or_create_ci_engagement(s, asset_id=env.asset_id, org_id=DEFAULT_ORG_ID)
    assert env.client.get(f"/v2/engagements/{ci.id}", headers=AUTH).status_code == 404


# --- the checklist ----------------------------------------------------------------------------------


def test_checklist_results_count_toward_done_and_are_audited(env: Env) -> None:
    eid = create(env)["id"]
    url = f"/v2/engagements/{eid}/checklist"
    for item, status in (("WSTG-INFO-01", "pass"), ("WSTG-INFO-02", "fail"),
                         ("WSTG-INFO-03", "not_applicable"), ("WSTG-INFO-04", "in_progress")):  # fmt: skip
        r = env.client.put(f"{url}/{item}", json={"status": status, "note": "seen"}, headers=AUTH)
        assert r.status_code == 200, r.text
    summary = r.json()
    assert (summary["done"], summary["pass"], summary["fail"], summary["in_progress"]) == (
        3,
        1,
        1,
        1,
    )
    full = env.client.get(url, headers=AUTH).json()
    first = full["items"][0]
    assert (first["id"], first["status"], first["note"]) == ("WSTG-INFO-01", "pass", "seen")
    assert full["items"][10]["status"] is None
    cleared = env.client.put(f"{url}/WSTG-INFO-01", json={"status": None}, headers=AUTH).json()
    assert cleared["done"] == 2
    assert env.client.put(f"{url}/V2.1.1", json={"status": "pass"}, headers=AUTH).status_code == 422
    assert env.client.put(f"{url}/WSTG-INFO-05", json={"status": "great"},
                          headers=AUTH).status_code == 422  # fmt: skip
    none = create(env, checklist=None)["id"]
    assert env.client.get(f"/v2/engagements/{none}/checklist", headers=AUTH).status_code == 404
    with env.sessions() as s:
        assert (
            len(
                s.scalars(
                    select(AuditEntry).where(AuditEntry.action == "engagement.checklist")
                ).all()
            )
            == 5
        )


# --- findings and tests -----------------------------------------------------------------------------


def test_findings_come_from_every_upload_into_the_engagement(env: Env) -> None:
    eid = create(env, status="in_progress")["id"]
    first = manual(env, eid)
    second = manual(env, eid, title="JWT accepted with alg none", route="/v2/auth", cwe="347")
    # a tool report imported into the same engagement, as its own Test
    imp = env.import_and_get(SARIF, engagement=eid, test="Burp Suite")
    assert imp["status"] == "applied", imp
    d = detail(env, eid)
    titles = [f["title"] for f in d["findings"]]
    # both manual findings, though each was its own upload (only the latest is a Test's snapshot)
    assert first["manual"]["title"] in titles and "JWT accepted with alg none" in titles
    assert len(titles) == 2 + imp["counts"]["new"]
    tests = {t["name"]: t for t in d["tests"]}
    assert tests["Manual review"]["findings"] == 2 and tests["Manual review"]["uploads"] == 2
    assert tests["Burp Suite"]["findings"] == imp["counts"]["new"]
    sev = [f["severity"] for f in d["findings"]]
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    assert sev == sorted(sev, key=lambda x: -order[x])
    assert second["manual"]["id"] in {f["manual_finding_id"] for f in d["findings"]}


def test_a_finding_another_source_reports_says_so(env: Env) -> None:
    a = create(env, status="in_progress")["id"]
    b = create(env, name="Second opinion", status="in_progress")["id"]
    env.import_and_get(SARIF, engagement=a, test="Burp Suite")
    env.import_and_get(SARIF, engagement=b, test="Nessus")
    found = detail(env, a)["findings"]
    assert len(found) == 3 and all(f["also_found_by"] == ["Nessus"] for f in found)
    assert all(f["also_found_by"] == ["Burp Suite"] for f in detail(env, b)["findings"])


# --- closing and the report -------------------------------------------------------------------------


def test_closing_writes_a_report_that_does_not_change_afterwards(env: Env) -> None:
    eid = create(env, status="in_progress")["id"]
    m = manual(env, eid)
    env.client.put(f"/v2/engagements/{eid}/checklist/WSTG-ATHZ-04",
                   json={"status": "fail", "note": "IDOR on orders"}, headers=AUTH)  # fmt: skip
    assert env.client.get(f"/v2/engagements/{eid}/report", headers=AUTH).status_code == 404
    r = env.client.post(f"/v2/engagements/{eid}/close", json={"summary": "One high."}, headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "closed" and r.json()["report_generated_at"]
    md = env.client.get(f"/v2/engagements/{eid}/report", headers=AUTH)
    assert md.headers["content-disposition"].startswith('attachment; filename="Q3-external-pentest')
    text = md.text
    assert "# Q3 external pentest" in text and "One high." in text
    assert "Priya N." in text and "**Out of scope:** Admin panel, staging" in text
    assert "Dates (UTC)" in text and "(UTC) for shared-token." in text
    assert "1 of 114 done (0 passed, 1 failed" in text and "IDOR on orders" in text
    assert "Steps to reproduce" in text and "Sign in as user A" in text
    assert "OWASP Foundation, CC BY-SA 4.0" in text
    html_r = env.client.get(f"/v2/engagements/{eid}/report?format=html", headers=AUTH)
    assert html_r.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in html_r.headers["content-security-policy"]
    assert "<script" not in html_r.text
    # frozen: fixing the issue later does not rewrite the delivered report
    with env.sessions() as s:
        issue = s.get(IssueRow, m["manual"]["issue_id"])
        assert issue is not None
        issue.title = "Renamed afterwards"
        s.commit()
    assert "Renamed afterwards" not in env.client.get(f"/v2/engagements/{eid}/report",
                                                       headers=AUTH).text  # fmt: skip
    # closed is read-only until reopened
    assert patch(env, eid, lead="x").status_code == 422
    assert env.client.put(f"/v2/engagements/{eid}/checklist/WSTG-INFO-01", json={"status": "pass"},
                          headers=AUTH).status_code == 422  # fmt: skip
    assert patch(env, eid, status="in_progress").json()["closed_at"] is None
    with env.sessions() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry))]
        assert "engagement.closed" in actions and "engagement.reopened" in actions
        events = [e.event_type for e in s.scalars(select(OutboxEvent))]
        assert "engagement.closed" in events


def test_only_an_engagement_under_way_can_close(env: Env) -> None:
    eid = create(env)["id"]  # planned
    r = env.client.post(f"/v2/engagements/{eid}/close", json={}, headers=AUTH)
    assert r.status_code == 422 and r.json()["detail"]["field"] == "status"


HOSTILE = "<img src=x onerror=alert(1)> [click](javascript:alert(1)) **bold** `code`"


def test_the_report_escapes_what_came_from_outside() -> None:
    r = {
        "format": 1, "name": HOSTILE, "type": "pentest", "project": "p", "starts_at": None,
        "ends_at": None, "closed_at": "2026-10-02T00:00:00", "generated_at": "2026-10-02T00:00:00",
        "generated_by": "x", "summary": HOSTILE,
        "scope": {"targets": [HOSTILE], "routes": [], "out_of_scope": HOSTILE},
        "lead": HOSTILE, "testers": [HOSTILE],
        "counts": {"total": 1, "by_severity": {"HIGH": 1}, "open": 1, "fixed": 0, "retest": {}},
        "checklist": None,
        "findings": [{
            "n": 1, "issue_id": "i", "title": HOSTILE, "severity": "HIGH", "state": "open",
            "retest_status": None, "test": HOSTILE, "location": HOSTILE, "cwe": None,
            "cvss_vector": None, "cvss_score": None, "steps": HOSTILE + "\nline two",
            "impact": "", "recommendation": "", "references": [HOSTILE], "also_found_by": [HOSTILE],
        }],
        "tests": [{"name": HOSTILE, "parser": HOSTILE, "findings": 1, "uploads": 1}],
    }  # fmt: skip
    page = report.html_page(r)
    assert "<img" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "<br>line two" in page and "<script" not in page
    md = report.markdown(r)
    assert "<img" not in md and "&lt;img" in md
    assert "[click](javascript" not in md and "\\[click\\](javascript" in md  # no link forms
    assert "\\*\\*bold\\*\\* \\`code\\`" in md  # shown as typed, not as formatting


def test_markdown_escapes_only_what_markdown_acts_on() -> None:
    assert (
        report._md("api.acme.example, payments-api (v2)") == "api.acme.example, payments-api (v2)"
    )
    assert report._md("# heading") == "\\# heading"
    assert report._md("- item") == "\\- item"
    assert report._md("1. first") == "1\\. first"
    assert report._md("a_b *c* [d]") == "a\\_b \\*c\\* \\[d\\]"
    assert report._md("<b>x</b> & y") == "&lt;b&gt;x&lt;/b&gt; &amp; y"
    block = report._md_block("1. Sign in\n2. Ask for #42\n- done")
    assert block == "1\\. Sign in\n2\\. Ask for #42\n\\- done"


def test_a_named_token_shows_by_name_on_the_engagement(env: Env) -> None:
    alice = token(env, "Alice")
    r = env.client.post(f"/v2/projects/{env.asset_id}/engagements", json={"name": "Audit"},
                        headers=alice)  # fmt: skip
    body = r.json()
    assert body["names"][body["created_by"]] == "Alice"


def test_the_report_names_who_closed_it(env: Env) -> None:
    alice = token(env, "Alice")
    eid = create(env, status="in_progress")["id"]
    assert (
        env.client.post(f"/v2/engagements/{eid}/close", json={}, headers=alice).status_code == 200
    )
    text = env.client.get(f"/v2/engagements/{eid}/report", headers=AUTH).text
    assert "(UTC) for Alice." in text
