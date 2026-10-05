"""Manual findings (Week 59, plan §43.2, ADR-0044): CVSS 4.0 scoring, the CWE picker, the route
picker, recording a finding through ingest, linking it to what automation already found, and
evidence attachments that are only ever downloaded.

CVSS expectations are FIRST's own: each vector below was scored on FIRST's official CVSS v4.0
calculator (first.org/cvss/calculator/cvsscalc40) on 2026-10-05, not by the library under test.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from sqlalchemy import select

from core.manual import attachments, cvss4, cwe
from core.manual.service import ManualFindingError, ManualFindingIn, validate
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Severity,
    TaintPathStep,
    Taxonomy,
)
from core.persistence import repo
from core.persistence.models import EvidenceAttachment, FindingRow, IssueRow, ManualFinding
from core.pipeline import _entrypoints
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import OTHER_ORG, Env, env  # noqa: F401  (env is the fixture)

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}

FIRST = {  # vector -> (score, rating) from FIRST's calculator
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": (9.3, "Critical"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N": (7.1, "High"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N": (5.3, "Medium"),
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": (1.0, "Low"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U": (8.1, "High"),
    "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N": (8.7, "High"),
    "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": (7.0, "High"),
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N": (6.3, "Medium"),
}
IDOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


@pytest.mark.parametrize(("vector", "expected"), FIRST.items())
def test_cvss4_scores_agree_with_firsts_calculator(
    vector: str, expected: tuple[float, str]
) -> None:
    s = cvss4.score(vector)
    assert (s.score, s.rating) == expected
    assert s.severity.value == expected[1].upper()


def test_cvss4_normalizes_order_and_refuses_incomplete_vectors() -> None:
    shuffled = "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"
    assert cvss4.score(shuffled).vector.startswith("CVSS:4.0/AV:N/AC:L")
    zero = cvss4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert (zero.score, zero.rating, zero.severity) == (0.0, "None", Severity.INFO)
    for bad in ("CVSS:4.0/AV:N/AC:L", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "x" * 400):
        with pytest.raises(cvss4.CvssError):
            cvss4.score(bad)


def test_the_cwe_picker_finds_by_number_and_by_words() -> None:
    assert cwe.search("89")[0] == ("CWE-89", cwe.name_of("CWE-89"))
    assert all("sql" in name.lower() for _, name in cwe.search("sql injection")[:3])
    assert cwe.search("CWE-99999")[0] == ("CWE-99999", "")  # real number, not in the extract
    assert cwe.normalize("cwe 79") == "CWE-79" and cwe.normalize("seventy") is None


def test_validation_names_the_field_that_is_wrong() -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        ({"title": "  "}, "title"),
        ({"cwe": "SQL"}, "cwe"),
        ({"cvss_vector": "CVSS:4.0/AV:N"}, "cvss_vector"),
        ({"cvss_vector": None, "severity": None}, "cvss_vector"),
        ({"route": "orders"}, "route"),
        ({"method": "FETCH"}, "method"),
        ({"location_kind": "file", "path": "/etc/passwd"}, "path"),
        ({"location_kind": "file", "path": "app/../../x"}, "path"),
        ({"references": ["javascript:alert(1)"]}, "references"),
        ({"location_kind": "elsewhere"}, "location_kind"),
    ]
    for override, field in cases:
        body = {"title": "IDOR", "cvss_vector": IDOR, "route": "/orders", **override}
        with pytest.raises(ManualFindingError) as caught:
            validate(ManualFindingIn(**body))
        assert caught.value.field == field, override


# --- over HTTP --------------------------------------------------------------------------------


def base(env: Env) -> str:
    return f"/v2/projects/{env.asset_id}"


def finding_body(**over: Any) -> dict[str, Any]:
    return {
        "title": "IDOR on GET /v2/orders/{id}",
        "cwe": "639",
        "cvss_vector": IDOR,
        "location_kind": "route",
        "method": "GET",
        "route": "/v2/orders/{id}",
        "steps": "1. Sign in as user A.\n2. Request user B's order id.",
        "impact": "Any customer can read any order.",
        "recommendation": "Check the order belongs to the caller.",
        "references": ["https://cwe.mitre.org/data/definitions/639.html"],
        **over,
    }


def record(env: Env, headers: Any = AUTH, **over: Any) -> Any:
    return env.client.post(
        f"{base(env)}/manual-findings", json=finding_body(**over), headers=headers
    )


def test_a_manual_finding_becomes_an_issue_through_ingest(env: Env) -> None:
    r = record(env)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["created"] is True
    m = body["manual"]
    assert (m["cvss_score"], m["severity"], m["cvss_vector"]) == (7.1, "HIGH", IDOR)
    assert m["cwe"] == "CWE-639" and m["route"] == "/v2/orders/{id}" and m["method"] == "GET"
    with env.sessions() as s:
        issue = s.get(IssueRow, body["issue_id"])
        assert issue is not None and issue.severity == "HIGH" and issue.category == "dast"
        row = s.scalars(select(FindingRow).where(FindingRow.issue_id == issue.id)).one()
        assert row.data["evidence"]["reported_by"] == ["manual"]
        assert "Steps to reproduce" in row.data["description"]
        assert row.data["scoring"]["native_severity"] == {"manual": "CVSS 4.0 7.1"}
    view = env.get(body["import_id"])  # an ordinary import record, so it can be undone
    assert view["status"] == "applied" and view["counts"]["new"] == 1 and view["parser"] == "manual"
    assert view["close_missing"] is False


def test_recording_the_same_finding_twice_is_one_issue(env: Env) -> None:
    first = record(env).json()
    again = record(env)
    assert again.status_code == 200 and again.json()["created"] is False
    assert again.json()["issue_id"] == first["issue_id"]
    with env.sessions() as s:
        assert len(list(s.scalars(select(ManualFinding)))) == 1


def test_two_findings_on_one_route_are_two_issues_and_neither_closes_the_other(env: Env) -> None:
    a = record(env).json()
    b = record(env, title="Mass assignment on order update", method="PUT", cwe="915").json()
    assert a["issue_id"] != b["issue_id"]
    with env.sessions() as s:
        assert {i.state for i in s.scalars(select(IssueRow))} == {"new"}


def test_a_file_finding_is_a_code_finding(env: Env) -> None:
    r = record(env, location_kind="file", path="app/orders.py", line=42, route=None, method=None)
    assert r.status_code == 201, r.text
    with env.sessions() as s:
        issue = s.get(IssueRow, r.json()["issue_id"])
        assert issue is not None and (issue.category, issue.path) == ("sast", "app/orders.py")


def test_a_field_error_comes_back_with_the_field(env: Env) -> None:
    r = record(env, cvss_vector="CVSS:4.0/AV:N")
    assert r.status_code == 422
    assert r.json()["detail"]["field"] == "cvss_vector"


def test_another_org_cannot_record_into_or_read_a_project(env: Env) -> None:
    mine = record(env).json()
    assert record(env, headers=OTHER).status_code == 404
    assert (
        env.client.get(f"/v2/manual-findings/{mine['manual']['id']}", headers=OTHER).status_code
        == 404
    )
    assert env.client.get(f"{base(env)}/manual-findings", headers=OTHER).status_code == 404


def test_cvss_and_cwe_endpoints(env: Env) -> None:
    r = env.client.post("/v2/cvss/v4", json={"vector": IDOR}, headers=AUTH)
    assert r.json() == {"vector": IDOR, "score": 7.1, "rating": "High", "severity": "HIGH"}
    assert env.client.post("/v2/cvss/v4", json={"vector": "nope"}, headers=AUTH).status_code == 422
    hits = env.client.get("/v2/cwe", params={"q": "639"}, headers=AUTH).json()
    assert hits[0]["id"] == "CWE-639"


# --- routes and what automation already knows ------------------------------------------------


def seed_scan(env: Env, *, cwe_id: str = "CWE-639", taint: bool = True) -> str:
    """A completed scan with code-intelligence entrypoints and one SAST finding in the handler."""
    handler_line = 40
    steps = (
        (
            TaintPathStep("app/orders.py", 41, "order_id from the path enters get_order()"),
            TaintPathStep("app/orders.py", 44, "Order.get(order_id) with no owner check", True),
        )
        if taint
        else ()
    )
    sast = Finding(
        id="semgrep:idor:app/orders.py:44", title="Object fetched by id without an owner check",
        description="d", location=Location("app/orders.py", 44, 44, "Order.get(order_id)"),
        taxonomy=Taxonomy(Category.SAST, cwe=(cwe_id,)),
        evidence=Evidence(reported_by=["opengrep"], rule_ids={"opengrep": ["idor"]}),
        taint_path=steps,
    )  # fmt: skip
    with env.sessions() as s:
        scan = repo.create_scan(s, source_type="git", source_ref="https://github.com/a/b",
                                source_label="a/b", tools=["opengrep"])  # fmt: skip
        scan.asset_id = env.asset_id
        s.commit()
        from core.postprocess import finalize

        findings = finalize([sast])
        result = repo.sync_issues_for_scan(s, scan.id, findings)
        repo.add_findings(s, scan.id, findings, result.updates)
        repo.set_entrypoints(s, scan.id, [
            {"method": "GET", "route": "/v2/orders/{id}", "path": "app/orders.py",
             "line": handler_line, "symbol": "app.orders.get_order", "framework": "fastapi"},
            {"method": "POST", "route": "/v2/orders", "path": "app/orders.py", "line": 80,
             "symbol": "app.orders.create_order", "framework": "fastapi"},
        ])  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        return scan.id


def test_the_route_picker_offers_the_latest_scans_entrypoints(env: Env) -> None:
    assert env.client.get(f"{base(env)}/routes", headers=AUTH).json() == {
        "scan_id": None,
        "routes": [],
    }
    scan_id = seed_scan(env)
    body = env.client.get(f"{base(env)}/routes", headers=AUTH).json()
    assert body["scan_id"] == scan_id
    assert [(r["method"], r["route"], r["path"], r["line"]) for r in body["routes"]] == [
        ("GET", "/v2/orders/{id}", "app/orders.py", 40),
        ("POST", "/v2/orders", "app/orders.py", 80),
    ]


def test_a_picked_route_links_to_the_handler_and_to_automations_taint_path(env: Env) -> None:
    seed_scan(env)
    with env.sessions() as s:
        automated = s.scalars(select(IssueRow)).one()
    r = record(env)
    assert r.status_code == 201, r.text
    m = r.json()["manual"]
    assert (m["path"], m["line"]) == ("app/orders.py", 40)  # the handler, from code intelligence
    assert m["related_issue_id"] == automated.id and m["related_source"] == "opengrep"
    with env.sessions() as s:
        row = s.scalars(select(FindingRow).where(FindingRow.issue_id == r.json()["issue_id"])).one()
        assert [step["line"] for step in row.data["taint_path"]] == [41, 44]
        assert row.data["location"]["path"] == "app/orders.py"


def test_no_link_when_the_cwes_are_unrelated_or_the_route_is_elsewhere(env: Env) -> None:
    seed_scan(env)
    unrelated = record(env, cwe="79", title="Reflected XSS in order page").json()["manual"]
    elsewhere = record(env, route="/v2/carts/{id}", title="IDOR on carts").json()["manual"]
    no_cwe = record(env, cwe=None, title="Something on orders").json()["manual"]
    assert unrelated["related_issue_id"] is None
    assert elsewhere["related_issue_id"] is None and elsewhere["path"] is None
    assert no_cwe["related_issue_id"] is None


def test_entrypoints_are_taken_from_the_code_graph() -> None:
    from types import SimpleNamespace

    from core.codeintel.models import CodeGraph, Entrypoint, Symbol

    sym = Symbol("s1", "app/api.py", "create", "app.api.create", "function", 12, 20, "python")
    graph = CodeGraph(
        symbols={"s1": sym},
        entrypoints=[Entrypoint("s1", "fastapi", "POST", "/orders"),
                     Entrypoint("missing", "flask", "GET", "/x"), Entrypoint("s1", "flask", "", "")],
    )  # fmt: skip
    assert _entrypoints(SimpleNamespace(graph=graph)) == [
        {"method": "POST", "route": "/orders", "path": "app/api.py", "line": 12,
         "symbol": "app.api.create", "framework": "fastapi"},
    ]  # fmt: skip
    assert _entrypoints(None) is None


# --- evidence attachments ---------------------------------------------------------------------

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
HTML = b"<!doctype html><script>fetch('/steal?c='+document.cookie)</script>"


def attach(
    env: Env, manual_id: str, name: str, data: bytes, ctype: str, headers: Any = AUTH
) -> Any:
    return env.client.post(
        f"/v2/manual-findings/{manual_id}/attachments", files={"file": (name, data, ctype)},
        headers=headers,
    )  # fmt: skip


def test_attachments_are_sniffed_not_trusted(env: Env) -> None:
    mid = record(env).json()["manual"]["id"]
    png = attach(env, mid, "shot.png", PNG, "image/png").json()
    assert (png["sniffed_type"], png["active_content"], png["encrypted"]) == (
        "image/png",
        False,
        False,
    )
    disguised = attach(env, mid, "../../shot.png", HTML, "image/png").json()
    assert disguised["sniffed_type"] == "text/html" and disguised["active_content"] is True
    assert disguised["file_name"] == "shot.png" and disguised["declared_type"] == "image/png"
    listed = env.client.get(f"/v2/manual-findings/{mid}", headers=AUTH).json()["attachments"]
    assert [a["id"] for a in listed] == [png["id"], disguised["id"]]


def test_an_attachment_is_only_ever_downloaded_through_a_signed_link(env: Env) -> None:
    mid = record(env).json()["manual"]["id"]
    att = attach(env, mid, "page.html", HTML, "text/html").json()
    link = env.client.post(f"/v2/attachments/{att['id']}/link", headers=AUTH).json()
    url = link["url"]
    assert url.startswith(f"/v2/attachments/{att['id']}/download?token=")
    got = env.client.get(url)  # no Authorization header: the link is the credential
    assert got.status_code == 200 and got.content == HTML
    assert got.headers["content-type"] == "application/octet-stream"
    assert got.headers["content-disposition"] == 'attachment; filename="page.html"'
    assert got.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in got.headers["content-security-policy"]
    assert got.headers["cache-control"] == "no-store"

    other = attach(env, mid, "b.png", PNG, "image/png").json()
    token = url.split("token=")[1]
    assert (
        env.client.get(f"/v2/attachments/{other['id']}/download?token={token}").status_code == 404
    )
    forged = token[:-4] + ("0000" if not token.endswith("0000") else "1111")
    assert env.client.get(f"/v2/attachments/{att['id']}/download?token={forged}").status_code == 404


def test_a_download_link_expires() -> None:
    key = attachments.link_key("t")
    token, expires = attachments.sign(key, "a1", "org", now=time.time() - 3600)
    assert attachments.verify(key, "a1", token) is None
    token, _ = attachments.sign(key, "a1", "org")
    assert attachments.verify(key, "a1", token) == "org"
    assert attachments.verify(attachments.link_key("other"), "a1", token) is None


def test_another_org_cannot_attach_to_or_link_an_attachment(env: Env) -> None:
    mid = record(env).json()["manual"]["id"]
    att = attach(env, mid, "a.png", PNG, "image/png").json()
    assert attach(env, mid, "b.png", PNG, "image/png", headers=OTHER).status_code == 404
    assert env.client.post(f"/v2/attachments/{att['id']}/link", headers=OTHER).status_code == 404


def test_size_and_count_limits(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    mid = record(env).json()["manual"]["id"]
    monkeypatch.setattr(attachments, "MAX_BYTES", 100)
    assert attach(env, mid, "big.bin", b"x" * 101, "application/octet-stream").status_code == 413
    monkeypatch.setattr(attachments, "MAX_PER_FINDING", 1)
    assert attach(env, mid, "a.png", PNG, "image/png").status_code == 201
    assert attach(env, mid, "b.png", PNG, "image/png").status_code == 422
    assert attach(env, mid, "empty.txt", b"", "text/plain").status_code == 422


class FakeOpenBao:
    """Stands in for OpenBao Transit: wraps keys by XOR with a per-org secret, which is enough to
    prove the bytes at rest are not the file and that reading needs the org's key."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def ensure_org_key(self, org_id: str) -> None:
        self.calls.append("ensure")

    def generate_data_key(self, org_id: str) -> Any:
        from core.secrets.openbao import DataKey

        plain = bytes(range(32))
        return DataKey(plain, "vault:v1:" + plain.hex())

    def unwrap_data_key(self, org_id: str, wrapped: str) -> bytes:
        self.calls.append("unwrap")
        return bytes.fromhex(wrapped.removeprefix("vault:v1:"))


def test_with_openbao_attachments_are_encrypted_at_rest(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeOpenBao()
    monkeypatch.setattr(attachments, "_openbao", lambda addr, token: fake)
    mid = record(env).json()["manual"]["id"]
    att = attach(env, mid, "shot.png", PNG, "image/png").json()
    assert att["encrypted"] is True
    with env.sessions() as s:
        row = s.get(EvidenceAttachment, att["id"])
        assert row is not None and row.data != PNG and PNG not in row.data and row.wrapped_dek
        # Bound to its own row: the same ciphertext under another id does not decrypt.
        from core.secrets.envelope import DecryptionError

        moved = EvidenceAttachment(**{c.name: getattr(row, c.name) for c in row.__table__.columns})
        moved.id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(DecryptionError):
            attachments.read(moved, openbao_addr="x", openbao_token="y")
    url = env.client.post(f"/v2/attachments/{att['id']}/link", headers=AUTH).json()["url"]
    assert env.client.get(url).content == PNG and "unwrap" in fake.calls


def test_sniffing() -> None:
    cases = {
        PNG: ("image/png", False),
        b"\xff\xd8\xff\xe0rest": ("image/jpeg", False),
        b"%PDF-1.7\n": ("application/pdf", True),
        b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>': ("image/svg+xml", True),
        HTML: ("text/html", True),
        b'{"log": {"entries": []}}': ("application/json", False),
        b"GET /v2/orders/2 HTTP/1.1\r\nHost: x\r\n": ("text/plain; http-capture", False),
        b"just words": ("text/plain", False),
        b"\x00\x01\x02": ("application/octet-stream", False),
    }
    for data, expected in cases.items():
        got = attachments.sniff(data)
        assert (got.content_type, got.active) == expected, data[:20]


def test_a_manual_finding_needs_ingest_write(env: Env) -> None:
    with env.sessions() as s:
        _, raw = repo.create_api_token(
            s, org_id=DEFAULT_ORG_ID, name="reader", scopes=["ingest:read"]
        )
    reader = {"Authorization": f"Bearer {raw}"}
    r = env.client.post(f"{base(env)}/manual-findings", json=finding_body(), headers=reader)
    assert r.status_code == 403
    assert env.client.get(f"{base(env)}/routes", headers=reader).status_code == 200


def test_an_issue_only_a_person_reported_can_be_opened(env: Env) -> None:
    """Found driving the screen: the issue page looked only in the latest native scan, so an
    issue from a manual finding (or any import) answered "not found"."""
    r = record(env).json()
    detail = env.client.get(f"/assets/{env.asset_id}/issues/{r['issue_id']}", headers=AUTH)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["title"] == "IDOR on GET /v2/orders/{id}" and body["issue"]["id"] == r["issue_id"]
    missing = "99999999-9999-4999-8999-999999999999"
    assert (
        env.client.get(f"/assets/{env.asset_id}/issues/{missing}", headers=AUTH).status_code == 404
    )
