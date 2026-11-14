from __future__ import annotations

import io
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from starlette.websockets import WebSocketDisconnect

import api.main as api_main
from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.gitfetch import validate_git_url
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PUBLIC = lambda host: ["140.82.112.3"]  # noqa: E731


class FakeSubscriber:
    def __init__(self) -> None:
        self.to_emit: list[dict[str, Any]] = []
        self.closed = False

    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        try:
            for e in self.to_emit:
                yield e
        finally:
            self.closed = True


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(api_main, "validate_git_url", lambda url: validate_git_url(url, PUBLIC))
    enqueued: list[str] = []
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    sub = FakeSubscriber()
    app = create_app(AppState(settings, sessions, lambda sid, org: enqueued.append(sid), sub))  # fmt: skip
    return TestClient(app), enqueued, sessions, sub, settings


def test_refuses_to_start_without_a_strong_token(sessions: sessionmaker[Session]) -> None:
    base = Settings.from_env()
    weak = Settings(**{**base.__dict__, "api_token": "short"})
    with pytest.raises(RuntimeError, match="BULWARK_API_TOKEN"):
        create_app(AppState(weak, sessions, lambda _sid, _org: None, FakeSubscriber()))


def test_health_is_public_everything_else_needs_a_token(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    assert client.get("/healthz").status_code == 200
    calls = [
        client.post("/scans", json={"source": {"type": "git", "url": "https://github.com/a/b"}}),
        client.get("/scans/00000000-0000-0000-0000-000000000000"),
        client.get("/scans/00000000-0000-0000-0000-000000000000/findings"),
        client.post("/scans/upload", files={"archive": ("a.zip", b"x")}),
    ]
    assert [c.status_code for c in calls] == [401] * 4
    bad = {"Authorization": "Bearer wrong"}
    assert client.get("/scans/x", headers=bad).status_code == 401


def test_create_scan_from_git_url_enqueues_a_job(env) -> None:  # type: ignore[no-untyped-def]
    client, enqueued, *_ = env
    r = client.post("/scans", headers=AUTH, json={"source": {"type": "git", "url": "https://github.com/OWASP/NodeGoat"}, "tools": ["bandit", "bandit", "trivy"]})  # fmt: skip
    assert r.status_code == 202 and r.json()["status"] == "queued"
    assert enqueued == [r.json()["id"]]
    view = client.get(f"/scans/{r.json()['id']}", headers=AUTH).json()
    assert view["tools"] == ["bandit", "trivy"] and view["source_type"] == "git"


@pytest.mark.parametrize(
    "url",
    ["http://github.com/a/b", "https://evil.com/a/b", "https://169.254.169.254/x",
     "https://github.com/a/../../etc", "file:///etc/passwd", "git@github.com:a/b.git"],
)  # fmt: skip
def test_ssrf_and_bad_sources_rejected_at_the_edge(env, url: str) -> None:  # type: ignore[no-untyped-def]
    client, enqueued, *_ = env
    r = client.post("/scans", headers=AUTH, json={"source": {"type": "git", "url": url}})
    assert r.status_code == 422 and enqueued == []


def test_local_paths_cannot_be_scanned_through_the_api(env) -> None:  # type: ignore[no-untyped-def]
    """The API must never accept a server-side directory (arbitrary file read)."""
    client, enqueued, *_ = env
    for src in ({"type": "path", "url": "/etc"}, {"type": "git", "url": "/etc"}):
        assert client.post("/scans", headers=AUTH, json={"source": src}).status_code == 422
    assert enqueued == []


def test_unknown_tool_rejected(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    r = client.post("/scans", headers=AUTH, json={"source": {"type": "git", "url": "https://github.com/a/b"}, "tools": ["nmap"]})  # fmt: skip
    assert r.status_code == 422 and "nmap" in r.json()["detail"]


def test_upload_saves_under_a_server_chosen_name(env) -> None:  # type: ignore[no-untyped-def]
    client, enqueued, sessions, _, settings = env
    r = client.post("/scans/upload", headers=AUTH, data={"tools": "bandit"}, files={"archive": ("../../evil/proj.zip", io.BytesIO(b"PK-data"), "application/zip")})  # fmt: skip
    assert r.status_code == 202 and enqueued == [r.json()["id"]]
    with sessions() as s:
        scan = repo.get_scan(s, r.json()["id"])
        assert scan is not None
        assert scan.source_label == "proj.zip"  # client path stripped
        stored = Path(scan.source_ref)
        assert stored.parent == settings.upload_dir and stored.read_bytes() == b"PK-data"
        assert "evil" not in str(stored) and stored.name != "proj.zip"


def test_upload_validation(env) -> None:  # type: ignore[no-untyped-def]
    client, enqueued, _, _, settings = env
    r = client.post("/scans/upload", headers=AUTH, files={"archive": ("x.exe", b"MZ")})
    assert r.status_code == 422
    big = client.post("/scans/upload", headers=AUTH, files={"archive": ("a.zip", b"x" * 5000)})
    assert big.status_code == 413
    assert list(settings.upload_dir.glob("*")) == []  # partial file cleaned up
    bad_tool = client.post("/scans/upload", headers=AUTH, data={"tools": "nope"}, files={"archive": ("a.zip", b"x")})  # fmt: skip
    assert bad_tool.status_code == 422 and enqueued == []


def test_scan_lookup_404s(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    for sid in ("not-a-uuid", "00000000-0000-0000-0000-000000000000", "' OR 1=1 --"):
        assert client.get(f"/scans/{sid}", headers=AUTH).status_code == 404
        assert client.get(f"/scans/{sid}/findings", headers=AUTH).status_code == 404


def test_a_scan_is_invisible_to_a_different_org_header(env) -> None:  # type: ignore[no-untyped-def]
    """ADR-0013: `X-Bulwark-Org` selects a scope on top of the (still shared) bearer token. A scan
    created under one org is a plain 404 for a different org -- never a 403, which would itself leak
    that the scan exists."""
    client = env[0]
    org_a, org_b = {**AUTH, "X-Bulwark-Org": "org-a"}, {**AUTH, "X-Bulwark-Org": "org-b"}
    sid = client.post(
        "/scans", headers=org_a, json={"source": {"type": "git", "url": "https://github.com/a/b"}}
    ).json()["id"]
    assert client.get(f"/scans/{sid}", headers=org_a).status_code == 200
    assert client.get(f"/scans/{sid}", headers=org_b).status_code == 404
    assert client.get(f"/scans/{sid}/findings", headers=org_b).status_code == 404
    assert sid not in {sc["id"] for sc in client.get("/scans", headers=org_b).json()}
    assert sid in {sc["id"] for sc in client.get("/scans", headers=org_a).json()}


def test_no_org_header_is_the_bootstrap_default_org(env) -> None:  # type: ignore[no-untyped-def]
    """No `X-Bulwark-Org` header at all (every pre-Week-29 client) behaves exactly as before: it's
    the one bootstrap org, and it's stable across requests -- not "no scoping"."""
    client = env[0]
    sid = client.post(
        "/scans", headers=AUTH, json={"source": {"type": "git", "url": "https://github.com/a/c"}}
    ).json()["id"]
    assert client.get(f"/scans/{sid}", headers=AUTH).status_code == 200
    # An explicit request for a *different* org still can't see it.
    assert (
        client.get(f"/scans/{sid}", headers={**AUTH, "X-Bulwark-Org": "org-a"}).status_code == 404
    )


def _seed(sessions: sessionmaker[Session]) -> str:
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="u", tools=["bandit"]
        ).id
        repo.add_tool_run(s, sid, "bandit", {"status": "ok", "findings": 2, "exit_code": 1, "duration_seconds": 1.5})  # fmt: skip
        repo.add_tool_run(s, sid, "trivy", {"status": "skipped", "reason": "no relevant files"})
        repo.set_raw_artifact(s, sid, "bandit", None, "withheld: secrets")
        fs = []
        for i, (cat, sev) in enumerate(
            [(Category.SAST, Severity.HIGH), (Category.SCA, Severity.LOW)]
        ):
            f = Finding(f"f{i}", "t", "d", Location(f"p{i}.py", i + 1, i + 1), Taxonomy(cat))
            f.scoring.normalized_severity = sev
            f.evidence.reported_by = ["bandit"]
            fs.append(f)
        repo.add_findings(s, sid, fs)
        repo.finish_scan(s, sid, "completed")
    return sid


def test_scan_view_and_findings_endpoints(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, *_ = env
    sid = _seed(sessions)
    v = client.get(f"/scans/{sid}", headers=AUTH).json()
    assert v["status"] == "completed" and v["severity_counts"] == {"HIGH": 1, "LOW": 1}
    assert v["tool_status"]["bandit"]["raw_artifact"] == "withheld"
    assert v["tool_status"]["trivy"] == {"status": "skipped", "findings": 0, "exit_code": None, "duration_seconds": None, "error": "no relevant files", "warnings": [], "raw_artifact": None}  # fmt: skip
    assert "source_ref" not in v  # internal server path is never exposed
    page = client.get(f"/scans/{sid}/findings", headers=AUTH).json()
    assert page["total"] == 2 and page["items"][0]["scoring"]["normalized_severity"] == "HIGH"
    q = client.get(f"/scans/{sid}/findings", headers=AUTH, params={"severity": "LOW", "category": "sca"}).json()  # fmt: skip
    assert q["total"] == 1 and q["items"][0]["id"] == "f1"
    assert (
        client.get(f"/scans/{sid}/findings", headers=AUTH, params={"limit": 501}).status_code == 422
    )
    assert client.get(f"/scans/{sid}/findings", headers=AUTH, params={"sort": "drop table"}).status_code == 422  # fmt: skip


def test_openapi_documents_the_api(env) -> None:  # type: ignore[no-untyped-def]
    spec = env[0].get("/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    assert {"/scans", "/scans/upload", "/scans/{scan_id}", "/scans/{scan_id}/findings"} <= set(spec["paths"])  # fmt: skip


# ---- WebSocket ----------------------------------------------------------------------------
def test_ws_rejects_a_bad_token(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, *_ = env
    sid = _seed(sessions)
    with client.websocket_connect(f"/scans/{sid}/ws") as ws:
        ws.send_json({"token": "wrong"})
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4401


@pytest.mark.parametrize("hello", ["[]", '"token"', "7", "not json"])
def test_ws_closes_on_a_first_message_that_is_not_an_object(env, hello: str) -> None:  # type: ignore[no-untyped-def]
    """Anyone can open the socket; `[]` as the first message used to crash its handler."""
    client, _, sessions, *_ = env
    sid = _seed(sessions)
    with client.websocket_connect(f"/scans/{sid}/ws") as ws:
        ws.send_text(hello)
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 1008
    with client.websocket_connect(f"/scans/{sid}/ws") as ws:
        ws.send_bytes(b"\x00\x01")
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 1008


def test_ws_unknown_scan(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    with client.websocket_connect("/scans/00000000-0000-0000-0000-000000000000/ws") as ws:
        ws.send_json({"token": TOKEN})
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4404


def test_ws_finished_scan_sends_snapshot_and_closes(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, *_ = env
    sid = _seed(sessions)
    with client.websocket_connect(f"/scans/{sid}/ws") as ws:
        ws.send_json({"token": TOKEN})
        snap = ws.receive_json()
        assert snap["type"] == "snapshot" and snap["status"] == "completed"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


def test_ws_streams_live_events_until_the_scan_finishes(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, sub, _ = env
    with sessions() as s:
        sid = repo.create_scan(s, source_type="git", source_ref="u", source_label="u", tools=["bandit"]).id  # fmt: skip
        repo.mark_running(s, sid)
    sub.to_emit = [
        {"type": "tool.finished", "tool": "bandit", "status": "ok"},
        {"type": "scan.finished", "status": "completed"},
        {"type": "never.sent"},
    ]
    with client.websocket_connect(f"/scans/{sid}/ws") as ws:
        ws.send_json({"token": TOKEN})
        assert ws.receive_json()["status"] == "running"  # snapshot first
        assert ws.receive_json()["type"] == "tool.finished"
        assert ws.receive_json()["type"] == "scan.finished"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()
    assert sub.closed  # subscription is always cleaned up


def test_queue_outage_fails_the_scan_and_removes_the_upload(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, _, settings = env

    def broken(scan_id: str, org_id: str) -> None:
        raise ConnectionError("redis down")

    client.app.state.bulwark.enqueue = broken  # type: ignore[attr-defined]
    up = client.post("/scans/upload", headers=AUTH, files={"archive": ("a.zip", b"PK")})
    assert up.status_code == 503
    assert list(settings.upload_dir.glob("*")) == []  # no orphaned file
    git = client.post("/scans", headers=AUTH, json={"source": {"type": "git", "url": "https://github.com/a/b"}})  # fmt: skip
    assert git.status_code == 503
    with sessions() as s:
        from core.persistence.models import Scan

        scans = s.query(Scan).all()
        assert len(scans) == 2 and {x.status for x in scans} == {"failed"}  # nothing stuck "queued"


def test_scan_view_reports_raw_unique_and_dedup_rate(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, *_ = env
    sid = _seed(sessions)  # tool_runs claim 2 raw findings (bandit=2), 2 unique stored
    v = client.get(f"/scans/{sid}", headers=AUTH).json()
    assert (v["raw_findings"], v["unique_findings"], v["dedup_rate"]) == (2, 2, 0.0)
    with sessions() as s:
        repo.add_tool_run(s, sid, "semgrep", {"status": "ok", "findings": 2})
    v = client.get(f"/scans/{sid}", headers=AUTH).json()
    assert (v["raw_findings"], v["unique_findings"], v["dedup_rate"]) == (4, 2, 0.5)


def test_list_scans_newest_first_with_counts(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, *_ = env
    first = _seed(sessions)
    with sessions() as s:
        second = repo.create_scan(s, source_type="git", source_ref="u2", source_label="second", tools=["bandit"]).id  # fmt: skip
    rows = client.get("/scans", headers=AUTH).json()
    assert [r["id"] for r in rows] == [second, first]
    assert rows[1]["unique_findings"] == 2 and rows[1]["severity_counts"] == {"HIGH": 1, "LOW": 1}
    assert "source_ref" not in rows[0]
    assert client.get("/scans", params={"limit": 51}, headers=AUTH).status_code == 422
    assert client.get("/scans").status_code == 401


def test_cors_allows_only_configured_origins(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    ok = client.options("/scans", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})  # fmt: skip
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    bad = client.options("/scans", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})  # fmt: skip
    assert "access-control-allow-origin" not in bad.headers


def test_cors_preflight_allows_every_method_a_route_uses(env) -> None:  # type: ignore[no-untyped-def]
    # Found in Week 61: preflight allowed only GET and POST, so every PUT, PATCH and DELETE the web
    # app makes from its own origin (settings, threat model, SLA, connectors) was refused.
    client = env[0]
    methods = {m for r in client.app.routes for m in getattr(r, "methods", set())}
    used = methods - {"HEAD", "OPTIONS"}
    assert {"PUT", "PATCH", "DELETE"} <= used
    for method in sorted(used):
        r = client.options("/scans", headers={"Origin": "http://localhost:3000",
                           "Access-Control-Request-Method": method,
                           "Access-Control-Request-Headers": "authorization,content-type"})  # fmt: skip
        assert r.status_code == 200, method
        assert method in r.headers["access-control-allow-methods"]


def test_risk_feeds_status_requires_auth_and_reflects_the_cache(env) -> None:  # type: ignore[no-untyped-def]
    import json

    client, _, _, _, settings = env
    assert client.get("/risk/feeds").status_code == 401
    empty = client.get("/risk/feeds", headers=AUTH).json()
    assert empty["fetched_at"] is None and empty["stale"] is True  # nothing downloaded yet
    d = settings.workdir / "feeds"
    d.mkdir()
    (d / "meta.json").write_text(
        json.dumps(
            {"fetched_at": "2999-01-01T00:00:00+00:00", "epss": {"rows": 5}, "errors": {"kev": "x"}}
        )
    )
    got = client.get("/risk/feeds", headers=AUTH).json()
    assert got["stale"] is False and got["epss"] == {"rows": 5} and got["errors"] == {"kev": "x"}


def test_export_downloads_every_finding_in_each_format(env) -> None:  # type: ignore[no-untyped-def]
    import json

    client, _, sessions, _, _ = env
    sid = _seed(sessions)
    total = client.get(f"/scans/{sid}", headers=AUTH).json()["unique_findings"]
    sarif = client.get(f"/scans/{sid}/export?format=sarif", headers=AUTH)
    assert sarif.status_code == 200 and sarif.headers["content-type"].startswith(
        "application/sarif+json"
    )
    assert f'filename="bulwark-{sid[:8]}.sarif"' in sarif.headers["content-disposition"]
    assert sarif.headers["x-content-type-options"] == "nosniff"
    assert len(json.loads(sarif.content)["runs"][0]["results"]) == total > 0
    html = client.get(f"/scans/{sid}/export?format=html", headers=AUTH)
    assert (
        html.headers["content-type"].startswith("text/html")
        and "sandbox" in html.headers["content-security-policy"]
    )
    assert client.get(f"/scans/{sid}/export?format=pdf", headers=AUTH).content.startswith(b"%PDF-")
    assert (
        len(
            json.loads(client.get(f"/scans/{sid}/export?format=json", headers=AUTH).content)[
                "findings"
            ]
        )
        == total
    )
    assert (
        "sarif" in client.get(f"/scans/{sid}/export", headers=AUTH).headers["content-disposition"]
    )  # default


def test_export_rejects_bad_requests(env) -> None:  # type: ignore[no-untyped-def]
    client, _, sessions, _, _ = env
    sid = _seed(sessions)
    assert client.get(f"/scans/{sid}/export").status_code == 401
    assert client.get(f"/scans/{sid}/export?format=docx", headers=AUTH).status_code == 422
    assert client.get("/scans/not-a-uuid/export", headers=AUTH).status_code == 404
    with sessions() as s:
        queued = repo.create_scan(s, source_type="git", source_ref="u", source_label="u", tools=["bandit"]).id  # fmt: skip
    assert client.get(f"/scans/{queued}/export?format=sarif", headers=AUTH).status_code == 409
