"""A campaign whose Nuclei run times out keeps what Nuclei found before then, and is `partial`: it
stores those findings but closes no Issue, because Nuclei didn't get to check everything.

Before, `run_nuclei` raised with nothing, so an active campaign against a real app lost every Nuclei
finding. The scanners are stubbed here (their real behaviour is in test_dast_nuclei_adapter.py and
the live tests); the campaign job, the egress proxy, persistence and Issue sync are real. Each
stub first sends one request through the campaign's real proxy, as a scanner does, to `shop.test`:
"up" is that name resolved to a local web server, "down" is it not resolving at all.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.dast import ownership, pipeline
from core.dast.adapters.nuclei import NucleiTimeout
from core.dast.mapping import dast_finding
from core.models import Finding, Severity
from core.persistence import repo
from core.persistence.models import FindingRow, IssueRow, Organization, Scan, ToolRun
from core.tenancy import DEFAULT_ORG_ID as ORG

HOST = "https://shop.test"


class _Page(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html></html>")

    def log_message(self, *a: object) -> None:
        pass


class Shop:
    """`shop.test` for the proxy: a local page while `up`, a name that resolves to nothing when not."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.up = True
        self.server = HTTPServer(("127.0.0.1", 0), _Page)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        real = socket.getaddrinfo

        def resolve(host: Any, *a: Any, **kw: Any) -> Any:
            if host == "shop.test":
                if not self.up:
                    raise socket.gaierror(socket.EAI_NONAME, "not known")
                host = "127.0.0.1"
            return real(host, *a, **kw)

        monkeypatch.setattr(socket, "getaddrinfo", resolve)

    def visit(self, proxy: Any) -> None:
        """A scanner's first request, through the campaign's proxy (`proxy` is its ProxyConfig)."""
        port = self.server.server_address[1]
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as c:
            c.sendall(f"GET http://shop.test:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            c.recv(4096)


@pytest.fixture
def shop(monkeypatch: pytest.MonkeyPatch) -> Iterator[Shop]:
    s = Shop(monkeypatch)
    yield s
    s.server.shutdown()


class _NullBus:
    def publish(self, scan_id: str, payload: dict[str, object]) -> None:
        pass


def _web(tool: str, rule: str, route: str) -> Finding:
    return dast_finding(tool, rule=rule, title=f"{tool} {rule}", host=HOST, route=route,
                        severity=Severity.MEDIUM, native="medium")  # fmt: skip


def _campaign(s: Session, asset_id: str, mode: str) -> str:
    scan = Scan(org_id=ORG, source_type="web", source_ref=f"{HOST}/", source_label="shop.test",
                tools=["zap-baseline", "nuclei"], asset_id=asset_id, dast_mode=mode)  # fmt: skip
    s.add(scan)
    s.commit()
    return scan.id


def test_a_nuclei_timeout_keeps_its_findings_and_closes_nothing(
    monkeypatch: pytest.MonkeyPatch, sessions: sessionmaker[Session], shop: Shop
) -> None:
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )
    zap_finds: list[Finding] = []

    def zap(*a: Any, proxy: Any, **kw: Any) -> list[Finding]:
        shop.visit(proxy)
        return list(zap_finds)

    monkeypatch.setattr(pipeline, "run_zap_baseline", zap)

    def nuclei_times_out(*a: Any, **kw: Any) -> list[Finding]:
        raise NucleiTimeout(
            "nuclei timed out after 300s; kept the 1 finding(s) it reported before then",
            [_web("nuclei", "swagger-api", "/api-docs")],
        )

    monkeypatch.setattr(pipeline, "run_nuclei", nuclei_times_out)

    with sessions() as s:
        s.add(Organization(id=ORG, name="default"))
        s.commit()
        asset, _ = repo.register_web_asset(s, domain="shop.test", method="well_known", org_id=ORG)

        # A passive campaign that completes: two Issues.
        zap_finds[:] = [_web("zap-baseline", "10020", "/a"), _web("zap-baseline", "10038", "/")]
        first = _campaign(s, asset.id, "passive")
    assert pipeline.run_dast_campaign_job(first, sessions, _NullBus(), org_id=ORG) == "completed"

    # The active one: ZAP no longer lists /a, and Nuclei times out after one finding.
    zap_finds[:] = [_web("zap-baseline", "10038", "/")]
    with sessions() as s:
        second = _campaign(s, asset.id, "active")
    assert pipeline.run_dast_campaign_job(second, sessions, _NullBus(), org_id=ORG) == "partial"

    with sessions() as s:
        stored = s.scalars(select(FindingRow).where(FindingRow.scan_id == second)).all()
        assert sorted(r.data["evidence"]["reported_by"][0] for r in stored) == [
            "nuclei", "zap-baseline"]  # fmt: skip
        run = s.scalars(
            select(ToolRun).where(ToolRun.scan_id == second, ToolRun.tool == "nuclei")
        ).one()
        assert (run.status, run.findings_count) == ("timeout", 1) and "kept the 1" in (
            run.error or ""
        )
        states = {i.state for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset.id))}
    assert "fixed" not in states  # /a was not shown fixed by a run that didn't finish


def test_a_campaign_against_a_target_that_is_down_changes_no_issue(
    monkeypatch: pytest.MonkeyPatch, sessions: sessionmaker[Session], shop: Shop
) -> None:
    """ZAP reports on the proxy's own 502 pages when the target does not answer, and the scan
    "completed": every Issue it did not see again was then closed as fixed. Now it fails."""
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )
    zap_finds: list[Finding] = []

    def zap(*a: Any, proxy: Any, **kw: Any) -> list[Finding]:
        shop.visit(proxy)
        return list(zap_finds)

    monkeypatch.setattr(pipeline, "run_zap_baseline", zap)
    with sessions() as s:
        s.add(Organization(id=ORG, name="default"))
        s.commit()
        asset, _ = repo.register_web_asset(s, domain="shop.test", method="well_known", org_id=ORG)
        zap_finds[:] = [_web("zap-baseline", "10020", "/a"), _web("zap-baseline", "10038", "/")]
        first = _campaign(s, asset.id, "passive")
    assert pipeline.run_dast_campaign_job(first, sessions, _NullBus(), org_id=ORG) == "completed"

    with sessions() as s:
        before = sorted(
            (i.id, i.state)
            for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset.id))
        )
    assert len(before) == 2

    shop.up = False  # the site is down; ZAP still "finds" a missing header, on the 502 page
    zap_finds[:] = [_web("zap-baseline", "10021", "/")]
    with sessions() as s:
        second = _campaign(s, asset.id, "passive")
    assert pipeline.run_dast_campaign_job(second, sessions, _NullBus(), org_id=ORG) == "failed"
    with sessions() as s:
        scan = s.get(Scan, second)
        assert scan is not None and "the target did not answer" in (scan.error or "")
        after = sorted(
            (i.id, i.state)
            for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset.id))
        )
        assert after == before  # neither closed, none added
        assert not s.scalars(select(FindingRow).where(FindingRow.scan_id == second)).all()


def test_a_campaign_whose_scanners_never_used_the_proxy_fails(
    monkeypatch: pytest.MonkeyPatch, sessions: sessionmaker[Session]
) -> None:
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )
    monkeypatch.setattr(pipeline, "run_zap_baseline",
                        lambda *a, **kw: [_web("zap-baseline", "10020", "/a")])  # fmt: skip
    with sessions() as s:
        s.add(Organization(id=ORG, name="default"))
        s.commit()
        asset, _ = repo.register_web_asset(s, domain="shop.test", method="well_known", org_id=ORG)
        scan_id = _campaign(s, asset.id, "passive")
    assert pipeline.run_dast_campaign_job(scan_id, sessions, _NullBus(), org_id=ORG) == "failed"
    with sessions() as s:
        assert "no request reached the target" in (s.get(Scan, scan_id).error or "")  # type: ignore[union-attr]
        assert not s.scalars(select(IssueRow)).all()
