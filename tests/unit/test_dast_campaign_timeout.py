"""A campaign whose Nuclei run times out keeps what Nuclei found before then, and is `partial`: it
stores those findings but closes no Issue, because Nuclei didn't get to check everything.

Before, `run_nuclei` raised with nothing, so an active campaign against a real app lost every Nuclei
finding. The scanners are stubbed here (their real behaviour is in test_dast_nuclei_adapter.py and
the live tests); the campaign job, the egress proxy, persistence and Issue sync are real.
"""

from __future__ import annotations

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
    monkeypatch: pytest.MonkeyPatch, sessions: sessionmaker[Session]
) -> None:
    monkeypatch.setattr(
        ownership, "verify", lambda *a, **kw: ownership.VerificationOutcome(ok=True)
    )
    zap_finds: list[Finding] = []
    monkeypatch.setattr(pipeline, "run_zap_baseline", lambda *a, **kw: list(zap_finds))

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
