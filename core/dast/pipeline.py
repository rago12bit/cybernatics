"""DAST campaign job: re-verify ownership live -> rate-limit (active only) -> run tools -> persist
(Week 49 task 3, plan §22.4). Deliberately a separate, much smaller pipeline from `core.pipeline.
run_scan_job` rather than forcing a web target through the SAST pipeline's workspace/reachability/
taint/SBOM machinery, none of which applies to a target with no checked-out source tree -- but it
ends at the exact same tables (`scans`, `tool_runs`, `findings`), via the same
`core.persistence.repo` functions, so the API/UI need no DAST-specific code path to display a
campaign's results.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from core.correlation import correlate
from core.dast import campaign as campaign_rules
from core.dast import ownership
from core.dast.adapters.nuclei import NucleiError, run_nuclei
from core.dast.adapters.zap import ZapError, run_zap_baseline
from core.models import Finding
from core.persistence import repo
from core.persistence.db import SessionFactory
from core.postprocess import finalize

log = logging.getLogger(__name__)


def run_dast_campaign_job(
    scan_id: str, sessions: SessionFactory, bus: Any, *, org_id: str | None = None
) -> str:
    """Returns the final status. Never raises for campaign-level problems -- an unverified or rate-
    limited campaign is a normal `failed` scan with a clear `error`, the same way a bad git URL
    fails an ordinary scan, not an exception the caller has to know to catch."""
    with sessions() as s:
        scan = repo.get_scan(s, scan_id, org_id=org_id)
        if scan is None:
            raise LookupError(f"dast campaign {scan_id} not found")
        asset_id, mode, target_url = scan.asset_id, scan.dast_mode, scan.source_ref
        repo.reset_scan_results(s, scan_id)
        repo.mark_running(s, scan_id)
    bus.publish(scan_id, {"type": "scan.started", "scan_id": scan_id, "tools": scan.tools})

    def fail(message: str, *, action: str) -> str:
        with sessions() as s:
            repo.finish_scan(s, scan_id, "failed", message)
            repo.append_audit_entry(
                s, actor="worker:dast-campaign", action=action, target=scan_id,
                payload={"asset_id": asset_id, "mode": mode, "reason": message},
            )  # fmt: skip
        bus.publish(
            scan_id,
            {"type": "scan.finished", "scan_id": scan_id, "status": "failed", "error": message},
        )
        return "failed"

    if asset_id is None or mode is None:
        return fail("not a DAST campaign (missing asset or mode)", action="dast.campaign.invalid")

    with sessions() as s:
        verification = repo.get_asset_verification(s, asset_id, org_id=org_id)
        if verification is None:
            return fail(
                "target has no ownership verification on record",
                action="dast.campaign.blocked_unverified",
            )
        outcome = ownership.verify(
            verification.method,
            scan.source_label,
            verification.token,
            resolver=ownership.DnsPythonResolver(),
            fetcher=ownership.HttpxFetcher(),
        )
        repo.record_verification_check(s, verification, ok=outcome.ok, error=outcome.error)
        if not outcome.ok:
            return fail(
                f"ownership verification failed at campaign start: {outcome.error}",
                action="dast.campaign.blocked_unverified",
            )

        if mode == "active":
            # This campaign's own row is already in the table (status="running") by the time this
            # check runs -- `exclude_scan_id` keeps it from counting as "the most recent prior
            # active campaign" against itself.
            last_active = repo.last_active_campaign_started_at(
                s, asset_id, org_id=org_id, exclude_scan_id=scan_id
            )
            limit = campaign_rules.check_active_scan_rate_limit(last_active)
            if not limit.allowed:
                hours = (limit.retry_after.total_seconds() / 3600) if limit.retry_after else 0
                return fail(
                    f"active scan rate limit: try again in {hours:.1f}h",
                    action="dast.campaign.rate_limited",
                )

    findings: list[Finding] = []
    tool_errors: list[str] = []
    started = time.monotonic()
    try:
        zap_findings = run_zap_baseline(target_url)
        findings.extend(zap_findings)
        elapsed = time.monotonic() - started
        with sessions() as s:
            repo.add_tool_run(
                s, scan_id, "zap-baseline",
                {"status": "ok", "findings": len(zap_findings), "duration_seconds": elapsed},
            )  # fmt: skip
    except ZapError as exc:
        tool_errors.append(str(exc))
        with sessions() as s:
            repo.add_tool_run(s, scan_id, "zap-baseline", {"status": "error", "error": str(exc)})

    if mode == "active":
        started = time.monotonic()
        try:
            nuclei_findings = run_nuclei(target_url)
            findings.extend(nuclei_findings)
            elapsed = time.monotonic() - started
            with sessions() as s:
                repo.add_tool_run(
                    s, scan_id, "nuclei",
                    {"status": "ok", "findings": len(nuclei_findings), "duration_seconds": elapsed},
                )  # fmt: skip
        except NucleiError as exc:
            tool_errors.append(str(exc))
            with sessions() as s:
                repo.add_tool_run(s, scan_id, "nuclei", {"status": "error", "error": str(exc)})

    if not findings and tool_errors:
        return fail("; ".join(tool_errors), action="dast.campaign.tools_failed")

    correlated, stats = correlate(findings)
    final_findings = finalize(correlated)
    status = "completed" if not tool_errors else "partial"
    with sessions() as s:
        # Same rule as core.pipeline._run_scan_job: only a full, unfiltered run can tell an issue is
        # fixed. A "partial" campaign (one tool errored) didn't look everywhere a "completed" one
        # would have, so absence here must not be read as "fixed."
        if status == "completed":
            issues = repo.sync_issues_for_scan(s, scan_id, final_findings)
            repo.add_findings(s, scan_id, final_findings, issues.updates)
        else:
            repo.add_findings(s, scan_id, final_findings, None)
        repo.finish_scan(s, scan_id, status)
        repo.append_audit_entry(
            s, actor="worker:dast-campaign", action="dast.campaign.completed", target=scan_id,
            payload={"asset_id": asset_id, "mode": mode, "status": status,
                     "raw_findings": stats.raw, "unique_findings": stats.unique},
        )  # fmt: skip
        counts = repo.severity_counts(s, scan_id)
    bus.publish(
        scan_id,
        {"type": "scan.finished", "scan_id": scan_id, "status": status,
         "findings": len(final_findings), "severity_counts": counts},
    )  # fmt: skip
    return status
