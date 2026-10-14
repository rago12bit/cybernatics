"""DAST campaign job: re-verify ownership live -> rate-limit (active only) -> run tools -> persist
(Week 49 task 3, plan §22.4). Deliberately a separate, much smaller pipeline from `core.pipeline.
run_scan_job` rather than forcing a web target through the SAST pipeline's workspace/reachability/
taint/SBOM machinery, none of which applies to a target with no checked-out source tree -- but it
ends at the exact same tables (`scans`, `tool_runs`, `findings`), via the same
`core.persistence.repo` functions, so the API/UI need no DAST-specific code path to display a
campaign's results.

The scanner tools run behind `core.dast.proxy`'s egress proxy (Week 49b, plan §22.4 follow-up): a
`BackgroundProxy` scoped to exactly the campaign's one verified host is started in
`run_dast_campaign_job` before either adapter runs and torn down after, on every exit path including
a tool error. This is the piece ADR-0035 originally disclosed as built but not wired in;
`core.dast.egress`'s nftables half (denying a scanner that ignores its proxy config outright) is
still Linux-only and still not exercised here, the same disclosed boundary as before.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlsplit

from core.correlation import correlate
from core.dast import campaign as campaign_rules
from core.dast import ownership
from core.dast.adapters.nuclei import NucleiError, NucleiTimeout, run_nuclei
from core.dast.adapters.zap import ZapError, run_zap_baseline
from core.dast.correlate import correlate_dast_with_sast
from core.dast.proxy import BackgroundProxy, ProxyConfig, ProxyError
from core.dast.routes import RouteHandler
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
    blocked_attempts: list[dict[str, Any]] = []

    def _record_blocked(host: str, port: int, is_connect: bool) -> None:
        blocked_attempts.append(
            {"host": host, "port": port, "protocol": "https" if is_connect else "http"}
        )

    target_host = urlsplit(target_url).hostname or target_url
    try:
        proxy = BackgroundProxy(frozenset({target_host}), on_blocked=_record_blocked)
    except ProxyError as exc:
        return fail(
            f"could not start the campaign's egress proxy: {exc}",
            action="dast.campaign.proxy_failed",
        )

    with proxy:
        proxy_config = ProxyConfig(host="host.docker.internal", port=proxy.port)
        started = time.monotonic()
        try:
            zap_findings = run_zap_baseline(target_url, proxy=proxy_config)
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
                repo.add_tool_run(
                    s, scan_id, "zap-baseline", {"status": "error", "error": str(exc)}
                )

        if mode == "active":
            started = time.monotonic()
            try:
                nuclei_findings = run_nuclei(target_url, proxy=proxy_config)
                findings.extend(nuclei_findings)
                elapsed = time.monotonic() - started
                with sessions() as s:
                    repo.add_tool_run(
                        s, scan_id, "nuclei",
                        {"status": "ok", "findings": len(nuclei_findings),
                         "duration_seconds": elapsed},
                    )  # fmt: skip
            except NucleiTimeout as exc:
                # What it found before the deadline is kept; the campaign is then "partial", so
                # nothing it didn't get to check is read as fixed.
                findings.extend(exc.findings)
                tool_errors.append(str(exc))
                with sessions() as s:
                    repo.add_tool_run(
                        s, scan_id, "nuclei",
                        {"status": "timeout", "findings": len(exc.findings), "error": str(exc),
                         "duration_seconds": time.monotonic() - started},
                    )  # fmt: skip
            except NucleiError as exc:
                tool_errors.append(str(exc))
                with sessions() as s:
                    repo.add_tool_run(s, scan_id, "nuclei", {"status": "error", "error": str(exc)})

    if blocked_attempts:
        # Egress the scanners tried and were refused -- real signal (a redirect, a misbehaving
        # template, an SSRF-shaped response) worth keeping on the campaign's own record, not just in
        # the proxy process's own stdout where nothing reads it (Week 49b, plan §22.4 follow-up).
        with sessions() as s:
            repo.add_tool_run(
                s, scan_id, "egress-proxy",
                {"status": "blocked_attempts", "attempts": blocked_attempts},
            )  # fmt: skip
            repo.append_audit_entry(
                s, actor="worker:dast-campaign", action="dast.campaign.egress_blocked",
                target=scan_id, payload={"asset_id": asset_id, "attempts": blocked_attempts},
            )  # fmt: skip

    # Before anything is read from the findings: a target that never answered (down, or not
    # reachable from here) still gets "findings" -- ZAP reports on the proxy's own 502 pages -- and
    # a completed campaign would then close every Issue it did not see again.
    unreached = proxy.target_unreached()
    if unreached is not None:
        return fail(f"{unreached}; no Issue was changed",
                    action="dast.campaign.target_unreachable")  # fmt: skip

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
                     "raw_findings": stats.raw, "unique_findings": stats.unique,
                     "blocked_egress_attempts": len(blocked_attempts)},
        )  # fmt: skip
        counts = repo.severity_counts(s, scan_id)
    _confirm_sast_findings_at_runtime(sessions, asset_id, scan_id, final_findings, org_id=org_id)
    bus.publish(
        scan_id,
        {"type": "scan.finished", "scan_id": scan_id, "status": status,
         "findings": len(final_findings), "severity_counts": counts},
    )  # fmt: skip
    return status


def _confirm_sast_findings_at_runtime(
    sessions: SessionFactory,
    asset_id: str,
    dast_scan_id: str,
    dast_findings: list[Finding],
    *,
    org_id: str | None,
) -> None:
    """SAST/DAST correlation (Week 49 task 4, plan §22.4): best-effort and strictly additive -- it
    only ever adds a "confirmed at runtime" marker to an Issue that already exists from the linked
    source Asset's own SAST scans, never creates, removes, or changes anything else. Any failure
    here must not undo or fail a DAST campaign that otherwise completed successfully. A web Asset
    with no `linked_source_asset_id` (it is optional when registering a site, on screen, by API or
    by CLI) simply has nothing to correlate against, silently."""
    try:
        with sessions() as s:
            web_asset = repo.get_asset(s, asset_id, org_id=org_id)
            source_asset_id = web_asset.linked_source_asset_id if web_asset else None
            if source_asset_id is None:
                return
            sast_scan = repo.latest_scan_with_route_map(s, source_asset_id, org_id=org_id)
            if sast_scan is None:
                return
            handlers = [RouteHandler(**h) for h in (sast_scan.route_map or [])]
            sast_pairs = repo.issue_findings_for_scan(s, source_asset_id, sast_scan.id)
            sast_findings = [f for _, f in sast_pairs]
            # issue_findings_for_scan returns (issue_id, Finding) pairs; invert for lookup by the
            # Finding's own id, which is what correlate_dast_with_sast actually reports.
            finding_id_to_issue = {f.id: issue_id for issue_id, f in sast_pairs}
            confirmations = correlate_dast_with_sast(dast_findings, sast_findings, handlers)
            for c in confirmations:
                issue_id = finding_id_to_issue.get(c.sast_finding_id)
                if issue_id is not None:
                    repo.mark_issue_confirmed_at_runtime(s, issue_id, scan_id=dast_scan_id)
    except Exception:  # noqa: BLE001 - correlation is additive and must never affect the campaign
        log.exception("SAST/DAST correlation failed for asset %s", asset_id)
