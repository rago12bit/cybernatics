"""Server-side scan job: source -> workspace -> parallel sandboxed tools -> persist -> publish.

The database is the source of truth; events are best-effort progress signals for the UI.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from core.correlation import correlate
from core.ingest import IngestError
from core.models import Category
from core.observability import bind_scan, in_context, mark_error, set_attributes, span
from core.observability import metrics as obs
from core.persistence import repo
from core.persistence.db import SessionFactory
from core.persistence.storage import ObjectStore
from core.postprocess import finalize
from core.reachability import analyze_or_none
from core.risk import ensure_fresh
from core.scan import ADAPTERS, ToolOutcome, detect_context, execute_tool
from core.source import materialize
from core.taint import analyze_or_none as taint_analyze_or_none
from core.tenancy import scoped_sessions

log = logging.getLogger(__name__)

SECRETS_WITHHELD = "withheld: scan contains detected secrets; raw output may echo them"


def _final_status(outcomes: list[ToolOutcome]) -> str:
    ran = [o for o in outcomes if o.status != "skipped"]
    if not ran or all(o.status == "ok" for o in ran):
        return "completed"
    return "partial" if any(o.status == "ok" for o in ran) else "failed"


def run_scan_job(
    scan_id: str,
    sessions: SessionFactory,
    store: ObjectStore,
    bus: Any,
    executor: Any = execute_tool,
    *,
    org_id: str | None = None,
) -> str:
    """Run one scan end to end. Returns the final status. Never raises for scan-level problems.

    Log lines inside carry the scan id. Stages are spans of one trace: ingest, per-tool spans (which
    run in parallel), correlate, finalize, persist.

    `org_id` (ADR-0013): set by `core.tasks.run_scan_task` from the enqueue call, which already
    knows it -- the worker has no other safe way to learn it (`core.tenancy.scoped_sessions`).
    `None` is the trusted-internal/test default (also every SQLite test's implicit case, since
    SQLite has no RLS to set up in the first place).
    """
    if org_id is not None:
        sessions = scoped_sessions(sessions, org_id)
    started = time.monotonic()
    obs.SCANS_RUNNING.inc()
    status = "failed"
    counts: dict[str, int] = {}
    try:
        with bind_scan(scan_id), span("scan", scan_id=scan_id) as sp:
            log.info("scan started")
            status, counts = _run_scan_job(scan_id, sessions, store, bus, executor)
            set_attributes(sp, status=status, findings=sum(counts.values()))
            if status == "failed":
                mark_error(sp, "scan failed")
            log.info(
                "scan finished",
                extra={"status": status, "findings": sum(counts.values()),
                       "duration_s": round(time.monotonic() - started, 2)},
            )  # fmt: skip
        return status
    finally:
        obs.SCANS_RUNNING.dec()
        obs.observe_scan(status, time.monotonic() - started, counts)


def _run_scan_job(
    scan_id: str,
    sessions: SessionFactory,
    store: ObjectStore,
    bus: Any,
    executor: Any,
) -> tuple[str, dict[str, int]]:
    with sessions() as s:
        scan = repo.get_scan(s, scan_id)
        if scan is None:
            raise LookupError(f"scan {scan_id} not found")
        source_type, source_ref, tools = scan.source_type, scan.source_ref, list(scan.tools)
        ref = scan.ref
        github = (scan.github_repo, scan.github_pr_number, scan.github_installation_id)
        repo.reset_scan_results(s, scan_id)
        repo.mark_running(s, scan_id)
    bus.publish(scan_id, {"type": "scan.started", "scan_id": scan_id, "tools": tools})

    def fail(message: str) -> tuple[str, dict[str, int]]:
        with sessions() as s:
            repo.finish_scan(s, scan_id, "failed", message)
        bus.publish(scan_id, {"type": "scan.finished", "scan_id": scan_id, "status": "failed",
                              "error": message})  # fmt: skip
        return "failed", {}

    try:
        with ExitStack() as stack:
            with span("ingest", source_type=source_type):
                workspace = stack.enter_context(materialize(source_ref, ref=ref))
                ctx = detect_context(workspace)
            with span("reachability"):
                reach = analyze_or_none(workspace)
            with span("taint"):
                taint = taint_analyze_or_none(workspace)
            runnable: list[str] = []
            outcomes: list[ToolOutcome] = []
            for name in tools:
                if ADAPTERS[name].applies_to(ctx):
                    runnable.append(name)
                    continue
                skipped = ToolOutcome(name, "skipped", error="no relevant files")
                outcomes.append(skipped)
                obs.observe_tool(name, "skipped", None)
                _record(sessions, bus, scan_id, skipped)

            raws: dict[str, bytes] = {}
            with span("tools", tools=",".join(runnable)):
                with ThreadPoolExecutor(max_workers=max(len(runnable), 1)) as pool:
                    futures = {pool.submit(in_context(executor), t, workspace): t for t in runnable}
                    for fut in as_completed(futures):
                        tool = futures[fut]
                        try:
                            outcome = fut.result()
                        except Exception as exc:  # noqa: BLE001 - a dying tool is data, not a crash
                            outcome = ToolOutcome(
                                tool, "error", error=f"{type(exc).__name__}: {exc}"
                            )
                            obs.observe_tool(tool, "error", None)
                        outcomes.append(outcome)
                        raws[tool] = outcome.raw
                        _record(sessions, bus, scan_id, outcome)
    except IngestError as exc:
        log.warning("ingestion failed: %s", exc)
        return fail(str(exc))
    except Exception:
        log.exception("scan crashed")
        return fail("internal error while running the scan")

    # Correlate BEFORE redacting: redaction placeholders look identical and would over-merge.
    with span("correlate") as sp:
        correlated, stats = correlate([f for o in outcomes for f in o.findings])
        set_attributes(sp, raw=stats.raw, unique=stats.unique)
    with span("finalize"):
        ensure_fresh()
        findings = finalize(correlated, reach=reach, taint=taint, root=workspace)
    has_secrets = any(f.taxonomy.category is Category.SECRETS for f in findings)
    with span("persist", findings=len(findings)):
        _store_raw(sessions, store, scan_id, outcomes, raws, has_secrets)
        status = _final_status(outcomes)
        with sessions() as s:
            # Only a full, unfiltered scan of the actual branch can tell an issue is fixed: absence
            # is only meaningful when the whole asset was actually looked at (rules out "partial"/
            # "failed"), AND when what was looked at is the asset's real current state, not a `ref`
            # override (Week 30) previewing a PR that might never merge. Syncing a PR scan's
            # findings into the shared asset's Issue history would corrupt it -- a PR-only finding
            # would show as "new" against the real branch, then falsely "fixed" the next time the
            # real branch is scanned and it's (correctly) absent there. A PR scan still gets "new
            # in this PR" (plan §36): `classify_findings_for_pr` is the read-only counterpart that
            # matches against the asset's current issues without writing any of this scan's own
            # findings back into that table.
            issues = updates = None
            if status == "completed":
                if ref is None:
                    issues = repo.sync_issues_for_scan(s, scan_id, findings)
                    updates = issues.updates
                else:
                    updates = repo.classify_findings_for_pr(s, scan_id, findings)
            repo.add_findings(s, scan_id, findings, updates)
            repo.finish_scan(s, scan_id, status)
            counts = repo.severity_counts(s, scan_id)
    if issues is not None:
        issue_counts: dict[str, int] | None = {
            "new": issues.new_count,
            "reintroduced": issues.reintroduced_count,
            "fixed": issues.fixed_count,
        }
    elif updates is not None:
        issue_counts = {
            "new": sum(1 for u in updates if u.state == "new"),
            "existing": sum(1 for u in updates if u.state != "new"),
        }
    else:
        issue_counts = None
    bus.publish(scan_id, {"type": "scan.finished", "scan_id": scan_id, "status": status,
                          "findings": len(findings), "raw_findings": stats.raw,
                          "dedup_rate": round(stats.dedup_rate, 3),
                          "severity_counts": counts, "issues": issue_counts})  # fmt: skip
    _cleanup_upload(source_type, source_ref)
    github_repo, pr_number, installation_id = github
    if github_repo and pr_number and installation_id:
        _post_pr_comment(scan_id, github_repo, pr_number, installation_id, status, counts, findings)
    return status, counts


def _post_pr_comment(
    scan_id: str,
    github_repo: str,
    pr_number: int,
    installation_id: str,
    status: str,
    severity_counts: dict[str, int],
    findings: list[Any],
) -> None:
    """Best-effort: a scan that already completed must not be reported as failed just because
    GitHub's API hiccupped or the App's credentials are momentarily wrong. Logged, not raised."""
    from core.ci.github import upsert_comment
    from core.config import Settings
    from core.github_app import installation_token, pr_comment_body

    settings = Settings.from_env()
    if not (settings.github_app_id and settings.github_app_private_key):
        log.warning("scan %s is tied to a GitHub PR but the App isn't configured", scan_id)
        return
    try:
        token = installation_token(
            installation_id, settings.github_app_id, settings.github_app_private_key
        )
        body = pr_comment_body(
            status=status,
            severity_counts=severity_counts,
            findings=[f.to_dict() for f in findings],
            scan_id=scan_id,
        )
        upsert_comment(github_repo, pr_number, body, token)
    except (
        Exception
    ):  # noqa: BLE001 - GitHub/network errors are data, not a reason to fail the scan
        log.exception("could not post PR comment for scan %s", scan_id)


def _record(sessions: SessionFactory, bus: Any, scan_id: str, o: ToolOutcome) -> None:
    block = o.status_block()
    if o.status == "skipped":
        block["reason"] = o.error
    with sessions() as s:
        repo.add_tool_run(s, scan_id, o.tool, block)
    bus.publish(scan_id, {"type": "tool.finished", "scan_id": scan_id, "tool": o.tool, **block})


def _store_raw(
    sessions: SessionFactory,
    store: ObjectStore,
    scan_id: str,
    outcomes: list[ToolOutcome],
    raws: dict[str, bytes],
    has_secrets: bool,
) -> None:
    """Persist raw tool output, except where it could echo a secret (threat T7)."""
    for o in outcomes:
        raw = raws.get(o.tool, b"")
        if not raw:
            continue
        # Gitleaks output is redacted at source; everything else may echo source lines.
        if has_secrets and o.tool != "gitleaks":
            with sessions() as s:
                repo.set_raw_artifact(s, scan_id, o.tool, None, SECRETS_WITHHELD)
            continue
        key = f"scans/{scan_id}/raw/{o.tool}.json"
        try:
            store.put(key, raw)
        except Exception:  # noqa: BLE001 - losing an artifact must not lose the scan
            log.exception("could not store raw output for %s/%s", scan_id, o.tool)
            continue
        with sessions() as s:
            repo.set_raw_artifact(s, scan_id, o.tool, key, None)


def _cleanup_upload(source_type: str, source_ref: str) -> None:
    if source_type == "archive":
        Path(source_ref).unlink(missing_ok=True)


__all__ = ["run_scan_job"]
