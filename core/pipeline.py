"""Server-side scan job: source -> workspace -> parallel sandboxed tools -> persist -> publish.

The database is the source of truth; events are best-effort progress signals for the UI.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from core.correlation import correlate
from core.ingest import IngestError
from core.models import Category
from core.persistence import repo
from core.persistence.db import SessionFactory
from core.persistence.storage import ObjectStore
from core.postprocess import finalize
from core.reachability import analyze_or_none
from core.risk import ensure_fresh
from core.scan import ADAPTERS, ToolOutcome, detect_context, execute_tool
from core.source import materialize

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
) -> str:
    """Run one scan end to end. Returns the final status. Never raises for scan-level problems."""
    with sessions() as s:
        scan = repo.get_scan(s, scan_id)
        if scan is None:
            raise LookupError(f"scan {scan_id} not found")
        source_type, source_ref, tools = scan.source_type, scan.source_ref, list(scan.tools)
        repo.reset_scan_results(s, scan_id)
        repo.mark_running(s, scan_id)
    bus.publish(scan_id, {"type": "scan.started", "scan_id": scan_id, "tools": tools})

    def fail(message: str) -> str:
        with sessions() as s:
            repo.finish_scan(s, scan_id, "failed", message)
        bus.publish(scan_id, {"type": "scan.finished", "scan_id": scan_id, "status": "failed",
                              "error": message})  # fmt: skip
        return "failed"

    try:
        with materialize(source_ref) as workspace:
            ctx = detect_context(workspace)
            reach = analyze_or_none(workspace)
            runnable: list[str] = []
            outcomes: list[ToolOutcome] = []
            for name in tools:
                if ADAPTERS[name].applies_to(ctx):
                    runnable.append(name)
                    continue
                skipped = ToolOutcome(name, "skipped", error="no relevant files")
                outcomes.append(skipped)
                _record(sessions, bus, scan_id, skipped)

            raws: dict[str, bytes] = {}
            with ThreadPoolExecutor(max_workers=max(len(runnable), 1)) as pool:
                futures = {pool.submit(executor, t, workspace): t for t in runnable}
                for fut in as_completed(futures):
                    tool = futures[fut]
                    try:
                        outcome = fut.result()
                    except Exception as exc:  # noqa: BLE001 - a dying tool is data, not a crash
                        outcome = ToolOutcome(tool, "error", error=f"{type(exc).__name__}: {exc}")
                    outcomes.append(outcome)
                    raws[tool] = outcome.raw
                    _record(sessions, bus, scan_id, outcome)
    except IngestError as exc:
        log.warning("scan %s ingestion failed: %s", scan_id, exc)
        return fail(str(exc))
    except Exception:
        log.exception("scan %s crashed", scan_id)
        return fail("internal error while running the scan")

    # Correlate BEFORE redacting: redaction placeholders look identical and would over-merge.
    correlated, stats = correlate([f for o in outcomes for f in o.findings])
    ensure_fresh()
    findings = finalize(correlated, reach=reach)
    has_secrets = any(f.taxonomy.category is Category.SECRETS for f in findings)
    _store_raw(sessions, store, scan_id, outcomes, raws, has_secrets)
    status = _final_status(outcomes)
    with sessions() as s:
        repo.add_findings(s, scan_id, findings)
        repo.finish_scan(s, scan_id, status)
        counts = repo.severity_counts(s, scan_id)
    bus.publish(scan_id, {"type": "scan.finished", "scan_id": scan_id, "status": status,
                          "findings": len(findings), "raw_findings": stats.raw,
                          "dedup_rate": round(stats.dedup_rate, 3),
                          "severity_counts": counts})  # fmt: skip
    _cleanup_upload(source_type, source_ref)
    return status


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
