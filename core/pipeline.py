"""Server-side scan job: source -> workspace -> parallel sandboxed tools -> persist -> publish.

The database is the source of truth; events are best-effort progress signals for the UI.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from core import inventory
from core.adapters import ToolAdapter
from core.correlation import correlate
from core.dast.routes import extract_routes_from_workspace
from core.ingest import IngestError
from core.integrations.dispatch import notify_scan_result
from core.models import Category, Finding, Package
from core.observability import bind_scan, in_context, mark_error, set_attributes, span
from core.observability import metrics as obs
from core.persistence import repo
from core.persistence.db import SessionFactory
from core.persistence.storage import ObjectStore
from core.plugins.registry import PluginError, resolve_adapters
from core.plugins.signing import PluginSignatureError
from core.postprocess import finalize
from core.reachability import ReachabilityIndex, analyze_or_none
from core.risk import ensure_fresh
from core.sbom.syft import SbomError, summarize
from core.scan import ADAPTERS, ToolOutcome, detect_context, execute_tool
from core.source import materialize
from core.supplychain.scorecard import enrich_direct_dependencies
from core.supplychain.typosquat import find_typosquats
from core.taint import analyze_or_none as taint_analyze_or_none
from core.tenancy import scoped_sessions

log = logging.getLogger(__name__)

SECRETS_WITHHELD = "withheld: scan contains detected secrets; raw output may echo them"


def _final_status(outcomes: list[ToolOutcome]) -> str:
    ran = [o for o in outcomes if o.status != "skipped"]
    if not ran or all(o.status == "ok" for o in ran):
        return "completed"
    return "partial" if any(o.status == "ok" for o in ran) else "failed"


def _adapter_bound_executor(adapters: Mapping[str, ToolAdapter]) -> Any:
    """Closes over this scan's resolved adapter table (built-ins plus any allowlisted, signature-
    verified plugins) without mutating `core.scan.ADAPTERS` itself -- that global is shared by every
    concurrent scan in this worker process, built-in or not, and two scans for different
    organizations must never see each other's plugins through it. Only substituted when the caller
    left `executor=None` (`run_scan_job`'s own default, used for every real production call); a
    caller that passes its own fake executor (every unit test in tests/unit/test_pipeline.py, and
    tests/unit/test_observability.py's monkeypatched one) bypasses adapter resolution entirely,
    which is correct there since those fakes never look at a ToolAdapter at all. Deliberately a
    `None` sentinel rather than comparing `executor is execute_tool`: a test that monkeypatches the
    module-level `execute_tool` name (as test_observability.py does) would otherwise make that
    identity check true by accident, silently wrapping a test double that was never meant to receive
    an `adapters=` keyword at all."""

    def _run(name: str, target: Path) -> ToolOutcome:
        return execute_tool(name, target, adapters=adapters)

    return _run


def _extract_route_map(workspace: Path) -> list[dict[str, Any]]:
    """Web-route handlers found in this scan's own source (Week 49 task 4, plan §22.4) -- what a
    later DAST campaign's `core.dast.correlate` needs to mark a static finding "confirmed at
    runtime." Best-effort like the SBOM/Scorecard enrichment below: a workspace with no Python, or
    one `ast` can't parse some of, must never fail the scan over a feature most scans never use."""
    try:
        return [
            {"route": h.route, "path": h.path, "line": h.line}
            for h in extract_routes_from_workspace(workspace)
        ]
    except Exception as exc:  # noqa: BLE001 - route extraction must never fail the whole scan
        log.warning("route extraction failed: %s", exc)
        return []


def _entrypoints(taint: Any) -> list[dict[str, Any]] | None:
    """The code graph's HTTP entrypoints, any framework, with their verbs and handler locations
    (Week 59, plan §43.2's route picker). Best-effort: `None` when code analysis did not run."""
    graph = getattr(taint, "graph", None)
    if graph is None:
        return None
    out = []
    for e in graph.entrypoints:
        sym = graph.symbols.get(e.symbol_id)
        if sym is None or not e.path:
            continue
        out.append({"method": e.method, "route": e.path, "path": sym.path, "line": sym.start_line,
                    "symbol": sym.qualified_name, "framework": e.framework})  # fmt: skip
    return sorted(out, key=lambda r: (r["route"], r["method"], r["path"], r["line"]))


def _process_sbom(
    raw: bytes, reach: ReachabilityIndex | None = None
) -> tuple[list[Finding], dict[str, Any] | None]:
    """Reshapes `syft`'s raw CycloneDX document into typosquat Findings (folded into the same
    correlate/finalize pipeline every other tool's Findings go through) and a JSON summary for the
    Dependencies screen (plan §20.5). Best-effort throughout: a corrupt SBOM, or Scorecard/deps.dev
    being unreachable, must not fail the whole scan -- the same "a dying tool is data" principle the
    per-tool loop above already applies."""
    try:
        sbom = summarize(raw)
    except SbomError as exc:
        log.warning("sbom: could not summarize syft output: %s", exc)
        return [], None
    findings = find_typosquats(sbom.packages)
    try:
        scorecard = enrich_direct_dependencies(sbom.direct_purls)
    except Exception as exc:  # noqa: BLE001 - a network/Scorecard failure must not fail the scan
        log.warning("sbom: scorecard enrichment failed: %s", exc)
        scorecard = {}
    packages = []
    for p in sbom.packages:
        if p.purl in sbom.direct_purls:
            relation = "direct"
        elif p.purl in sbom.transitive_purls:
            relation = "transitive"
        elif p.purl in sbom.roots:
            relation = "root"
        else:
            relation = "unknown"
        result = scorecard.get(p.purl)
        used = (
            reach.assess_package(Package(p.name, p.version, p.ecosystem))
            if reach is not None
            else None
        )
        packages.append(
            {
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
                "purl": p.purl,
                "license": p.license,
                "path": p.path,
                "relation": relation,
                "depends_on": list(sbom.graph.get(p.purl, ())),
                # Whether the application's own code imports it (plan §46.1's "reachable"):
                # null when that cannot be told, never a guessed "no".
                "reachable": used.reachable if used is not None else None,
                "reachable_reason": used.reason if used is not None else "",
                "scorecard": (
                    {"score": result.score, "checks": result.checks, "date": result.date}
                    if result is not None
                    else None
                ),
            }
        )
    summary = {
        "components": len(sbom.packages),
        "ecosystems": dict(sbom.ecosystems),
        "packages": packages,
    }
    return list(findings), summary


def run_scan_job(
    scan_id: str,
    sessions: SessionFactory,
    store: ObjectStore,
    bus: Any,
    executor: Any = None,
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
            status, counts = _run_scan_job(scan_id, sessions, store, bus, executor, org_id)
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
    org_id: str | None = None,
) -> tuple[str, dict[str, int]]:
    with sessions() as s:
        scan = repo.get_scan(s, scan_id)
        if scan is None:
            raise LookupError(f"scan {scan_id} not found")
        source_type, source_ref, tools = scan.source_type, scan.source_ref, list(scan.tools)
        source_label = scan.source_label
        ref = scan.ref
        asset_id = scan.asset_id
        scan_org = scan.org_id
        github = (scan.github_repo, scan.github_pr_number, scan.github_installation_id)
        # Resolved once, up front, inside the same org-scoped session this scan's own org already
        # uses: a plugin tool not (or no longer) allowlisted, or whose image fails Sigstore
        # verification right now, must fail the whole scan here, before it's even marked running --
        # not surface as a mysteriously-missing tool outcome later.
        try:
            adapters = resolve_adapters(tools, ADAPTERS, org_id, s)
        except (PluginError, PluginSignatureError) as exc:
            repo.finish_scan(s, scan_id, "failed", f"plugin resolution failed: {exc}")
            bus.publish(scan_id, {"type": "scan.finished", "scan_id": scan_id, "status": "failed",
                                  "error": f"plugin resolution failed: {exc}"})  # fmt: skip
            return "failed", {}
        repo.reset_scan_results(s, scan_id)
        repo.mark_running(s, scan_id)
    bus.publish(scan_id, {"type": "scan.started", "scan_id": scan_id, "tools": tools})
    if executor is None:
        executor = _adapter_bound_executor(adapters)

    def fail(message: str) -> tuple[str, dict[str, int]]:
        with sessions() as s:
            repo.finish_scan(s, scan_id, "failed", message)
        bus.publish(scan_id, {"type": "scan.finished", "scan_id": scan_id, "status": "failed",
                              "error": message})  # fmt: skip
        return "failed", {}

    sbom_findings: list[Finding] = []
    sbom_summary: dict[str, Any] | None = None
    try:
        with ExitStack() as stack:
            with span("ingest", source_type=source_type):
                workspace = stack.enter_context(materialize(source_ref, ref=ref))
                ctx = detect_context(workspace)
            with span("dast_routes"):
                route_map = _extract_route_map(workspace)
            with span("reachability"):
                reach = analyze_or_none(workspace)
            with span("taint"):
                taint = taint_analyze_or_none(workspace)
            runnable: list[str] = []
            outcomes: list[ToolOutcome] = []
            for name in tools:
                if adapters[name].applies_to(ctx):
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

            # Supply-chain risk (plan §20.5): "syft" produces a document, not Findings, via the
            # normal tools loop above (already persisted as a raw artifact by `_store_raw` below,
            # exactly like any other tool's output) -- this reshapes that document into typosquat
            # Findings (folded into the same correlate/finalize pipeline as everything else) and a
            # JSON summary for the Dependencies screen. Best-effort: a corrupt SBOM or an
            # unreachable Scorecard/deps.dev must not fail the whole scan.
            if "syft" in raws:
                with span("sbom"):
                    sbom_findings, sbom_summary = _process_sbom(raws["syft"], reach)
    except IngestError as exc:
        log.warning("ingestion failed: %s", exc)
        return fail(str(exc))
    except Exception:
        log.exception("scan crashed")
        return fail("internal error while running the scan")

    # Correlate BEFORE redacting: redaction placeholders look identical and would over-merge.
    with span("correlate") as sp:
        correlated, stats = correlate([f for o in outcomes for f in o.findings] + sbom_findings)
        set_attributes(sp, raw=stats.raw, unique=stats.unique)
    with span("finalize"):
        ensure_fresh()
        verdicts: dict[str, Any] = {}
        if asset_id is not None:
            with sessions() as s:
                verdicts = repo.assistant_verdicts_for_asset(s, asset_id)
        findings = finalize(
            correlated,
            reach=reach,
            taint=taint,
            root=workspace,
            verdict_lookup=(lambda f: verdicts.get(f.fingerprint)) if verdicts else None,
        )
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
            repo.set_sbom_summary(s, scan_id, sbom_summary)
            if status == "completed" and ref is None and asset_id and sbom_summary:
                # The component inventory (plan §46.1): this project's SBOM is now this one.
                try:
                    inventory.record(
                        s, org_id=scan_org, asset_id=asset_id, scan_id=scan_id,
                        source=inventory.SCAN_SOURCE, packages=sbom_summary["packages"],
                    )  # fmt: skip
                except Exception:  # noqa: BLE001 - the inventory must not fail the scan
                    log.exception("inventory: could not record the SBOM of scan %s", scan_id)
                    s.rollback()
            repo.set_route_map(s, scan_id, route_map)
            repo.set_entrypoints(s, scan_id, _entrypoints(taint))
            repo.finish_scan(s, scan_id, status)
            counts = repo.severity_counts(s, scan_id)
            # Integrations (Week 51 task 2, plan §23): only for a real, full scan of the asset's
            # current state, the same condition that gates writing real Issue history above -- a
            # PR scan must not notify Slack or file a GitHub issue for something that might never
            # merge.
            if issues is not None and org_id is not None:
                try:
                    notify_scan_result(
                        s, org_id, source_label, scan_id, issues,
                        {f.id: f for f in findings},
                    )  # fmt: skip
                except Exception:  # noqa: BLE001 - a dying integration must not fail the scan
                    log.exception("integrations dispatch failed for scan %s", scan_id)
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
