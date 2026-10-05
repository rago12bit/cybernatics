"""Targeted retests (plan §43.3: "when a single DAST template or a single rule can check an issue,
offer a targeted retest that re-runs only that check against that location").

- **A rule** (`kind="rule"`): for an Issue a code, secrets, IaC or dependency scanner found, check
  out the project's default branch again, copy only the Issue's file into an empty directory (same
  relative path), run only the tool that reported it there -- in its usual sandbox, with the whole
  repository's language context -- and look for that rule at that file. The Issue is still present
  if a finding has its fingerprint, or the same rule fires on the same file.
- **A DAST template** (`kind="dast"`): for an Issue a DAST campaign found, re-run only that Nuclei
  template (or ZAP's passive baseline, keeping only that alert) against that one URL -- only if the
  target's ownership verification still passes, through the same egress proxy a campaign uses.

The result decides a requested retest (`core.retest.service.decide_automatically`). A retest never
writes scan history: it has its own row (`RetestRun`), so it cannot become "the latest scan" or
close any other Issue.

Not offered for an Issue only a person or an imported report found: a tester retests those.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import Asset, FindingRow, IssueRow, RetestRun, Scan
from core.retest import service
from core.sla.policy import OPEN_STATES

log = logging.getLogger(__name__)

# Tools whose findings are about a file in the repository (not an image or an SBOM document).
FILE_TOOLS = frozenset(
    {"opengrep", "semgrep", "bandit", "gosec", "gitleaks", "checkov", "trivy", "osv-scanner"}
)
DAST_TOOLS = frozenset({"nuclei", "zap-baseline", "zap"})


@dataclass(frozen=True)
class Target:
    kind: str  # rule | dast
    tool: str
    rule: str
    location: str  # a repository-relative path, or a URL
    source_ref: str  # what to check out (a git URL or archive path), or the target URL

    def describe(self) -> str:
        what = "template" if self.kind == "dast" else "rule"
        return f"{self.tool} {what} {self.rule} against {self.location}"


@dataclass(frozen=True)
class Offer:
    target: Target | None
    reason: str | None = None  # why there is none


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _latest_occurrence(s: Session, issue_id: str) -> tuple[dict[str, Any], Scan] | None:
    row = s.execute(
        select(FindingRow.data, Scan)
        .join(Scan, Scan.id == FindingRow.scan_id)
        .where(FindingRow.issue_id == issue_id, Scan.source_type != "import")
        .order_by(Scan.created_at.desc(), FindingRow.pk.desc())
        .limit(1)
    ).first()
    return (row[0], row[1]) if row is not None else None


def offer(s: Session, issue: IssueRow) -> Offer:
    """What a targeted retest of this Issue would re-run, or why there is none."""
    if issue.state not in OPEN_STATES:
        return Offer(None, "The issue is not open.")
    found = _latest_occurrence(s, issue.id)
    if found is None:
        return Offer(None, "A person or an imported report found this; a tester retests it.")
    data, scan = found
    reported = list((data.get("evidence") or {}).get("reported_by") or [])
    rules: dict[str, list[str]] = (data.get("evidence") or {}).get("rule_ids") or {}
    loc = data.get("location") or {}
    if scan.source_type == "web":
        tool = next((t for t in reported if t in DAST_TOOLS and rules.get(t)), None)
        if tool is None:
            return Offer(None, "No single DAST template or alert reported this.")
        parts = urlsplit(scan.source_ref)
        url = f"{parts.scheme}://{loc.get('host') or parts.netloc}{loc.get('route') or parts.path}"
        return Offer(Target("dast", tool, rules[tool][0], url, scan.source_ref))
    tool = next((t for t in reported if t in FILE_TOOLS and rules.get(t)), None)
    path = str(loc.get("path") or "")
    if tool is None or not path:
        return Offer(None, "No single rule from a file scanner reported this.")
    native = repo.latest_native_snapshot_scan_id(s, scan.org_id, issue.asset_id)
    latest = s.get(Scan, native) if native else scan
    assert latest is not None
    return Offer(Target("rule", tool, rules[tool][0], path, latest.source_ref))


def start(s: Session, issue: IssueRow, *, actor: str) -> RetestRun:
    """Queue a targeted retest. Marks the retest requested first if nobody had."""
    o = offer(s, issue)
    if o.target is None:
        raise service.RetestError("action", o.reason or "No targeted retest for this issue.")
    busy = s.scalars(
        select(RetestRun).where(
            RetestRun.issue_id == issue.id, RetestRun.status.in_(("queued", "running"))
        )
    ).first()
    if busy is not None:
        raise service.RetestError("action", "A targeted retest of this issue is already running.")
    if issue.retest_status != "requested":
        service.act(s, issue, "request", actor=actor, note="Targeted retest started.")
    asset = s.get(Asset, issue.asset_id)
    assert asset is not None
    t = o.target
    run = RetestRun(
        org_id=asset.org_id, issue_id=issue.id, kind=t.kind, tool=t.tool, rule=t.rule[:300],
        location=t.location, source_ref=t.source_ref, status="queued", requested_by=actor,
    )  # fmt: skip
    s.add(run)
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=actor, action="issue.retest.targeted", target=issue.id,
        payload={"run_id": run.id, "tool": t.tool, "rule": t.rule, "location": t.location},
    )  # fmt: skip
    return run


# --- running --------------------------------------------------------------------------------------

Materialize = Callable[[str], AbstractContextManager[Path]]
Executor = Callable[[str, Path, Any], Any]  # (tool, target, repo context) -> ToolOutcome
DastRunner = Callable[[str, Target], list[Any]]  # (url, target) -> Findings


def _default_materialize(source: str) -> AbstractContextManager[Path]:
    from core.source import materialize

    return materialize(source)


def _default_executor(tool: str, target: Path, ctx: Any) -> Any:
    from core.scan import execute_tool

    return execute_tool(tool, target, ctx=ctx)


def _rule_check(
    t: Target, issue: IssueRow, materialize: Materialize, executor: Executor
) -> tuple[bool | None, str]:
    """(still present?, detail); None when the check itself could not run."""
    from core.correlation import correlate
    from core.scan import detect_context

    with materialize(t.source_ref) as ws, tempfile.TemporaryDirectory(prefix="bulwark-rt-") as tmp:
        src = (ws / t.location).resolve()
        if not src.is_relative_to(ws.resolve()):
            return None, "The location is outside the repository."
        if not src.is_file():
            return False, f"{t.location} no longer exists on the default branch."
        dest = Path(tmp) / t.location
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        outcome = executor(t.tool, Path(tmp), detect_context(ws))
        if getattr(outcome, "status", "ok") != "ok":
            return (
                None,
                f"{t.tool} did not finish: {getattr(outcome, 'error', None) or outcome.status}",
            )
        found, _ = correlate(list(outcome.findings))
    hits = [
        f for f in found
        if f.fingerprint == issue.fingerprint
        or (f.location.path == t.location and t.rule in f.evidence.rule_ids.get(t.tool, []))
    ]  # fmt: skip
    if hits:
        line = hits[0].location.start_line
        return True, f"{t.tool} rule {t.rule} still fires on {t.location}:{line}."
    return False, f"{t.tool} rule {t.rule} no longer fires on {t.location}."


def _default_dast(url: str, t: Target) -> list[Any]:
    from core.dast.adapters.nuclei import run_nuclei
    from core.dast.adapters.zap import run_zap_baseline
    from core.dast.proxy import BackgroundProxy, ProxyConfig

    host = urlsplit(url).hostname or url
    with BackgroundProxy(frozenset({host})) as proxy:
        cfg = ProxyConfig(host="host.docker.internal", port=proxy.port)
        if t.tool == "nuclei":
            return run_nuclei(url, proxy=cfg, template_ids=(t.rule,))
        return run_zap_baseline(url, proxy=cfg)


def _dast_check(
    s: Session, t: Target, issue: IssueRow, runner: DastRunner, verify: Callable[..., Any] | None
) -> tuple[bool | None, str]:
    from core.dast import ownership

    v = repo.get_asset_verification(s, issue.asset_id)
    if v is None:
        return None, "The target has no ownership verification on record."
    check = (verify or ownership.verify)(
        v.method, urlsplit(t.source_ref).netloc or t.source_ref, v.token,
        resolver=ownership.DnsPythonResolver(), fetcher=ownership.HttpxFetcher(),
    )  # fmt: skip
    repo.record_verification_check(s, v, ok=check.ok, error=check.error)
    if not check.ok:
        return None, f"Ownership verification failed: {check.error}"
    found = runner(t.location, t)
    hits = [f for f in found if t.rule in f.evidence.rule_ids.get(t.tool, [])]
    if hits:
        return True, f"{t.tool} {t.rule} still reports {t.location}."
    return False, f"{t.tool} {t.rule} no longer reports {t.location}."


def run(
    s: Session,
    run_id: str,
    *,
    materialize: Materialize | None = None,
    executor: Executor | None = None,
    dast: DastRunner | None = None,
    verify: Callable[..., Any] | None = None,
) -> RetestRun | None:
    """Run a queued targeted retest and decide the Issue's retest from it. Idempotent: a run that
    is no longer queued is left alone."""
    r = s.get(RetestRun, run_id)
    if r is None or r.status != "queued":
        return r
    issue = s.get(IssueRow, r.issue_id)
    if issue is None:
        r.status, r.detail, r.finished_at = "failed", "The issue no longer exists.", _now()
        s.commit()
        return r
    r.status, r.started_at = "running", _now()
    s.commit()
    t = Target(r.kind, r.tool, r.rule, r.location, r.source_ref)
    try:
        if r.kind == "dast":
            present, detail = _dast_check(s, t, issue, dast or _default_dast, verify)
        else:
            present, detail = _rule_check(
                t, issue, materialize or _default_materialize, executor or _default_executor
            )
    except Exception as exc:  # noqa: BLE001 - a broken run is a result, not a crash
        log.exception("targeted retest %s failed", run_id)
        present, detail = None, f"{type(exc).__name__}: {exc}"[:500]
    r.finished_at, r.detail = _now(), detail
    if present is None:
        r.status = "failed"
    else:
        r.status, r.result = "done", ("still_present" if present else "gone")
        service.decide_automatically(
            s, issue, still_reported=present, by=f"targeted retest ({t.tool} {t.rule})",
            detail=detail,
        )  # fmt: skip
    s.commit()
    return r


def runs(s: Session, issue_id: str, limit: int = 10) -> list[RetestRun]:
    return list(
        s.scalars(
            select(RetestRun)
            .where(RetestRun.issue_id == issue_id)
            .order_by(RetestRun.created_at.desc())
            .limit(limit)
        )
    )
