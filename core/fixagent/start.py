"""Starting the verified-fix agent for one Issue (plan §21.2), shared by the API and the rules
engine's "request a verified fix" action (plan §45), so both refuse the same things for the same
reasons: no completed scan, no occurrence in it, no scanner to rerun, or too many runs already in
progress for the organization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from core.fixagent import client as fixagent_client
from core.fixagent import store as fixagent_store
from core.fixagent.limits import WorkflowLimits
from core.models import finding_from_dict
from core.persistence import repo
from core.persistence.models import Asset


class FixStartError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Started:
    run_id: str
    workflow_id: str


async def start(
    s: Session,
    org_id: str,
    asset: Asset,
    issue_id: str,
    *,
    run_tests: bool = False,
    test_image: str | None = None,
    test_command: str | None = None,
) -> Started:
    scan = repo.latest_scan_for_asset(s, asset.id, org_id=org_id)
    if scan is None:
        raise FixStartError(409, "no completed scan for this asset")
    finding_doc = repo.get_issue_finding(s, issue_id, scan.id)
    if finding_doc is None:
        raise FixStartError(409, "this issue has no occurrence in the latest scan")
    finding = finding_from_dict(
        {k: v for k, v in finding_doc.items() if k not in ("scan_id", "issue")}
    )
    tool = (
        finding.evidence.reported_by[0]
        if finding.evidence.reported_by
        else next(iter(finding.evidence.rule_ids), "")
    )
    if not tool:
        raise FixStartError(409, "could not tell which scanner originally reported this finding")

    limits = WorkflowLimits.from_env()
    if fixagent_store.count_running_for_org(s, org_id) >= limits.max_concurrent_per_org:
        raise FixStartError(
            429,
            f"too many verified-fix runs already in progress for this organization "
            f"(max {limits.max_concurrent_per_org})",
        )

    verified_owner = scan.github_installation_id is not None
    run_tests_spec: dict[str, Any] | None = None
    if run_tests and verified_owner:
        if not test_image or not test_command:
            raise FixStartError(
                422, "test_image and test_command are required when run_tests is true"
            )
        run_tests_spec = {"image": test_image, "command": test_command}
    # run_tests without a verified-owner asset is silently downgraded to "no tests," not a 4xx:
    # asking for an opt-in you don't qualify for yet is a normal request, not an error (plan §21.2:
    # "hardened Docker for now, verified-owner repositories only").

    workflow_id = fixagent_client.new_workflow_id(issue_id)
    run = fixagent_store.create_run(s, org_id, issue_id, workflow_id)
    baseline = fixagent_store.baseline_fingerprints_for(s, scan.id, finding.location.path)
    try:
        await fixagent_client.start_verified_fix(
            run.id,
            workflow_id,
            org_id,
            issue_id,
            finding.to_dict(),
            scan.source_ref,
            scan.ref,
            tool,
            baseline,
            scan.github_repo,
            scan.github_installation_id,
            run_tests_spec,
            limits,
            baseline_findings=fixagent_store.baseline_findings_for(
                s, scan.id, finding.location.path
            ),
        )
    except Exception as exc:  # noqa: BLE001 - Temporal unreachable, or any other startup failure
        raise FixStartError(503, f"could not start the verified-fix workflow: {exc}") from exc
    return Started(run_id=run.id, workflow_id=workflow_id)
