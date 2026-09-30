"""Apply a proposed patch to a real checkout, then verify it (plan §21.2): rerun the originating
rule, rerun every applicable scanner on the whole checkout, optionally run the project's own tests.
Each function here is what `core/fixagent/workflow.py` calls as a Temporal activity -- kept as
plain, directly-testable functions so the workflow layer is a thin orchestration shell, not where
the actual logic lives.

"Rerun scanners on changed files" (the plan's own wording) is implemented as a full `core.scan.scan`
of the whole patched checkout, not a new "scan only these files" mode: nothing in this codebase can
scope a scan to a file subset today (confirmed before writing this -- `ToolAdapter.applies_to`
filters by language, not by a changed-file list), and some rules need cross-file context a
single-file scan would give up for a real correctness loss. The result is filtered down to findings
on the *changed* file(s) plus a same-fingerprint check against the pre-patch baseline, which is
functionally "changed files" without inventing new scanning infrastructure for it.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from core.models import Finding
from core.scan import Executor, scan, threaded_executor


class PatchApplyError(Exception):
    """The patch (already schema-validated by `core.llm.contract.validate_patch`) did not apply
    cleanly to this checkout -- in practice this means the checkout drifted since the finding was
    gathered (a concurrent commit to the file), never a shape problem in the patch itself."""


def apply_patch(checkout: Path, patch: str) -> None:
    proc = subprocess.run(
        ["patch", "-p1", "--forward", "--no-backup-if-mismatch"],
        input=patch,
        capture_output=True,
        text=True,
        cwd=checkout,
        timeout=30,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise PatchApplyError(f"patch did not apply cleanly: {detail}")


@dataclass(frozen=True)
class VerificationStep:
    name: str  # "rerun_rule" | "rerun_scanners" | "run_tests"
    passed: bool
    detail: str


def rerun_rule(
    checkout: Path, finding: Finding, tool: str, executor: Executor = threaded_executor
) -> VerificationStep:
    """Did the SAME defect (by fingerprint) still turn up when only the originating tool runs
    again? A clean pass here means this one rule no longer objects to this one location -- it says
    nothing about every other rule, which `rerun_scanners` covers separately. `executor` is
    injectable for the same reason `core.scan.scan` already makes it a parameter: a real scan spins
    up real Docker containers, which a unit test should not have to do (see
    `tests/unit/test_pipeline.py::executor_from` for the established fake)."""
    result = scan(checkout, [tool], executor=executor)
    still_present = any(f.fingerprint == finding.fingerprint for f in result.findings)
    if still_present:
        return VerificationStep("rerun_rule", False, f"{tool} still flags this finding")
    return VerificationStep("rerun_rule", True, f"{tool} no longer flags this finding")


def rerun_scanners(
    checkout: Path,
    changed_paths: list[str],
    tools: list[str],
    baseline_fingerprints: frozenset[str],
    executor: Executor = threaded_executor,
) -> VerificationStep:
    """Any finding on a changed file, after the patch, whose fingerprint was NOT already present
    before the patch (`baseline_fingerprints`: the pre-patch scan's own findings restricted to these
    paths) -- a real regression the patch introduced, distinct from a pre-existing, untouched issue
    on the same file that has nothing to do with this fix. The finding this patch was meant to fix
    is expected to vanish, not reappear in `baseline_fingerprints` as something to tolerate."""
    result = scan(checkout, tools, executor=executor)
    on_changed = [f for f in result.findings if f.location.path in changed_paths]
    new = [f for f in on_changed if f.fingerprint not in baseline_fingerprints]
    if new:
        titles = ", ".join(sorted({f.title for f in new})[:5])
        return VerificationStep("rerun_scanners", False, f"{len(new)} new finding(s): {titles}")
    return VerificationStep("rerun_scanners", True, "no new findings on the changed file(s)")
