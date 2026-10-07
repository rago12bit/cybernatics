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

**Which finding is which, across a patch.** A code finding's fingerprint hashes the snippet the
scanner quoted and the rules that fired, and neither is stable across a patch to a nearby line:
Bandit quotes three lines, so editing line 30 changes the fingerprint of an untouched finding on
line 32; and correlation folds a rule into the nearest finding of the same weakness, so when line
30's finding goes, the B303 that sat with it moves to line 32's (both seen live in Week 76 on
PyCQA/bandit#2). Compared by fingerprint alone, that untouched finding looks like a regression,
while an edit to the line next to the one being fixed could make the fixed finding look gone.

So both steps also recognise a finding by *where it is*: the path, the category and the
whitespace-normalised text of the lines it flags, read from the file itself before and after the
patch (neighbouring lines do not enter it; a line that moved keeps it), sharing at least one rule.
And no rule may fire on a changed file more often than it did before. A rule that drifted between
neighbours passes both; a vulnerable call moved to another line does not, since its text is new.
Places are counted, so of two identical flagged lines, fixing one is still seen.
"""

from __future__ import annotations

import hashlib
import subprocess
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.models import Finding
from core.scan import Executor, scan, threaded_executor


class PatchApplyError(Exception):
    """The patch (already schema-validated by `core.llm.contract.validate_patch`) did not apply
    cleanly to this checkout -- in practice this means the checkout drifted since the finding was
    gathered (a concurrent commit to the file), never a shape problem in the patch itself."""


def apply_patch(checkout: Path, patch: str) -> None:
    # --fuzz=0: GNU patch's default fuzz (2) will silently apply a hunk over mismatched
    # context, which is exactly the drifted-checkout case this function must catch.
    proc = subprocess.run(
        ["patch", "-p1", "--forward", "--no-backup-if-mismatch", "--fuzz=0"],
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


MAX_FLAGGED_LINES = 30


@dataclass(frozen=True)
class Known:
    """A finding that was on a changed file before the patch, as the verifier needs it to recognise
    the same finding afterwards (`core.fixagent.store.baseline_findings_for`)."""

    path: str
    fingerprint: str
    category: str
    rule_ids: tuple[str, ...]
    start_line: int
    end_line: int

    @staticmethod
    def of(f: Finding) -> Known:
        return Known(
            f.location.path, f.fingerprint, f.taxonomy.category.value, _rules(f),
            f.location.start_line, f.location.end_line,
        )  # fmt: skip

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> Known:
        return Known(
            str(d["path"]), str(d.get("fingerprint", "")), str(d.get("category", "")),
            tuple(sorted(str(r) for r in d.get("rule_ids") or ())),
            int(d.get("start_line") or 0), int(d.get("end_line") or 0),
        )  # fmt: skip


def _rules(f: Finding) -> tuple[str, ...]:
    return tuple(sorted({r for rules in f.evidence.rule_ids.values() for r in rules}))


def flagged_key(path: str, category: str, source: str | None, start: int, end: int) -> str | None:
    """Where a finding is (module docstring), or None when there is nothing to anchor on: no source,
    no line (a file-level finding), or only blank lines -- then only the fingerprint can say whether
    it is the same finding."""
    if source is None or start < 1:
        return None
    lines = source.splitlines()
    if start > len(lines):
        return None
    end = max(start, min(end, start + MAX_FLAGGED_LINES - 1, len(lines)))
    text = "\n".join(" ".join(line.split()) for line in lines[start - 1 : end])
    if not text.strip():
        return None
    return hashlib.sha256(f"{path}|{category}|{text}".encode()).hexdigest()


@dataclass(frozen=True)
class _Seen:
    path: str
    place: str | None
    rules: frozenset[str]

    def same(self, other: _Seen) -> bool:
        return (
            self.place is not None and self.place == other.place and bool(self.rules & other.rules)
        )


def _seen(f: Finding, source: str | None) -> _Seen:
    loc = f.location
    place = flagged_key(loc.path, f.taxonomy.category.value, source, loc.start_line, loc.end_line)
    return _Seen(loc.path, place, frozenset(_rules(f)))


def _seen_known(k: Known, originals: Mapping[str, str]) -> _Seen:
    place = flagged_key(k.path, k.category, originals.get(k.path), k.start_line, k.end_line)
    return _Seen(k.path, place, frozenset(k.rule_ids))


def _read(checkout: Path, path: str) -> str | None:
    p = checkout / path
    return p.read_text(errors="replace") if p.is_file() else None


def rerun_rule(
    checkout: Path,
    finding: Finding,
    tool: str,
    executor: Executor = threaded_executor,
    *,
    original: str | None = None,
    known: Sequence[Known] = (),
) -> VerificationStep:
    """Did the SAME defect still turn up when only the originating tool runs again? The same by
    fingerprint, or by the flagged-lines key: the rule still fires on lines that read as they did
    before the patch (`original` is the file's text before it). Of several identical flagged lines
    (`known`, the file's findings before the patch), the defect is gone when fewer remain.

    A clean pass here means this one rule no longer objects to this one location -- it says nothing
    about every other rule, which `rerun_scanners` covers separately. `executor` is injectable for
    the same reason `core.scan.scan` already makes it a parameter: a real scan spins up real Docker
    containers, which a unit test should not have to do (see
    `tests/unit/test_pipeline.py::executor_from` for the established fake)."""
    result = scan(checkout, [tool], executor=executor)
    still_present = any(f.fingerprint == finding.fingerprint for f in result.findings)
    path = finding.location.path
    target = _seen(finding, original)
    if not still_present and target.place is not None and target.rules:
        originals = {path: original} if original is not None else {}
        before = max(1, sum(1 for k in known if target.same(_seen_known(k, originals))))
        after_text = _read(checkout, path)
        after = sum(
            1 for f in result.findings
            if f.location.path == path and target.same(_seen(f, after_text))
        )  # fmt: skip
        still_present = after >= before
    if still_present:
        return VerificationStep("rerun_rule", False, f"{tool} still flags this finding")
    return VerificationStep("rerun_rule", True, f"{tool} no longer flags this finding")


def rerun_scanners(
    checkout: Path,
    changed_paths: list[str],
    tools: list[str],
    baseline_fingerprints: frozenset[str],
    executor: Executor = threaded_executor,
    *,
    known: Sequence[Known] = (),
    originals: Mapping[str, str] | None = None,
) -> VerificationStep:
    """Any finding on a changed file, after the patch, that was NOT already there before it -- a
    real regression the patch introduced, distinct from a pre-existing, untouched issue on the same
    file that has nothing to do with this fix. Already there: its fingerprint is in
    `baseline_fingerprints` (the pre-patch scan's findings on these paths); or it is where one of
    `known` (those same findings, read against `originals`, the files' text before the patch) was,
    sharing a rule with it, and none of its rules fires more often on its file than before (module
    docstring). Each known finding accounts for one finding after the patch. The finding this
    patch was meant to fix is expected to vanish, not reappear as something to tolerate
    (`rerun_rule` checks that)."""
    result = scan(checkout, tools, executor=executor)
    on_changed = [f for f in result.findings if f.location.path in changed_paths]
    after_text = {p: _read(checkout, p) for p in changed_paths}
    pool = [_seen_known(k, originals or {}) for k in known]
    free = [True] * len(pool)
    budget = Counter((s.path, r) for s in pool for r in s.rules)

    def take_place(s: _Seen) -> bool:
        for i, k in enumerate(pool):
            if free[i] and k.same(s):
                free[i] = False
                return True
        return False

    seen = [(f, _seen(f, after_text.get(f.location.path))) for f in on_changed]
    for f, s in seen:  # the same fingerprint: the same finding
        if f.fingerprint in baseline_fingerprints:
            take_place(s)
            budget.subtract((s.path, r) for r in s.rules)
    new = []
    for f, s in seen:
        if f.fingerprint in baseline_fingerprints:
            continue
        if all(budget[(s.path, r)] > 0 for r in s.rules) and take_place(s):
            budget.subtract((s.path, r) for r in s.rules)
        else:
            new.append(f)
    if new:
        titles = ", ".join(sorted({f.title for f in new})[:5])
        return VerificationStep("rerun_scanners", False, f"{len(new)} new finding(s): {titles}")
    return VerificationStep("rerun_scanners", True, "no new findings on the changed file(s)")
