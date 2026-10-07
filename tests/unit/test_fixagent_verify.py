"""apply_patch, rerun_rule, rerun_scanners (plan §21.2) -- against a fake executor
(`tests/unit/test_pipeline.py::executor_from`'s pattern), so no real Docker container runs here.

`core.scan.scan()` always recomputes `Finding.fingerprint` via `core.correlation.engine.fingerprint`
(confirmed before writing these tests -- every finding goes through `correlate()`, even a lone,
unmerged one, and `correlate()` unconditionally overwrites `.fingerprint`). So "the same defect
still there" is modeled here by giving two Finding objects the IDENTICAL path/snippet/CWE/rule-ids
that `fingerprint()` actually hashes, not by hand-assigning a fingerprint string that scan() would
discard anyway.
"""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Any

import pytest

from core.adapters.bandit import BanditAdapter
from core.correlation.engine import fingerprint
from core.fixagent.verify import (
    Known,
    PatchApplyError,
    apply_patch,
    flagged_key,
    rerun_rule,
    rerun_scanners,
)
from core.models import Category, Finding, Location, Taxonomy
from core.scan import ToolOutcome, scan

SRC = 'def get_user(uid):\n    return db.execute("SELECT * FROM users WHERE id=" + uid)\n'
SNIPPET = 'return db.execute("SELECT * FROM users WHERE id=" + uid)'
PATCH = (
    "--- a/app/users.py\n+++ b/app/users.py\n@@ -1,2 +1,2 @@\n"
    " def get_user(uid):\n"
    '-    return db.execute("SELECT * FROM users WHERE id=" + uid)\n'
    '+    return db.execute("SELECT * FROM users WHERE id=?", (uid,))\n'
)


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    d = tmp_path / "repo"
    (d / "app").mkdir(parents=True)
    (d / "app" / "users.py").write_text(SRC)
    return d


def _sqli_finding() -> Finding:
    """The original finding, with its real, correlate()-computed fingerprint."""
    f = Finding(
        "f1", "SQL injection", "d", Location("app/users.py", 2, 2, SNIPPET),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip
    f.evidence.reported_by = ["bandit"]
    f.evidence.rule_ids = {"bandit": ["B608"]}
    f.fingerprint = fingerprint(f)
    return f


def _same_shape_finding() -> Finding:
    """A freshly-scanned finding with the identical path/snippet/CWE/rule-ids as `_sqli_finding` --
    real code would hash to the SAME fingerprint via correlate(), so passing this through the fake
    executor (which skips correlate() itself) means the test must fingerprint it the same way."""
    f = Finding(
        "f1", "SQL injection", "d", Location("app/users.py", 2, 2, SNIPPET),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip
    f.evidence.reported_by = ["bandit"]
    f.evidence.rule_ids = {"bandit": ["B608"]}
    f.fingerprint = fingerprint(f)  # what scan()'s own correlate() would compute for it too
    return f


def executor_from(table: dict[str, ToolOutcome]):  # type: ignore[no-untyped-def]
    def run(names: list[str], target: Path) -> list[ToolOutcome]:
        return [table[n] for n in names]

    return run


_NEEDS_PATCH = pytest.mark.skipif(shutil.which("patch") is None, reason="needs the `patch` tool")


@_NEEDS_PATCH
def test_apply_patch_writes_the_new_content_for_real(checkout: Path) -> None:
    apply_patch(checkout, PATCH)
    assert "id=?" in (checkout / "app" / "users.py").read_text()


@_NEEDS_PATCH
def test_apply_patch_raises_on_a_patch_that_does_not_match_the_code(checkout: Path) -> None:
    bad = PATCH.replace("get_user(uid):", "get_user_typo(uid):")
    with pytest.raises(PatchApplyError):
        apply_patch(checkout, bad)


def test_rerun_rule_passes_once_the_fingerprint_is_gone(checkout: Path) -> None:
    finding = _sqli_finding()
    executor = executor_from({"bandit": ToolOutcome("bandit", "ok", findings=[])})
    step = rerun_rule(checkout, finding, "bandit", executor=executor)
    assert step.passed and step.name == "rerun_rule"


def test_rerun_rule_fails_when_the_same_defect_still_turns_up(checkout: Path) -> None:
    finding = _sqli_finding()
    still_there = _same_shape_finding()
    executor = executor_from({"bandit": ToolOutcome("bandit", "ok", findings=[still_there])})
    step = rerun_rule(checkout, finding, "bandit", executor=executor)
    assert not step.passed


def test_rerun_scanners_passes_when_nothing_new_appears_on_the_changed_file(checkout: Path) -> None:
    pre_existing = (
        _sqli_finding()
    )  # the very finding this patch is fixing: expected in the baseline
    executor = executor_from({"bandit": ToolOutcome("bandit", "ok", findings=[pre_existing])})
    step = rerun_scanners(
        checkout,
        ["app/users.py"],
        ["bandit"],
        frozenset({pre_existing.fingerprint}),
        executor=executor,
    )
    assert step.passed


def test_rerun_scanners_fails_on_a_genuinely_new_finding(checkout: Path) -> None:
    new_issue = Finding(
        "f3", "hardcoded secret", "d", Location("app/users.py", 1, 1, "AKIA123"), Taxonomy(Category.SECRETS)
    )  # fmt: skip
    executor = executor_from({"bandit": ToolOutcome("bandit", "ok", findings=[new_issue])})
    step = rerun_scanners(checkout, ["app/users.py"], ["bandit"], frozenset(), executor=executor)
    assert not step.passed and "hardcoded secret" in step.detail


def test_rerun_scanners_ignores_findings_on_files_the_patch_never_touched(checkout: Path) -> None:
    (checkout / "other.py").write_text("y = 1\n")
    elsewhere = Finding(
        "f4",
        "unrelated elsewhere",
        "d",
        Location("other.py", 1, 1, "y = 1"),
        Taxonomy(Category.SAST),
    )
    executor = executor_from({"bandit": ToolOutcome("bandit", "ok", findings=[elsewhere])})
    step = rerun_scanners(checkout, ["app/users.py"], ["bandit"], frozenset(), executor=executor)
    assert step.passed  # out of scope for this patch's own regression check


# --- which finding is which across a patch, on recorded real Bandit output -------------------------
#
# Bandit quotes three lines around a finding, so a patch to line 6 changes the fingerprint of the
# untouched finding on line 7 (seen live in Week 76 on PyCQA/bandit#2). tests/fixtures/fixagent/
# bandit-neighbours.json has real Bandit 1.7.10 output for each version of one small file.

RECORDED = json.loads(
    (Path(__file__).parent.parent / "fixtures/fixagent/bandit-neighbours.json").read_text()
)
PATH = "app/crypto.py"


def _tree(tmp_path: Path, name: str) -> Path:
    d = tmp_path / f"{name}-{uuid.uuid4().hex[:8]}"
    (d / "app").mkdir(parents=True)
    (d / PATH).write_text(RECORDED[name]["source"])
    return d


def _bandit(name: str):  # type: ignore[no-untyped-def]
    findings = BanditAdapter().parse(json.dumps(RECORDED[name]["bandit"]).encode())
    return executor_from({"bandit": ToolOutcome("bandit", "ok", findings, 0, 1.0)})


def _before(tmp_path: Path, name: str = "before") -> list[Finding]:
    """The pre-patch scan, fingerprinted by the real correlate() as the stored baseline was."""
    return scan(_tree(tmp_path, name), ["bandit"], executor=_bandit(name)).findings


def _at(findings: list[Finding], rule: str, line: int) -> Finding:
    return next(
        f for f in findings
        if f.evidence.rule_ids.get("bandit") == [rule] and f.location.start_line == line
    )  # fmt: skip


def _verify(tmp_path: Path, after: str, before: str = "before", line: int = 6) -> tuple[Any, Any]:
    base = _before(tmp_path, before)
    return _verify_against(tmp_path, base, _at(base, "B304", line), before, after)


def _verify_against(
    tmp_path: Path, base: list[Finding], target: Finding, before: str, after: str
) -> tuple[Any, Any]:
    checkout = _tree(tmp_path, after)
    original = RECORDED[before]["source"]
    known = [Known.of(f) for f in base]
    rule = rerun_rule(checkout, target, "bandit", _bandit(after), original=original, known=known)
    scanners = rerun_scanners(
        checkout, [PATH], ["bandit"], frozenset(f.fingerprint for f in base), _bandit(after),
        known=known, originals={PATH: original},
    )  # fmt: skip
    return rule, scanners


def test_the_recording_shows_the_problem(tmp_path: Path) -> None:
    base, fixed = _before(tmp_path), _before(tmp_path, "fixed")
    # The untouched line-7 finding has a new fingerprint after line 6 changed...
    assert _at(base, "B304", 7).fingerprint != _at(fixed, "B304", 7).fingerprint
    # ...so comparing fingerprints alone, as before, calls it a regression.
    old = rerun_scanners(
        _tree(tmp_path, "fixed"), [PATH], ["bandit"],
        frozenset(f.fingerprint for f in base), _bandit("fixed"),
    )  # fmt: skip
    assert not old.passed and "1 new finding(s)" in old.detail


def test_a_fix_next_to_another_finding_passes(tmp_path: Path) -> None:
    rule, scanners = _verify(tmp_path, "fixed")
    assert rule.passed, rule.detail
    assert scanners.passed, scanners.detail


def test_editing_only_the_line_next_to_it_is_not_a_fix(tmp_path: Path) -> None:
    # A comment above line 6 moves the finding to line 7 and changes its quoted snippet, so its
    # fingerprint changes -- but the flagged line still reads the same.
    base = _before(tmp_path)
    after = _before(tmp_path, "neighbour_only")
    assert _at(base, "B304", 6).fingerprint not in {f.fingerprint for f in after}
    rule, _ = _verify(tmp_path, "neighbour_only")
    assert not rule.passed and "still flags" in rule.detail


def test_a_genuinely_new_finding_still_fails(tmp_path: Path) -> None:
    rule, scanners = _verify(tmp_path, "regression")
    assert rule.passed  # the cipher is gone...
    assert not scanners.passed and "1 new finding(s)" in scanners.detail  # ...for an eval()
    assert "eval" in scanners.detail


def test_of_two_identical_flagged_lines_fixing_one_is_seen(tmp_path: Path) -> None:
    rule, scanners = _verify(tmp_path, "twice_one_fixed", before="twice_before")
    assert rule.passed, rule.detail
    assert scanners.passed, scanners.detail


def test_a_rule_correlation_moves_to_the_neighbour_is_not_a_regression(tmp_path: Path) -> None:
    # Correlation folds the SHA1 finding (B303, line 7) into the nearest cipher finding: line 8's
    # before the fix, line 10's after it -- so the untouched line-10 finding gains a rule.
    base, fixed = _before(tmp_path, "drift_before"), _before(tmp_path, "drift_fixed")
    assert _at(base, "B304", 10).evidence.rule_ids == {"bandit": ["B304"]}
    after = next(f for f in fixed if f.location.start_line == 10)
    assert after.evidence.rule_ids == {"bandit": ["B303", "B304"]}
    target = next(f for f in base if f.location.start_line == 8)
    rule, scanners = _verify_against(tmp_path, base, target, "drift_before", "drift_fixed")
    assert rule.passed, rule.detail
    assert scanners.passed, scanners.detail


def test_a_new_defect_folded_into_an_untouched_finding_still_fails(tmp_path: Path) -> None:
    # The patch fixes line 6 but adds an MD5 call under the untouched cipher line; correlation
    # folds the new B324 into that finding, which still reads the same -- only the rule count shows
    # the file now has a rule firing that it did not before.
    folded = _before(tmp_path, "folded_regression")
    assert [
        f.evidence.rule_ids for f in folded if "B304" in f.evidence.rule_ids.get("bandit", [])
    ] == [{"bandit": ["B304", "B324"]}]
    rule, scanners = _verify(tmp_path, "folded_regression")
    assert rule.passed
    assert not scanners.passed and "1 new finding(s)" in scanners.detail


def test_another_rule_on_the_same_line_is_not_the_same_defect(tmp_path: Path) -> None:
    # Constructed, not recorded: the flagged line still reads the same, but only a different rule
    # fires on it now. The original defect is gone (rerun_rule); the other rule is a new finding,
    # which rerun_scanners' rule count reports.
    def at_line_2(rule: str) -> Finding:
        f = Finding("x", "t", "d", Location("app/users.py", 2, 2, SNIPPET),
                    Taxonomy(Category.SAST, cwe=("CWE-89",)))  # fmt: skip
        f.evidence.reported_by, f.evidence.rule_ids = ["bandit"], {"bandit": [rule]}
        f.fingerprint = fingerprint(f)
        return f

    target, other = at_line_2("B608"), at_line_2("B610")
    run = executor_from({"bandit": ToolOutcome("bandit", "ok", [other], 1, 1.0)})
    checkout = tmp_path / "repo"
    (checkout / "app").mkdir(parents=True)
    (checkout / "app/users.py").write_text(SRC)
    rule = rerun_rule(checkout, target, "bandit", run, original=SRC, known=[Known.of(target)])
    assert rule.passed, rule.detail
    scanners = rerun_scanners(checkout, ["app/users.py"], ["bandit"], frozenset({target.fingerprint}),
                              run, known=[Known.of(target)], originals={"app/users.py": SRC})  # fmt: skip
    assert not scanners.passed


def test_without_a_line_to_read_only_the_fingerprint_counts() -> None:
    assert flagged_key(PATH, "sast", None, 6, 6) is None  # no source
    assert flagged_key(PATH, "sast", "x = 1\n", 0, 0) is None  # a file-level finding
    assert flagged_key(PATH, "sast", "x = 1\n", 9, 9) is None  # past the end
    assert flagged_key(PATH, "sast", "\n\n", 1, 2) is None  # blank
    a = flagged_key(PATH, "sast", "  x  =  1\n", 1, 1)
    assert a == flagged_key(PATH, "sast", "x = 1\n", 1, 1)  # whitespace is not identity
    assert a != flagged_key("other.py", "sast", "x = 1\n", 1, 1)
    assert a != flagged_key(PATH, "secrets", "x = 1\n", 1, 1)
