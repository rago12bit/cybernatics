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

import shutil
from pathlib import Path

import pytest

from core.correlation.engine import fingerprint
from core.fixagent.verify import PatchApplyError, apply_patch, rerun_rule, rerun_scanners
from core.models import Category, Finding, Location, Taxonomy
from core.scan import ToolOutcome

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
