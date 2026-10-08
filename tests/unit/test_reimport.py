"""The reimport decision (Week 54 task 3, plan §42.1, ADR-0040): example cases for each rule in the
plan, then property-based tests that replay random sequences of imports into two Tests and compare
the engine against an independent oracle built from plain set arithmetic -- "generated report
sequences with known ground truth" (plan §60), the defence against risk R20 (reimport bugs
silently closing or reopening issues)."""

from __future__ import annotations

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from core.correlation import correlate
from core.imports.reimport import ReimportPlan, plan_reimport
from core.issues import ExistingIssue, State, match_keys
from core.models import Category, Finding, Location, Severity, Taxonomy


def defect(n: int) -> Finding:
    """A distinct code defect per `n`: its own file and snippet, far enough apart that correlate()
    never merges two of them into one finding."""
    snippet = f"danger_{n}(request)"
    f = Finding(
        id=f"semgrep:rule{n}:app/mod{n}.py:10",
        title=f"defect {n}",
        description="d",
        location=Location(f"app/mod{n}.py", 10, 10, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = ["semgrep"]
    f.evidence.rule_ids = {"semgrep": [f"rule{n}"]}
    return f


def file_of(*ns: int) -> list[Finding]:
    merged, _ = correlate([defect(n) for n in ns])
    return merged


class World:
    """An in-memory stand-in for the database: Issues plus each Test's latest snapshot. It applies
    a plan with `ReimportPlan.resulting_states`, the same mapping the real writer uses."""

    def __init__(self) -> None:
        self.issues: dict[str, ExistingIssue] = {}
        self.snapshots: dict[str, set[str]] = {}
        self._ids = (f"issue-{i}" for i in itertools.count())

    def import_into(
        self, test: str, defects: set[int], *, close_missing: bool = True
    ) -> ReimportPlan:
        findings = file_of(*sorted(defects))
        other_live = set().union(*(s for t, s in self.snapshots.items() if t != test))
        plan = plan_reimport(
            findings,
            list(self.issues.values()),
            previous_issue_ids=self.snapshots.get(test, set()),
            other_live_issue_ids=other_live,
            close_missing=close_missing,
            new_issue_id=lambda: next(self._ids),
        )
        states = plan.resulting_states()
        for f, u in zip(findings, plan.updates, strict=True):
            assert u.issue_id is not None
            if u.issue_id not in self.issues:
                keys = match_keys(f)
                self.issues[u.issue_id] = ExistingIssue(
                    u.issue_id, keys.category, keys.primary, keys.fallback, "new"
                )
        for issue_id, state in states.items():
            old = self.issues[issue_id]
            self.issues[issue_id] = ExistingIssue(
                old.id, old.category, old.fingerprint, old.fallback_fingerprint, state
            )
        self.snapshots[test] = {u.issue_id for u in plan.updates if u.issue_id}
        return plan

    def state(self, issue_id: str) -> State:
        return self.issues[issue_id].state


# --- the plan's rules, one example each -------------------------------------------------------


def test_import_is_reimport_with_an_empty_history() -> None:
    plan = World().import_into("nessus", {1, 2, 3})
    assert plan.counts == {"new": 3, "unchanged": 0, "reopened": 0, "closed": 0, "detached": 0, "held": 0}


def test_the_same_report_again_changes_nothing() -> None:
    w = World()
    w.import_into("nessus", {1, 2, 3})
    plan = w.import_into("nessus", {1, 2, 3})
    assert plan.counts == {"new": 0, "unchanged": 3, "reopened": 0, "closed": 0, "detached": 0, "held": 0}


def test_a_defect_the_file_stops_reporting_is_closed() -> None:
    w = World()
    first = w.import_into("nessus", {1, 2, 3})
    plan = w.import_into("nessus", {1, 2})
    assert plan.counts["closed"] == 1 and plan.counts["unchanged"] == 2
    gone = set(first.new_issue_ids) - {u.issue_id for u in plan.updates}
    assert set(plan.closed_issue_ids) == gone
    assert all(w.state(i) == "fixed" for i in gone)


def test_a_closed_defect_that_comes_back_is_reopened_not_new() -> None:
    w = World()
    w.import_into("nessus", {1, 2})
    w.import_into("nessus", {1})  # 2 closed
    plan = w.import_into("nessus", {1, 2})
    assert plan.counts == {"new": 0, "unchanged": 1, "reopened": 1, "closed": 0, "detached": 0, "held": 0}
    assert w.state(plan.reopened_issue_ids[0]) == "reintroduced"


def test_one_tools_report_cannot_close_another_tools_findings() -> None:
    w = World()
    w.import_into("burp", {10, 11})
    plan = w.import_into("nessus", {1, 2})  # nessus never reported 10/11
    assert plan.counts["closed"] == 0
    assert all(w.state(i) != "fixed" for i in w.issues)


def test_a_defect_another_source_still_reports_is_detached_not_closed() -> None:
    w = World()
    w.import_into("burp", {1, 2})
    w.import_into("nessus", {1, 2})
    plan = w.import_into("nessus", {1})  # nessus drops 2; burp still reports it
    assert plan.counts["closed"] == 0 and plan.counts["detached"] == 1
    assert w.state(plan.detached_issue_ids[0]) != "fixed"


def test_close_missing_off_only_adds() -> None:
    w = World()
    w.import_into("nessus", {1, 2, 3})
    plan = w.import_into("nessus", {1}, close_missing=False)
    assert plan.counts["closed"] == 0 and plan.counts["detached"] == 0
    assert all(w.state(i) != "fixed" for i in w.issues)


def test_the_same_defect_twice_in_one_file_is_one_issue() -> None:
    # Two findings with one fingerprint, as a raw (un-correlated) report can contain: `sync`
    # classifies the second against the Issue the first just created and calls it "open", so a
    # per-finding tally would say 1 new + 1 unchanged for a single new defect.
    (f,) = file_of(1)
    plan = plan_reimport([f, f], [], previous_issue_ids=(), new_issue_id=iter(["x", "y"]).__next__)
    assert plan.counts["new"] == 1 and plan.counts["unchanged"] == 0
    assert len(plan.updates) == 2 and plan.updates[0].issue_id == plan.updates[1].issue_id


def test_an_issue_that_is_already_fixed_is_not_closed_again() -> None:
    w = World()
    w.import_into("nessus", {1, 2})
    w.import_into("nessus", {1})  # 2 fixed
    plan = w.import_into("nessus", {1})
    assert plan.counts["closed"] == 0 and plan.closed_issue_ids == ()


# --- ground truth over random sequences ---------------------------------------------------------

TESTS = st.sampled_from(["A", "B"])
DEFECTS = st.sets(st.integers(min_value=0, max_value=7))
SEQUENCES = st.lists(st.tuples(TESTS, DEFECTS), min_size=1, max_size=12)


@settings(max_examples=250, deadline=None)
@given(SEQUENCES)
def test_counts_match_an_independent_oracle_when_every_import_closes_missing(
    sequence: list[tuple[str, set[int]]],
) -> None:
    """With close_missing on, an Issue is live exactly when some Test's current snapshot reports it,
    so every count is plain set arithmetic over defect numbers -- no engine code involved."""
    w = World()
    snap: dict[str, set[int]] = {}  # the oracle's own record: defect numbers, not issue ids
    seen: set[int] = set()
    for test, defects in sequence:
        other = set().union(*(s for t, s in snap.items() if t != test))
        prev = snap.get(test, set())
        live_before = prev | other
        plan = w.import_into(test, defects)

        assert len(plan.new_issue_ids) == len(defects - seen), "new"
        assert len(plan.unchanged_issue_ids) == len(defects & live_before), "unchanged"
        assert len(plan.reopened_issue_ids) == len((defects & seen) - live_before), "reopened"
        assert len(plan.closed_issue_ids) == len((prev - defects) - other), "closed"
        assert len(plan.detached_issue_ids) == len((prev - defects) & other), "detached"

        snap[test] = set(defects)
        seen |= defects
        live_ids = {i for i, issue in w.issues.items() if issue.state != "fixed"}
        current = set().union(*(w.snapshots.values()))
        assert live_ids == current, "live Issues must be exactly those a current snapshot reports"


@settings(max_examples=250, deadline=None)
@given(st.lists(st.tuples(TESTS, DEFECTS, st.booleans()), min_size=1, max_size=12))
def test_invariants_hold_for_any_mix_of_close_missing_settings(
    sequence: list[tuple[str, set[int], bool]],
) -> None:
    w = World()
    for test, defects, close_missing in sequence:
        prev = set(w.snapshots.get(test, set()))
        before = {i: issue.state for i, issue in w.issues.items()}
        plan = w.import_into(test, defects, close_missing=close_missing)
        in_file = {u.issue_id for u in plan.updates}

        # The four outcomes partition the file's Issues: each counted once, none twice.
        outcomes = [
            set(plan.new_issue_ids), set(plan.unchanged_issue_ids), set(plan.reopened_issue_ids)
        ]  # fmt: skip
        assert sum(len(o) for o in outcomes) == len(in_file)
        assert set().union(*outcomes) == in_file
        # Nothing the file still reports is closed, and nothing is both closed and detached.
        assert not set(plan.closed_issue_ids) & in_file
        assert not set(plan.closed_issue_ids) & set(plan.detached_issue_ids)
        # An Issue present in any current snapshot is never left fixed.
        for snapshot in w.snapshots.values():
            assert all(w.state(i) != "fixed" for i in snapshot)
        # Scope: an import only ever changes Issues it reported or previously reported (R20).
        changed = {i for i, s in w.issues.items() if before.get(i) != s.state}
        assert changed <= in_file | prev
        # close_missing off closes and detaches nothing.
        if not close_missing:
            assert plan.closed_issue_ids == () and plan.detached_issue_ids == ()


@settings(max_examples=150, deadline=None)
@given(SEQUENCES)
def test_reimporting_the_same_file_straight_away_is_always_a_no_op(
    sequence: list[tuple[str, set[int]]],
) -> None:
    w = World()
    for test, defects in sequence:
        w.import_into(test, defects)
        again = w.import_into(test, defects)
        counts = again.counts
        assert (counts["new"], counts["reopened"], counts["closed"], counts["detached"]) == (
            0, 0, 0, 0,
        )  # fmt: skip
        assert counts["unchanged"] == len({u.issue_id for u in again.updates})
