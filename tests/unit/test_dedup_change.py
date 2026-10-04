"""The dry run's decision (Week 58, plan §42.3): merges, splits, and the properties that make a
preview trustworthy -- every occurrence ends up in exactly one Issue, every Issue is accounted for,
and what the preview says is what the digest pins."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from core.dedup.change import Candidate, plan_change
from core.dedup.strategies import key_for
from core.models import Finding
from tests.unit.test_dedup_strategies import code

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def cand(issue_id: str, *findings: Finding, age: int = 0, key: str = "old") -> Candidate:
    return Candidate(
        issue_id, T0 + timedelta(days=age), key,
        tuple((hash((issue_id, i)) & 0xFFFFFF, f) for i, f in enumerate(findings)),
    )  # fmt: skip


def test_issues_with_one_new_key_are_merged_into_the_oldest() -> None:
    a = cand("a", code(line=1), age=2)
    b = cand("b", code(line=2), age=0)
    c = cand("c", code(line=3), age=1)
    plan = plan_change([a, b, c], "tool_id")
    (g,) = plan.groups
    assert (g.survivor, set(g.merged)) == ("b", {"a", "c"}) and plan.merge_groups == 1
    assert (plan.issues_before, plan.issues_after, plan.merged_away) == (3, 1, 2)
    assert plan.issues_split == 0 and plan.created_by_split == 0


def test_distinct_keys_stay_distinct_and_unchanged_when_the_key_is_the_same() -> None:
    a, b = cand("a", code(path="x.py")), cand("b", code(path="y.py"))
    plan = plan_change([a, b], "tool_id")
    assert plan.issues_after == 2 and plan.merged_away == 0 and plan.created_by_split == 0
    again = plan_change(
        [cand("a", code(path="x.py"), key=key_for("tool_id", code(path="x.py")))], "tool_id"
    )
    assert again.groups[0].survivor == "a"


def test_an_issue_whose_occurrences_get_different_keys_is_split() -> None:
    both = cand("a", code(path="x.py"), code(path="y.py"), code(path="y.py", line=5))
    plan = plan_change([both], "tool_id")
    assert plan.issues_after == 2 and plan.issues_split == 1 and plan.created_by_split == 1
    kept = next(g for g in plan.groups if g.survivor == "a")
    new = next(g for g in plan.groups if g.survivor is None)
    assert len(kept.rows) == 2 and len(new.rows) == 1  # the key most occurrences have is kept
    assert new.split_from == "a"


def test_a_split_part_joins_an_existing_issue_that_already_has_that_key() -> None:
    both = cand("a", code(path="x.py"), code(path="x.py", line=2), code(path="y.py"), age=0)
    only_y = cand("b", code(path="y.py", line=9), age=1)
    plan = plan_change([both, only_y], "tool_id")
    y = next(g for g in plan.groups if g.survivor == "b")
    assert plan.created_by_split == 0 and y.split_from is None and len(y.rows) == 2


def test_a_key_another_issue_already_holds_is_a_conflict_not_a_plan() -> None:
    f = code()
    held = frozenset({key_for("tool_id", f)})
    plan = plan_change([cand("a", f)], "tool_id", held_elsewhere=held)
    assert plan.groups == () and plan.conflicts == tuple(held)


def test_the_digest_pins_the_plan() -> None:
    cs = [cand("a", code(line=1)), cand("b", code(line=2))]
    first, same = plan_change(cs, "tool_id"), plan_change(list(reversed(cs)), "tool_id")
    assert first.digest == same.digest  # order of the input does not matter
    assert plan_change(cs, "hash_fields", ("title", "path")).digest != first.digest
    extra = [*cs, cand("c", code(line=3))]
    assert plan_change(extra, "tool_id").digest != first.digest  # a new Issue moves the digest


PATHS = ["a.py", "b.py", "c.py"]
RULES = ["r1", "r2"]


@st.composite
def projects(draw: st.DrawFn) -> list[Candidate]:
    n = draw(st.integers(0, 8))
    out = []
    for i in range(n):
        occ = [
            code(path=draw(st.sampled_from(PATHS)), rule=draw(st.sampled_from(RULES)),
                 line=draw(st.integers(1, 90)), snippet=f"x{draw(st.integers(0, 3))}(y)")
            for _ in range(draw(st.integers(1, 4)))
        ]  # fmt: skip
        out.append(cand(f"i{i:02d}", *occ, age=draw(st.integers(0, 30))))
    return out


@settings(max_examples=150, deadline=None)
@given(projects(), st.sampled_from(["tool_id", "hash_fields", "tool_id_or_hash", "fingerprint_v2"]))
def test_every_occurrence_and_every_issue_is_accounted_for(
    cs: list[Candidate], strategy: str
) -> None:
    fields = ("title", "path") if strategy == "hash_fields" else ()
    plan = plan_change(cs, strategy, fields)
    rows = [r for g in plan.groups for r in g.rows]
    assert len(rows) == len(set(rows))  # no occurrence in two Issues
    assert sorted(rows) == sorted(r for c in cs for r, _ in c.occurrences)  # none lost
    assert len({g.key for g in plan.groups}) == len(plan.groups)  # one Issue per key
    # Oracle: the keys, by plain set arithmetic.
    keys = {key_for(strategy, f, fields) for c in cs for _, f in c.occurrences}
    assert {g.key for g in plan.groups} == keys
    survivors = [g.survivor for g in plan.groups if g.survivor]
    merged = [m for g in plan.groups for m in g.merged]
    assert sorted([*survivors, *merged]) == sorted(c.issue_id for c in cs)  # each Issue once
    assert plan.issues_after == len(keys)
    assert plan.created_by_split == plan.issues_after - len(survivors)
