"""The reimport decision (plan §42.1, ADR-0040): given what a file reports, what each Issue already
is, and what this scope previously reported, decide what is new, unchanged, reopened and closed.

Pure, like `core.issues`: no database, no I/O, so the whole decision is testable against ground
truth (see tests/unit/test_reimport.py) and the import screen's *preview* is literally this function
without the write that follows -- the counts it shows cannot differ from what an import then does,
because they are one computation (`plan_reimport`), not two that must be kept in agreement.

Matching and state transitions are NOT reimplemented here. `core.issues.sync` already decides, for
one batch of findings, which existing Issue each finding is, whether it is new, and whether a fixed
Issue came back; this module reuses it and adds only what a *partial* source needs: closing is
scoped to what that source previously reported, not to everything the asset has.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Literal

from core.issues import LIVE_STATES, ExistingIssue, IssueUpdate, State
from core.issues import sync as sync_issues
from core.models.finding import Finding

Outcome = Literal["new", "unchanged", "reopened"]


@dataclass(frozen=True)
class ReimportPlan:
    """Everything an import will do, decided before anything is written.

    Counts are of **Issues**, not findings: a file reporting the same defect twice is one Issue.
    `closed_issue_ids` become `fixed`. `detached_issue_ids` are Issues this file stopped
    reporting that stay open because another source still reports them (ADR-0040) -- not "fixed",
    so not counted as closed. `held_issue_ids` are Issues this file stopped reporting at a place
    its tool only samples (ZAP: `core.dast.mapping.crawl_samples`), while the same rule still fires
    on the same host -- not seen, but not shown fixed either, so they stay open."""

    updates: tuple[IssueUpdate, ...]  # one per finding, same order as the input
    new_issue_ids: tuple[str, ...]
    unchanged_issue_ids: tuple[str, ...]
    reopened_issue_ids: tuple[str, ...]
    closed_issue_ids: tuple[str, ...]
    detached_issue_ids: tuple[str, ...]
    held_issue_ids: tuple[str, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new_issue_ids),
            "unchanged": len(self.unchanged_issue_ids),
            "reopened": len(self.reopened_issue_ids),
            "closed": len(self.closed_issue_ids),
            "detached": len(self.detached_issue_ids),
            "held": len(self.held_issue_ids),
        }

    def resulting_states(self) -> dict[str, State]:
        """The state every touched Issue ends in -- the single place that maps an outcome to a
        state, shared by the database writer and the tests' in-memory model."""
        states: dict[str, State] = {}
        for ids, state in (
            (self.new_issue_ids, "new"),
            (self.unchanged_issue_ids, "open"),
            (self.reopened_issue_ids, "reintroduced"),
            (self.closed_issue_ids, "fixed"),
        ):
            for issue_id in ids:
                states[issue_id] = state  # type: ignore[assignment]  # literal tuple above
        return states


def _default_issue_id() -> str:
    return str(uuid.uuid4())


def plan_reimport(
    findings: list[Finding],
    existing: list[ExistingIssue],
    *,
    previous_issue_ids: Collection[str],
    other_live_issue_ids: Collection[str] = (),
    close_missing: bool = True,
    held_issue_ids: Collection[str] = (),
    new_issue_id: Callable[[], str] = _default_issue_id,
) -> ReimportPlan:
    """Decide an import.

    `existing` is every Issue of the asset (fixed ones too, so a returning defect is recognised as
    reopened rather than new). `previous_issue_ids` is the Issues this scope reported last time --
    the only ones the file can close ("one tool's report cannot close another tool's findings").
    `other_live_issue_ids` is the Issues some *other* source still reports; a file that stops
    reporting one of those has not fixed it. `held_issue_ids` is the Issues at a place this file
    only samples (the caller decides which, from the findings and each Issue's last place); missing
    from the file, they are held open. `close_missing=False` closes nothing and detaches nothing:
    the file is only added.
    """
    result = sync_issues(findings, existing, new_issue_id)

    # One outcome per Issue. Two findings in a file can be the same Issue, and `sync` classifies the
    # second against the Issue the first just created (reporting it as "open"), so a per-finding
    # tally would say "1 new, 1 unchanged" for one new defect.
    outcome: dict[str, Outcome] = {}
    for u in result.updates:
        assert u.issue_id is not None  # sync() always allocates a real id
        if u.is_new_issue:
            outcome[u.issue_id] = "new"
        elif u.issue_id in outcome:
            continue
        else:
            outcome[u.issue_id] = "reopened" if u.state == "reintroduced" else "unchanged"

    closed: list[str] = []
    detached: list[str] = []
    held: list[str] = []
    if close_missing:
        live = {i.id for i in existing if i.state in LIVE_STATES}
        other_live = set(other_live_issue_ids)
        hold = set(held_issue_ids)
        for issue_id in sorted((set(previous_issue_ids) & live) - set(outcome)):
            if issue_id in other_live:
                detached.append(issue_id)
            elif issue_id in hold:
                held.append(issue_id)
            else:
                closed.append(issue_id)

    def ids(kind: Outcome) -> tuple[str, ...]:
        return tuple(sorted(i for i, o in outcome.items() if o == kind))

    return ReimportPlan(
        updates=tuple(result.updates),
        new_issue_ids=ids("new"),
        unchanged_issue_ids=ids("unchanged"),
        reopened_issue_ids=ids("reopened"),
        closed_issue_ids=tuple(closed),
        detached_issue_ids=tuple(detached),
        held_issue_ids=tuple(held),
    )
