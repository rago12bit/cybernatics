"""Issue identity and lifecycle across scans of the same asset (ADR-0012).

Pure functions only — no database access, so the matching and state-machine logic is testable
without Postgres. `core/persistence/repo.py` is what turns this into rows.

A `Finding` is one sighting, in one scan. An `Issue` is the same defect tracked across every scan
of one asset (one repository, one uploaded archive by name): it is what lets the product say
"fixed", "reintroduced", or "new in this scan" instead of treating every scan as an island.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from core.correlation import cwe_family
from core.correlation.normalize import is_placeholder, snippet_hash
from core.models.finding import Finding

State = Literal["new", "open", "fixed", "reintroduced"]

# States that mean "this issue is currently believed present". Anything else ("fixed") is absent
# until a matching Occurrence reappears.
LIVE_STATES = frozenset({"new", "open", "reintroduced"})


def fallback_key(f: Finding) -> str | None:
    """Location-independent identity for a code finding: the primary fingerprint (ADR-0004) minus
    the file path, so moving a function to another file does not manufacture a spurious "new" issue
    alongside a spurious "fixed" one.

    Returns None only for SCA findings (the package/version/CVE triple is already
    location-independent, so the primary fingerprint already serves as its own fallback and this
    would just duplicate it). Every other case anchors on the rule id(s) that fired, same as the
    primary fingerprint (`core.correlation.engine.fingerprint` -- see its docstring for the two real
    collisions, confirmed against this repo's own golden scan data, that made this necessary): a
    placeholder or empty snippet alone gives literally nothing to anchor on, and even a real,
    non-empty snippet isn't always unique -- an IaC linter (Trivy's Terraform checks, for one)
    routinely quotes the *entire resource block* verbatim for every distinct rule that fires against
    it, so several genuinely different findings can share one snippet. Without the rule id here too,
    this key -- already path-independent by design -- would match those collisions *anywhere in the
    asset*, which is a strictly worse version of the same bug than the primary fingerprint has.
    """
    if f.package:
        return None
    snip = f.location.snippet
    cwe = min(cwe_family(f) or {"none"})
    rule_ids = sorted({r for rules in f.evidence.rule_ids.values() for r in rules})
    rules_part = "|".join(rule_ids) if rule_ids else "no-rule-id"
    snippet_part = (
        "placeholder" if (is_placeholder(snip) or not snip.strip()) else snippet_hash(snip)
    )
    raw = f"{cwe}|{snippet_part}|{rules_part}"
    return "fallback:" + hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True)
class MatchKeys:
    """The keys one Finding could be matched to an existing Issue by, in preference order. Both
    keys are scoped by category: `fingerprint()` (ADR-0004) hashes the CWE, path and snippet, but
    not the category, so two findings of *different* categories (say a SAST rule and a secrets
    rule) can hash identically when both lack a CWE and both land on the same redacted line. That
    ambiguity is harmless for correlation (`same_defect` also requires compatible categories before
    it ever compares fingerprints), but Issue identity uses the fingerprint on its own, so it must
    add the category itself to stay collision-safe.
    """

    category: str
    primary: str
    fallback: str | None


def match_keys(f: Finding) -> MatchKeys:
    return MatchKeys(
        category=f.taxonomy.category.value, primary=f.fingerprint, fallback=fallback_key(f)
    )


@dataclass(frozen=True)
class ExistingIssue:
    """The minimal view of a stored Issue that the sync algorithm needs. Built by the repo layer
    from `IssueRow`; kept as a plain dataclass so this module never imports SQLAlchemy."""

    id: str
    category: str
    fingerprint: str
    fallback_fingerprint: str | None
    state: State


@dataclass
class IssueUpdate:
    """One outcome of syncing a scan's findings against an asset's existing issues."""

    finding_id: str
    issue_id: str
    state: State
    is_new_issue: bool
    fingerprint: str  # the fingerprint the issue should now be stored under (may have moved)


@dataclass
class SyncResult:
    updates: list[IssueUpdate] = field(default_factory=list)  # one per finding in this scan
    fixed_issue_ids: list[str] = field(default_factory=list)  # existing issues absent this scan
    new_count: int = 0
    reintroduced_count: int = 0
    fixed_count: int = 0


def _next_state(prior: State | None, was_fixed: bool) -> tuple[State, bool]:
    """State for a matched issue, and whether it's a brand new one.

    A never-seen fingerprint starts "new". Seeing it again (whatever its prior live state) settles
    it to "open" — "new" means "first time", not "still recent". An issue that had been fixed and
    reappears becomes "reintroduced", regardless of how it was last classified before that.
    """
    if prior is None:
        return "new", True
    if was_fixed:
        return "reintroduced", False
    return "open", False


def sync(
    findings: list[Finding],
    existing: list[ExistingIssue],
    new_issue_id: Callable[[], str],
) -> SyncResult:
    """Match this scan's findings against an asset's existing issues and compute the lifecycle
    transitions. Callers persist the result; this function only decides it.

    `new_issue_id` generates an id for an issue that doesn't exist yet (kept as a parameter, not a
    module-level uuid4 call, so tests can supply deterministic ids).
    """
    by_primary = {(i.category, i.fingerprint): i for i in existing}
    by_fallback = {
        (i.category, i.fallback_fingerprint): i for i in existing if i.fallback_fingerprint
    }
    matched_issue_ids: set[str] = set()
    result = SyncResult()

    for f in findings:
        keys = match_keys(f)
        found = by_primary.get((keys.category, keys.primary))
        if found is None and keys.fallback is not None:
            found = by_fallback.get((keys.category, keys.fallback))
        was_fixed = found is not None and found.state == "fixed"
        state, is_new = _next_state(found.state if found else None, was_fixed)
        issue_id = found.id if found else new_issue_id()
        if is_new:
            # Record it immediately: two findings *in this same scan* can share a key too (the
            # collision above isn't only a cross-scan concern), and the second one must reuse this
            # issue rather than mint a duplicate that would violate the (asset, category,
            # fingerprint) uniqueness the repo layer enforces.
            fresh = ExistingIssue(issue_id, keys.category, keys.primary, keys.fallback, state)
            by_primary[(keys.category, keys.primary)] = fresh
            if keys.fallback is not None:
                by_fallback[(keys.category, keys.fallback)] = fresh
        matched_issue_ids.add(issue_id)
        result.updates.append(
            IssueUpdate(
                finding_id=f.id,
                issue_id=issue_id,
                state=state,
                is_new_issue=is_new,
                fingerprint=keys.primary,  # always store the current primary; it may have moved
            )
        )
        if is_new:
            result.new_count += 1
        elif state == "reintroduced":
            result.reintroduced_count += 1

    result.fixed_issue_ids = [
        i.id for i in existing if i.id not in matched_issue_ids and i.state in LIVE_STATES
    ]
    result.fixed_count = len(result.fixed_issue_ids)
    return result
