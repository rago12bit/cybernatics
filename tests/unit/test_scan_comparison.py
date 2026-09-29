"""core/persistence/repo.py::compare_scans (plan §28.6/§36): categorizing the issues between two
scans of the same asset as new/fixed/reintroduced/unchanged."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from core.events import MemoryPublisher
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo
from core.persistence.storage import MemoryStore
from core.pipeline import run_scan_job
from core.scan import ToolOutcome
from core.tenancy import DEFAULT_ORG_ID


def finding(path: str, rule: str, line: int = 1) -> Finding:
    f = Finding(
        id=f"bandit:{rule}:{path}:{line}",
        title=f"finding {rule}",
        description="d",
        location=Location(path, line, line, f"code-{rule}", f"hash-{rule}"),
        taxonomy=Taxonomy(Category.SAST, cwe=(f"CWE-{rule}",)),
    )
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = ["bandit"]
    f.evidence.rule_ids = {"bandit": [rule]}
    return f


def run(sessions: sessionmaker[Session], url: str, findings: list[Finding]) -> str:
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=url, source_label=url, tools=["bandit"]
        ).id
    run_scan_job(
        sid, sessions, MemoryStore(), MemoryPublisher(),
        lambda name, target: ToolOutcome("bandit", "ok", findings),
    )  # fmt: skip
    return sid


def test_unchanged_new_fixed_and_reintroduced_are_each_categorized_correctly(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    url = str(sample_repo)
    # Scan 1: "a" and "b" present.
    s1 = run(sessions, url, [finding("a.py", "R1"), finding("b.py", "R2")])
    # Scan 2: "a" still there (unchanged), "b" gone (fixed), "c" appears (new).
    s2 = run(sessions, url, [finding("a.py", "R1"), finding("c.py", "R3")])
    # Scan 3: "b" comes back (reintroduced), "a" still there, "c" gone.
    s3 = run(sessions, url, [finding("a.py", "R1"), finding("b.py", "R2")])

    with sessions() as s:
        cmp_1_2 = repo.compare_scans(s, s1, s2, org_id=DEFAULT_ORG_ID)
        assert cmp_1_2 is not None
        assert [i["title"] for i in cmp_1_2.unchanged] == ["finding R1"]
        assert [i["title"] for i in cmp_1_2.fixed] == ["finding R2"]
        assert [i["title"] for i in cmp_1_2.new] == ["finding R3"]
        assert cmp_1_2.reintroduced == []

        cmp_2_3 = repo.compare_scans(s, s2, s3, org_id=DEFAULT_ORG_ID)
        assert cmp_2_3 is not None
        assert [i["title"] for i in cmp_2_3.unchanged] == ["finding R1"]
        assert [i["title"] for i in cmp_2_3.fixed] == ["finding R3"]
        assert [i["title"] for i in cmp_2_3.reintroduced] == ["finding R2"]
        assert cmp_2_3.new == []


def test_comparison_is_order_independent_and_orders_by_time_not_argument_order(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    url = str(sample_repo)
    s1 = run(sessions, url, [finding("a.py", "R1")])
    s2 = run(sessions, url, [finding("b.py", "R2")])
    with sessions() as s:
        forward = repo.compare_scans(s, s1, s2, org_id=DEFAULT_ORG_ID)
        backward = repo.compare_scans(s, s2, s1, org_id=DEFAULT_ORG_ID)
        assert forward is not None and backward is not None
        assert forward.earlier.id == backward.earlier.id == s1
        assert forward.later.id == backward.later.id == s2
        assert [i["title"] for i in forward.fixed] == [i["title"] for i in backward.fixed]
        assert [i["title"] for i in forward.new] == [i["title"] for i in backward.new]


def test_comparing_scans_of_different_assets_returns_none(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    a = run(sessions, str(sample_repo), [finding("a.py", "R1")])
    b = run(sessions, "a-different-repo", [finding("a.py", "R1")])
    with sessions() as s:
        assert repo.compare_scans(s, a, b, org_id=DEFAULT_ORG_ID) is None


def test_comparing_an_unknown_scan_returns_none(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    a = run(sessions, str(sample_repo), [finding("a.py", "R1")])
    with sessions() as s:
        assert repo.compare_scans(s, a, "does-not-exist", org_id=DEFAULT_ORG_ID) is None
