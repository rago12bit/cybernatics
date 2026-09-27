"""Application-level org isolation (ADR-0013), on SQLite. This is what actually protects the fast
test suite — Postgres Row-Level Security has no SQLite equivalent, so RLS itself is only proven live
against real Postgres (docs/v2-week29-verification.md), not here. These tests cover the belt in
"belt-and-suspenders": every `core/persistence/repo.py` query that takes an `org_id` still has to
filter by it correctly even if a policy somewhere is ever misconfigured or missing.
"""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID


def _scan(sessions: sessionmaker[Session], org_id: str, label: str) -> str:
    with sessions() as s:
        return repo.create_scan(
            s, source_type="git", source_ref=label, source_label=label,
            tools=["bandit"], org_id=org_id,
        ).id  # fmt: skip


def test_omitting_org_id_defaults_to_the_bootstrap_org(sessions: sessionmaker[Session]) -> None:
    """Every pre-Week-29 caller (and every existing test) omits `org_id`; it must still work exactly
    as before, scoped to the one bootstrap organization."""
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="u", tools=["bandit"]
        )
    assert scan.org_id == DEFAULT_ORG_ID


def test_get_scan_is_invisible_across_orgs_not_just_unauthorized(
    sessions: sessionmaker[Session],
) -> None:
    sid = _scan(sessions, "org-a", "https://example.com/a/b")
    with sessions() as s:
        assert repo.get_scan(s, sid, org_id="org-a") is not None
        assert repo.get_scan(s, sid, org_id="org-b") is None  # wrong org: same as not-found
        assert repo.get_scan(s, sid) is not None  # org_id=None: trusted-internal, unscoped


def test_list_scans_never_leaks_another_orgs_scan(sessions: sessionmaker[Session]) -> None:
    a = _scan(sessions, "org-a", "https://example.com/a/1")
    b = _scan(sessions, "org-b", "https://example.com/b/1")
    with sessions() as s:
        ids_a = {sc.id for sc in repo.list_scans(s, org_id="org-a")}
        ids_b = {sc.id for sc in repo.list_scans(s, org_id="org-b")}
    assert ids_a == {a}
    assert ids_b == {b}
    assert ids_a.isdisjoint(ids_b)


def test_same_public_repo_gets_separate_assets_per_org(sessions: sessionmaker[Session]) -> None:
    """The bug ADR-0013 exists to prevent: two orgs scanning the same repo must never share an Asset,
    or one org's Issue lifecycle history (and counts) would leak into the other's."""
    url = "https://github.com/OWASP/NodeGoat"
    with sessions() as s:
        asset_a = repo.get_or_create_asset(s, source_type="git", source_label=url, org_id="org-a")
        asset_b = repo.get_or_create_asset(s, source_type="git", source_label=url, org_id="org-b")
        # Scanning it again under org-a's own org still resolves to the SAME asset (identity is
        # unaffected within one org) -- only the cross-org case must diverge.
        asset_a_again = repo.get_or_create_asset(
            s, source_type="git", source_label=url, org_id="org-a"
        )
    assert asset_a.id != asset_b.id
    assert asset_a.id == asset_a_again.id
