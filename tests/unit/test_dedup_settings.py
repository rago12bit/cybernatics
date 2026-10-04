"""Deduplication settings (Week 58, ADR-0042): versioned per project per source, and applied to
imports and native scans before findings are matched to Issues."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.correlation import correlate
from core.dedup.settings import (
    current_settings,
    history,
    rekey,
    rekey_for_asset,
    save_setting,
)
from core.imports.service import apply_import, preview_import
from core.models import Finding
from core.persistence import repo
from core.persistence.models import IssueRow
from tests.unit.test_dedup_strategies import code
from tests.unit.test_import_service import ORG, digest, setup


def at(s: Session, asset_id: str, source: str, strategy: str, fields: tuple[str, ...] = ()) -> None:
    save_setting(s, org_id=ORG, asset_id=asset_id, source=source, strategy=strategy, fields=fields)
    s.commit()


def load(*findings: Finding) -> list[Finding]:
    return correlate(list(findings))[0]


def do(s: Session, test_id: str, findings: list[Finding], n: int):
    return apply_import(
        s, org_id=ORG, test_id=test_id, findings=findings, parser="semgrep",
        file_digest=digest(n), file_name=f"r{n}.sarif",
    )  # fmt: skip


def test_settings_are_versioned_by_insertion_and_the_highest_version_wins(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, _ = setup(s, "T")
        assert current_settings(s, asset_id) == {}  # no row: the default
        at(s, asset_id, "nessus", "tool_id")
        at(s, asset_id, "nessus", "hash_fields", ("title", "path"))
        at(s, asset_id, "zap", "tool_id")
        now = current_settings(s, asset_id)
        assert (now["nessus"].strategy, now["nessus"].version, now["nessus"].fields) == (
            "hash_fields", 2, ("title", "path"))  # fmt: skip
        assert now["zap"].version == 1
        assert [(h.source, h.version) for h in history(s, asset_id)] == [
            ("nessus", 2), ("nessus", 1), ("zap", 1)]  # fmt: skip
        assert [h.strategy for h in history(s, asset_id, "nessus")] == ["hash_fields", "tool_id"]


def test_a_setting_belongs_to_one_project(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        a, _ = setup(s, "T")
        other = repo.get_or_create_asset(s, source_type="git", source_label="c/d", org_id=ORG)
        at(s, a, "nessus", "tool_id")
        assert current_settings(s, other.id) == {}


def test_a_bad_setting_is_refused_and_nothing_is_written(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, _ = setup(s, "T")
        with pytest.raises(ValueError):
            save_setting(s, org_id=ORG, asset_id=asset_id, source="zap", strategy="hash_fields")
        assert history(s, asset_id) == []


def test_rekey_changes_only_the_sources_with_a_non_default_setting_and_is_idempotent() -> None:
    from core.dedup.settings import Setting

    a, b = code(tool="semgrep"), code(tool="bandit", rule="B1")
    keep = (a.fingerprint, b.fingerprint)
    settings = {"semgrep": Setting("semgrep", "tool_id", (), 1),
                "bandit": Setting("bandit", "fingerprint_v2", (), 1)}  # fmt: skip
    assert rekey([a, b], settings) == 1  # only semgrep
    assert a.fingerprint.startswith("dd1:tool_id:") and b.fingerprint == keep[1]
    first = a.fingerprint
    assert rekey([a, b], settings) == 0 and a.fingerprint == first  # idempotent


def test_tool_id_makes_the_same_rule_in_the_same_file_one_issue_whatever_the_line(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        at(s, asset_id, "semgrep", "tool_id")
        first = do(
            s, t["SAST"], load(code(line=10, snippet="a(x)"), code(line=40, snippet="b(y)")), 1
        )
        assert first.record.new_count == 1  # two findings, one Issue
        # The code moves and changes; under the default that is new + closed, here it is unchanged.
        second = do(s, t["SAST"], load(code(line=77, snippet="totally(different, args, more)")), 2)
    assert (second.record.new_count, second.record.unchanged_count, second.record.closed_count) == (
        0,
        1,
        0,
    )


def test_the_default_still_treats_a_changed_snippet_as_a_different_defect(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, t = setup(s, "SAST")
        do(s, t["SAST"], load(code(line=10, snippet="a(x)")), 1)
        second = do(s, t["SAST"], load(code(line=10, snippet="totally(different, args, more)")), 2)
    assert (second.record.new_count, second.record.closed_count) == (1, 1)


def test_a_chosen_key_switches_off_the_path_free_fallback(sessions: sessionmaker[Session]) -> None:
    """By default a function moved to another file is the same Issue (the fallback key ignores the
    path). A project that chose `path` as part of its key told Bulwark otherwise."""
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        moved = [code(path="b.py")]
        do(s, t["SAST"], load(code(path="a.py")), 1)
        same = preview_import(s, org_id=ORG, test_id=t["SAST"], findings=load(*moved))
        assert (same.counts["new"], same.counts["closed"]) == (0, 0)  # default: moved, unchanged

        at(s, asset_id, "semgrep", "hash_fields", ("title", "path"))
        split = preview_import(s, org_id=ORG, test_id=t["SAST"], findings=load(code(path="b.py")))
    assert (split.counts["new"], split.counts["closed"]) == (1, 1)


def test_a_native_scan_is_matched_by_the_projects_setting_too(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, _ = setup(s, "T")
        at(s, asset_id, "bandit", "tool_id")

        def scan(findings: list[Finding]) -> None:
            sc = repo.create_scan(s, source_type="git", source_ref="https://x", source_label="a/b",
                                  tools=["bandit"], org_id=ORG)  # fmt: skip
            result = repo.sync_issues_for_scan(s, sc.id, findings)
            repo.add_findings(s, sc.id, findings, result.updates)
            repo.finish_scan(s, sc.id, "completed")

        scan(load(code(tool="bandit", rule="B1", line=10), code(tool="bandit", rule="B1", line=30)))
        scan(load(code(tool="bandit", rule="B1", line=99, snippet="moved(z)")))
        issues = list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id)))
    assert (
        len(issues) == 1 and issues[0].state != "fixed" and issues[0].fingerprint.startswith("dd1:")
    )


def test_a_source_with_no_setting_is_unaffected_by_anothers(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, _ = setup(s, "T")
        at(s, asset_id, "nessus", "tool_id")
        f = code(tool="semgrep")
        before = f.fingerprint
        assert rekey_for_asset(s, asset_id, [f]) == 0 and f.fingerprint == before
