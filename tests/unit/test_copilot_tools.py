"""core.copilot.tools: the 5 read-only tools a copilot turn may call (plan §21.5)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.codeintel import analyze
from core.copilot.tools import (
    CopilotContext,
    ToolError,
    compare_scans_tool,
    fetch_code_range,
    get_call_path,
    list_routes,
    query_issues,
)
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo


def _seed_asset_with_a_completed_scan(sessions: sessionmaker[Session]) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id="org-a",
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def _seed_finding(
    sessions: sessionmaker[Session], scan_id: str, finding_id: str, path: str = "app/users.py"
) -> str:
    with sessions() as s:
        f = Finding(
            finding_id, "SQL injection", "d", Location(path, 2, 2),
            Taxonomy(Category.SAST, cwe=("CWE-89",)),
        )  # fmt: skip
        result = repo.sync_issues_for_scan(s, scan_id, [f])
        repo.add_findings(s, scan_id, [f], issue_updates=result.updates)
        return next(u.issue_id for u in result.updates if u.finding_id == finding_id)


def _ctx(sessions: sessionmaker[Session], asset_id: str, checkout: Path) -> CopilotContext:
    with sessions() as s:
        scan = repo.latest_scan_for_asset(s, asset_id)
        assert scan is not None
        return CopilotContext(
            session=s, org_id="org-a", asset_id=asset_id, latest_scan_id=scan.id,
            checkout=checkout, graph=analyze(checkout),
        )  # fmt: skip


def test_fetch_code_range_reads_real_lines_with_numbers(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("line1\nline2\nline3\n")
    ctx = CopilotContext(
        session=None, org_id="o", asset_id="a", latest_scan_id="s", checkout=tmp_path,  # type: ignore[arg-type]
        graph=analyze(tmp_path),
    )  # fmt: skip
    out = fetch_code_range(ctx, "a.py", start_line=2, end_line=2)
    assert out.strip() == "2 | line2"


def test_fetch_code_range_rejects_a_path_escaping_the_checkout(tmp_path: Path) -> None:
    ctx = CopilotContext(
        session=None, org_id="o", asset_id="a", latest_scan_id="s", checkout=tmp_path,  # type: ignore[arg-type]
        graph=analyze(tmp_path),
    )  # fmt: skip
    with pytest.raises(ToolError, match="escapes"):
        fetch_code_range(ctx, "../outside.py")


def test_get_call_path_lists_a_real_caller(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def helper():\n    pass\n\n\ndef main():\n    helper()\n")
    ctx = CopilotContext(
        session=None, org_id="o", asset_id="a", latest_scan_id="s", checkout=tmp_path,  # type: ignore[arg-type]
        graph=analyze(tmp_path),
    )  # fmt: skip
    out = get_call_path(ctx, "a.py", 1)
    assert "main" in out


def test_list_routes_filters_by_method(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.get('/users')\ndef list_users():\n    pass\n\n"
        "@app.post('/users')\ndef create_user():\n    pass\n"
    )
    ctx = CopilotContext(
        session=None, org_id="o", asset_id="a", latest_scan_id="s", checkout=tmp_path,  # type: ignore[arg-type]
        graph=analyze(tmp_path),
    )  # fmt: skip
    out = list_routes(ctx, method="POST")
    assert "/users" in out and "GET /users" not in out


def test_query_issues_finds_a_real_seeded_issue(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    with sessions() as s:
        scan = repo.latest_scan_for_asset(s, asset_id)
        assert scan is not None
        scan_id = scan.id
    issue_id = _seed_finding(sessions, scan_id, "f1")
    ctx = _ctx(sessions, asset_id, tmp_path)
    out = query_issues(ctx, cwe="CWE-89")
    assert issue_id in out
    ctx.session.close()


def test_query_issues_cwe_filter_excludes_non_matching(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    with sessions() as s:
        scan = repo.latest_scan_for_asset(s, asset_id)
        assert scan is not None
        scan_id = scan.id
    _seed_finding(sessions, scan_id, "f1")
    ctx = _ctx(sessions, asset_id, tmp_path)
    out = query_issues(ctx, cwe="CWE-999")
    assert out == "(no matching issues)"
    ctx.session.close()


def test_compare_scans_tool_reports_a_new_issue(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    with sessions() as s:
        scan_a = repo.latest_scan_for_asset(s, asset_id)
        assert scan_a is not None
        scan_a_id = scan_a.id
    with sessions() as s:
        scan_b = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id="org-a",
        )  # fmt: skip
        repo.finish_scan(s, scan_b.id, "completed")
        scan_b_id = scan_b.id
    issue_id = _seed_finding(sessions, scan_b_id, "f1")
    ctx = _ctx(sessions, asset_id, tmp_path)
    out = compare_scans_tool(ctx, scan_a_id, scan_b_id)
    assert issue_id in out and "new:" in out
    ctx.session.close()


def test_compare_scans_tool_rejects_scans_from_different_assets(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_a = _seed_asset_with_a_completed_scan(sessions)
    with sessions() as s:
        scan_a = repo.latest_scan_for_asset(s, asset_a)
        assert scan_a is not None
        scan_a_id = scan_a.id
    with sessions() as s:
        scan_c = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/y.git", source_label="acme/y",
            tools=["bandit"], org_id="org-a",
        )  # fmt: skip
        repo.finish_scan(s, scan_c.id, "completed")
        scan_c_id = scan_c.id
    ctx = _ctx(sessions, asset_a, tmp_path)
    with pytest.raises(ToolError, match="do not belong to the same project"):
        compare_scans_tool(ctx, scan_a_id, scan_c_id)
    ctx.session.close()
