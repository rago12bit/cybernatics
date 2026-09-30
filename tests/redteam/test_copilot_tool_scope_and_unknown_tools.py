"""Red-team scenarios (plan §21.9): "calls disallowed tools" and "reaches another tenant's data".

For disallowed tools: core.copilot.service._dispatch's own unknown-tool branch is exercised
directly with a name modeled on what an injected instruction might ask for ("delete_all_issues") --
it must come back as an ordinary error-shaped tool result, never raise, never execute anything.

For cross-tenant reach: query_issues's real signature takes no asset/org parameter at all -- scope
comes only from the CopilotContext built once at conversation start, never from anything the model
supplies. This is proven against two REAL seeded assets, and by passing an attacker-controlled
"asset_id" key through _dispatch's tool_input (which the real dispatch code simply has nowhere to
put, since it only forwards the four named keyword arguments query_issues actually accepts).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from core.codeintel import analyze
from core.copilot.service import _dispatch
from core.copilot.tools import CopilotContext
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from tests.redteam.payloads import load_payloads

PAYLOADS = load_payloads()


def _seed_asset_with_a_completed_scan(sessions: sessionmaker[Session], org_id: str) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref=f"https://example.com/{org_id}.git",
            source_label=f"{org_id}/repo", tools=["bandit"], org_id=org_id,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def _seed_finding(
    sessions: sessionmaker[Session], scan_id: str, finding_id: str, title: str
) -> None:
    with sessions() as s:
        f = Finding(
            finding_id,
            title,
            "d",
            Location("app/x.py", 2, 2),
            Taxonomy(Category.SAST, cwe=("CWE-89",)),
        )
        result = repo.sync_issues_for_scan(s, scan_id, [f])
        repo.add_findings(s, scan_id, [f], issue_updates=result.updates)


def _ctx(
    sessions: sessionmaker[Session], org_id: str, asset_id: str, checkout: Path
) -> CopilotContext:
    with sessions() as s:
        scan = repo.latest_scan_for_asset(s, asset_id)
        assert scan is not None
        return CopilotContext(
            session=s, org_id=org_id, asset_id=asset_id, latest_scan_id=scan.id,
            checkout=checkout, graph=analyze(checkout),
        )  # fmt: skip


def test_unknown_tool_name_from_an_injected_instruction_is_a_safe_error_not_a_crash(
    sessions: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    org_id = "org-redteam-a"
    asset_id = _seed_asset_with_a_completed_scan(sessions, org_id)
    ctx = _ctx(sessions, org_id, asset_id, tmp_path)

    # The kind of tool name an injected "you are now the security auditor" instruction (role-change
    # in the corpus) might try to invoke -- never one of the 5 real tool schemas.
    result = _dispatch(ctx, "delete_all_issues", {"payload": PAYLOADS["role-change"]})
    assert result == "error: unknown tool: delete_all_issues"


def test_query_issues_never_sees_another_assets_data_even_if_the_model_asks_for_it(
    sessions: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    org_a, org_b = "org-redteam-a", "org-redteam-b"
    asset_a = _seed_asset_with_a_completed_scan(sessions, org_a)
    asset_b = _seed_asset_with_a_completed_scan(sessions, org_b)
    with sessions() as s:
        scan_a = repo.latest_scan_for_asset(s, asset_a)
        scan_b = repo.latest_scan_for_asset(s, asset_b)
        assert scan_a is not None and scan_b is not None
    _seed_finding(sessions, scan_a.id, "fa1", f"Asset A secret finding. {PAYLOADS['role-change']}")
    _seed_finding(sessions, scan_b.id, "fb1", "Asset B secret finding, never for org A")

    ctx_a = _ctx(sessions, org_a, asset_a, tmp_path)

    # An attacker-controlled tool_input trying to redirect the query at asset B -- _dispatch's real
    # signature has nowhere to put "asset_id", so this key is simply dropped, never reaching
    # repo.list_asset_issues.
    out = _dispatch(ctx_a, "query_issues", {"asset_id": asset_b, "path_contains": ""})
    assert "Asset A secret finding" in out
    assert "Asset B secret finding" not in out
