"""Week 33: the project overview API (plan §28.1) -- /assets and /assets/{id}/overview, built
entirely from existing scan/issue data (see core/persistence/repo.py's asset-overview functions).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

import api.main as api_main
from api.deps import AppState
from api.main import create_app
from core.config import Settings
from core.gitfetch import validate_git_url
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PUBLIC = lambda host: ["140.82.112.3"]  # noqa: E731

FindingFactory = Callable[..., Finding]


class _FakeSubscriber:
    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        return
        yield  # pragma: no cover - makes this an async generator


@pytest.fixture
def env(sessions: sessionmaker[Session], tmp_path: Any, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(api_main, "validate_git_url", lambda url: validate_git_url(url, PUBLIC))
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token=TOKEN, workdir=tmp_path,
        upload_dir=tmp_path / "uploads", max_upload_bytes=1000,
    )  # fmt: skip
    app = create_app(AppState(settings, sessions, lambda sid, org: None, _FakeSubscriber()))  # fmt: skip
    return TestClient(app), sessions, settings


def _finding(fid: str, path: str, sev: Severity, *, cat: Category = Category.SAST) -> Finding:
    # core.issues.match_keys() matches on a *primary* key (fingerprint) first, falling back to a
    # location-independent key (category + a hash of the snippet's normalized tokens) whenever the
    # primary key is new. That fallback intentionally treats snippets as equal once identifiers and
    # literals are normalized to generic "ID"/"NUM"/"STR" tokens (so a renamed variable still
    # matches) -- which means two *different*, unrelated test findings with equally-generic
    # placeholder snippets would collide onto the same fallback key and be merged into one Issue.
    # A placeholder-marker snippet (the same one production code uses for a redacted secret) makes
    # fallback_key() return None outright, matching purely on the `fingerprint` this test controls.
    f = Finding(
        fid,
        f"title {fid}",
        "desc",
        Location(path, 1, 1, snippet="[snippet withheld: test]"),
        Taxonomy(cat),
    )
    f.scoring.normalized_severity = sev
    f.scoring.risk_score = {"CRITICAL": 90, "HIGH": 70, "LOW": 20}[sev.value]
    f.evidence.reported_by = ["bandit"]
    # The real pipeline computes this via core.correlation.engine.fingerprint before syncing issues
    # (core/pipeline.py); a plain Finding() leaves it "" for every instance, which would make every
    # finding here collide onto the same Issue (same category, same empty key) once synced. `fid`
    # is already unique per test finding, so it's a fine stand-in identity for this test's purposes.
    f.fingerprint = f"fp-{fid}"
    return f


def _run_scan(
    sessions: sessionmaker[Session],
    findings: list[Finding],
    *,
    org_id: str = DEFAULT_ORG_ID,
    label: str = "acme/payments-api",
) -> str:
    """Mirrors what core/pipeline.py actually does: sync issues against the asset, then persist
    findings carrying the resulting issue_id/state, then mark the scan completed."""
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="u", source_label=label, tools=["bandit"],
            org_id=org_id,
        )  # fmt: skip
        repo.add_tool_run(s, scan.id, "bandit", {"status": "ok", "findings": len(findings), "exit_code": 1, "duration_seconds": 1.2})  # fmt: skip
        result = repo.sync_issues_for_scan(s, scan.id, findings)
        repo.add_findings(s, scan.id, findings, issue_updates=result.updates)
        repo.finish_scan(s, scan.id, "completed")
        return scan.id


def test_list_assets_reflects_latest_scan(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    _run_scan(sessions, [_finding("f1", "a.py", Severity.HIGH)])
    assets = client.get("/assets", headers=AUTH).json()
    assert len(assets) == 1
    a = assets[0]
    assert a["label"] == "acme/payments-api"
    assert a["latest_scan_status"] == "completed"
    assert a["open_issue_count"] == 1


def test_overview_for_a_fresh_project_treats_everything_as_new(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    _run_scan(
        sessions,
        [
            _finding("f1", "a.py", Severity.CRITICAL),
            _finding("f2", "b.py", Severity.HIGH),
            _finding("f3", "c.py", Severity.LOW),
        ],
    )
    asset_id = client.get("/assets", headers=AUTH).json()[0]["id"]
    ov = client.get(f"/assets/{asset_id}/overview", headers=AUTH).json()

    assert ov["verdict_count"] == 2  # critical + high, both reachable (unset -> not False)
    assert len(ov["fix_first"]) == 3
    assert ov["fix_first"][0]["scoring"]["normalized_severity"] == "CRITICAL"  # risk-sorted
    assert ov["more_at_lower_risk"] == 0  # all 3 open issues are shown in fix_first already
    assert ov["since_previous_scan"] == {"fixed": 0, "new": 3, "returned": 0}
    assert len(ov["trend"]) == 1 and ov["trend"][0]["open_count"] == 3
    assert ov["scanned"] == [{"tool": "bandit", "status": "ok", "findings": 3}]


def test_overview_second_scan_shows_real_fixed_and_new_deltas(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    _run_scan(
        sessions,
        [
            _finding("f1", "a.py", Severity.CRITICAL),  # will be fixed
            _finding("f2", "b.py", Severity.HIGH),  # stays open
        ],
    )
    # Second scan: f1 is gone (fixed), f2 recurs (open), f3 is genuinely new.
    _run_scan(
        sessions,
        [
            _finding("f2", "b.py", Severity.HIGH),
            _finding("f3", "c.py", Severity.CRITICAL),
        ],
    )
    asset_id = client.get("/assets", headers=AUTH).json()[0]["id"]
    ov = client.get(f"/assets/{asset_id}/overview", headers=AUTH).json()

    assert ov["since_previous_scan"] == {"fixed": 1, "new": 1, "returned": 0}
    assert len(ov["trend"]) == 2
    assert ov["trend"][0]["open_count"] == 2  # after scan 1: f1, f2 open
    assert ov["trend"][1]["open_count"] == 2  # after scan 2: f2, f3 open (f1 fixed)
    assert ov["asset"]["open_issue_count"] == 2


def test_overview_is_org_scoped_like_every_other_asset_read(env) -> None:  # type: ignore[no-untyped-def]
    client, sessions, _ = env
    _run_scan(sessions, [_finding("f1", "a.py", Severity.HIGH)], org_id="org-a")
    org_a = {**AUTH, "X-Bulwark-Org": "org-a"}
    org_b = {**AUTH, "X-Bulwark-Org": "org-b"}
    asset_id = client.get("/assets", headers=org_a).json()[0]["id"]
    assert client.get(f"/assets/{asset_id}/overview", headers=org_a).status_code == 200
    assert client.get(f"/assets/{asset_id}/overview", headers=org_b).status_code == 404
    assert client.get("/assets", headers=org_b).json() == []


def test_overview_unknown_and_malformed_asset_id_is_404(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    assert client.get("/assets/00000000-0000-0000-0000-000000000000/overview", headers=AUTH).status_code == 404  # fmt: skip
    assert client.get("/assets/not-a-uuid/overview", headers=AUTH).status_code == 404


def test_overview_requires_auth_and_scope(env) -> None:  # type: ignore[no-untyped-def]
    client = env[0]
    assert client.get("/assets").status_code == 401
    assert client.get("/assets/00000000-0000-0000-0000-000000000000/overview").status_code == 401
