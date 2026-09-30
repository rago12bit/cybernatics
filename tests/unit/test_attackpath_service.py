"""core.attackpath.service.find_attack_paths: the full fetch-issues -> apply-rules -> rank pass
(plan §21.6), against real persisted issues and (for the SSRF case) a real on-disk directory
analyzed by core.codeintel.analyze -- not hand-built fixtures, the same standard
test_embeddings_service.py and test_copilot_tools.py already hold this kind of pass to."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from core.attackpath.model import EdgeKind, Impact, Likelihood, NodeKind
from core.attackpath.service import find_attack_paths
from core.codeintel import analyze
from core.models import Category, Evidence, Finding, Location, Scoring, Severity, Taxonomy
from core.persistence import repo


def _seed_scan(sessions: sessionmaker[Session]) -> tuple[str, str]:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id="org-a",
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id, scan.id


def _seed_findings(
    sessions: sessionmaker[Session], scan_id: str, findings: list[Finding]
) -> dict[str, str]:
    with sessions() as s:
        result = repo.sync_issues_for_scan(s, scan_id, findings)
        repo.add_findings(s, scan_id, findings, issue_updates=result.updates)
        return {u.finding_id: u.issue_id for u in result.updates}


def test_ssrf_path_found_against_a_real_analyzed_checkout(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/preview')\n"
        "def preview():\n"
        "    return helper()\n\n"
        "def helper():\n"
        "    return sink()\n\n"
        "def sink():\n"
        "    import requests\n"
        "    return requests.get('http://x')\n"
    )
    graph = analyze(tmp_path)
    assert graph.entrypoints, "fixture must produce a real Flask entrypoint"

    asset_id, scan_id = _seed_scan(sessions)
    ssrf = Finding(
        "ssrf-1", "SSRF", "d", Location("app.py", 11, 11),
        Taxonomy(Category.SAST, cwe=("CWE-918",)),
        scoring=Scoring(normalized_severity=Severity.HIGH),
    )  # fmt: skip
    _seed_findings(sessions, scan_id, [ssrf])

    with sessions() as s:
        paths = find_attack_paths(s, asset_id, scan_id, graph)

    assert len(paths) == 1
    path = paths[0]
    assert path.likelihood is Likelihood.HIGH
    assert path.impact is Impact.HIGH
    assert {n.kind for n in path.nodes} == {NodeKind.ISSUE, NodeKind.CLOUD_RESOURCE}
    assert {e.kind for e in path.edges} == {EdgeKind.REACHABLE_FROM, EdgeKind.EXPOSES}


def test_no_ssrf_path_when_issue_is_unreachable(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text(
        "def sink():\n    import requests\n    return requests.get('http://x')\n"
    )
    graph = analyze(tmp_path)
    asset_id, scan_id = _seed_scan(sessions)
    ssrf = Finding(
        "ssrf-1", "SSRF", "d", Location("app.py", 3, 3), Taxonomy(Category.SAST, cwe=("CWE-918",)),
    )  # fmt: skip
    _seed_findings(sessions, scan_id, [ssrf])

    with sessions() as s:
        paths = find_attack_paths(s, asset_id, scan_id, graph)
    assert paths == []


def test_secret_and_iac_issues_chain_via_both_heuristic_rules(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    graph = analyze(tmp_path)  # empty checkout: rules 2/3 don't touch the code graph at all
    asset_id, scan_id = _seed_scan(sessions)
    secret = Finding(
        "secret-1", "AWS Access Key ID", "d", Location("config.py", 5, 5),
        Taxonomy(Category.SECRETS, cwe=("CWE-798",)),
        evidence=Evidence(rule_ids={"gitleaks": ["aws-access-key-id"]}),
    )  # fmt: skip
    resource = Finding(
        "iac-1", "Public S3 bucket", "d", Location("main.tf", 10, 10, snippet="aws_s3_bucket.data"),
        Taxonomy(Category.IAC),
    )  # fmt: skip
    workflow = Finding(
        "iac-2", "Insecure workflow", "d",
        Location(".github/workflows/deploy.yml", 8, 8, snippet="deploy"),
        Taxonomy(Category.IAC),
    )  # fmt: skip
    ids = _seed_findings(sessions, scan_id, [secret, resource, workflow])

    with sessions() as s:
        paths = find_attack_paths(s, asset_id, scan_id, graph)

    assert len(paths) == 2
    rule_ids = sorted(e.rule_id for p in paths for e in p.edges)
    assert rule_ids == ["ci-secret-workflow-v1", "secret-grants-resource-v1"]
    resource_labels = {p.nodes[1].label for p in paths}
    assert resource_labels == {"aws_s3_bucket.data", "deploy"}
    expected_cheapest = f"iss_{ids['secret-1']}"
    assert all(p.cheapest_link == expected_cheapest for p in paths)
    assert all(p.likelihood is Likelihood.MEDIUM for p in paths)
    assert all(p.impact is Impact.LOW for p in paths)
