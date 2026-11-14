from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.events import MemoryPublisher
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo
from core.persistence.models import FindingRow
from core.persistence.storage import MemoryStore
from core.pipeline import SECRETS_WITHHELD, run_scan_job
from core.scan import ToolOutcome


def finding(
    tool: str,
    cat: Category,
    path: str = "a.py",
    line: int = 1,
    sev: Severity = Severity.HIGH,
    fid: str | None = None,
) -> Finding:
    f = Finding(
        id=fid or f"{tool}:{path}:{line}",
        title=f"{tool} finding",
        description="d",
        location=Location(path, line, line, "code", "h"),
        taxonomy=Taxonomy(cat),
    )
    f.scoring.normalized_severity = sev
    f.evidence.reported_by = [tool]
    return f


def make_scan(
    s: Session,
    tools: list[str],
    ref: str,
    stype: str = "git",
    label: str = "lbl",
    *,
    pr_ref: str | None = None,
    asset_label: str | None = None,
) -> str:
    return repo.create_scan(
        s,
        source_type=stype,
        source_ref=ref,
        source_label=label,
        tools=tools,
        ref=pr_ref,
        asset_label=asset_label,
    ).id


def executor_from(table: dict[str, ToolOutcome]):  # type: ignore[no-untyped-def]
    def run(name: str, target: Path) -> ToolOutcome:
        out = table[name]
        if isinstance(out, Exception):
            raise out
        return out

    return run


def test_happy_path_persists_everything_and_publishes_progress(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit", "trivy"], str(sample_repo))
    table = {
        "bandit": ToolOutcome(
            "bandit", "ok", [finding("bandit", Category.SAST)], 1, 2.0, raw=b"RAW"
        ),
    }
    store, bus = MemoryStore(), MemoryPublisher()
    status = run_scan_job(sid, sessions, store, bus, executor_from(table))
    assert status == "completed"  # trivy skipped (no lockfiles), bandit ok
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.status == "completed" and scan.finished_at
        runs = {r.tool: r for r in scan.tool_runs}
        assert runs["trivy"].status == "skipped" and runs["bandit"].findings_count == 1
        assert runs["bandit"].raw_object_key == f"scans/{sid}/raw/bandit.json"
        assert s.query(FindingRow).count() == 1
    assert store.get(f"scans/{sid}/raw/bandit.json") == b"RAW"
    kinds = [e["type"] for _, e in bus.events]
    assert kinds[0] == "scan.started" and kinds[-1] == "scan.finished"
    assert kinds.count("tool.finished") == 2


def test_syft_produces_an_sbom_summary_and_typosquat_findings(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """plan §20.5: opting "syft" into a scan's tools produces `Scan.sbom_summary` (for the
    Dependencies screen) and folds typosquat Findings into the same persisted findings table as
    every other tool's -- with no `dependencies` array in this fixture, `direct_purls` is empty, so
    `enrich_direct_dependencies` makes zero network calls (nothing to resolve)."""
    import json as _json

    cyclonedx = _json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "bom-ref": "a",
                    "name": "reqeusts",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/reqeusts@1.0.0",
                },
                {
                    "bom-ref": "b",
                    "name": "flask",
                    "version": "2.0.0",
                    "purl": "pkg:pypi/flask@2.0.0",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                },
            ],
        }
    ).encode()
    with sessions() as s:
        sid = make_scan(s, ["syft"], str(sample_repo))
    table = {"syft": ToolOutcome("syft", "ok", [], raw=cyclonedx)}
    status = run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    assert status == "completed"
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.sbom_summary is not None
        assert scan.sbom_summary["components"] == 2
        by_name = {p["name"]: p for p in scan.sbom_summary["packages"]}
        assert by_name["flask"]["license"] == "BSD-3-Clause"
        assert by_name["reqeusts"]["relation"] == "unknown"  # no dependency graph in this fixture
        rows = s.query(FindingRow).all()
        assert len(rows) == 1  # the typosquat finding for "reqeusts"
        assert rows[0].data["evidence"]["reported_by"] == ["bulwark-typosquat"]


def test_partial_failure_is_reported_not_fatal(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit", "semgrep", "gitleaks"], str(sample_repo))
    table = {
        "bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST)]),
        "semgrep": ToolOutcome("semgrep", "timeout", error="wall-clock timeout"),
        "gitleaks": RuntimeError("boom"),  # type: ignore[dict-item]
    }
    bus = MemoryPublisher()
    assert run_scan_job(sid, sessions, MemoryStore(), bus, executor_from(table)) == "partial"
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None
        runs = {r.tool: r for r in scan.tool_runs}
        assert runs["semgrep"].status == "timeout" and runs["gitleaks"].status == "error"
        assert "boom" in (runs["gitleaks"].error or "")
        assert s.query(FindingRow).count() == 1  # the healthy tool's findings still landed


def test_all_tools_failing_marks_scan_failed(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    table = {"bandit": ToolOutcome("bandit", "error", error="docker down")}
    assert (
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
        == "failed"
    )


def test_raw_output_is_withheld_when_secrets_were_found(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """Threat T7: Bandit's raw JSON echoes the secret's source line, so it must not be stored."""
    with sessions() as s:
        sid = make_scan(s, ["bandit", "gitleaks"], str(sample_repo))
    table = {
        "bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST, line=20)],
                              raw=b'{"code": "KEY = \\"s3cr3t-value\\""}'),
        "gitleaks": ToolOutcome("gitleaks", "ok", [finding("gitleaks", Category.SECRETS, line=20)],
                                raw=b'[{"Secret": "REDACTED"}]'),
    }  # fmt: skip
    store = MemoryStore()
    run_scan_job(sid, sessions, store, MemoryPublisher(), executor_from(table))
    assert list(store.objects) == [f"scans/{sid}/raw/gitleaks.json"]
    assert all(b"s3cr3t-value" not in v for v in store.objects.values())
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None
        runs = {r.tool: r for r in scan.tool_runs}
        assert runs["bandit"].raw_withheld_reason == SECRETS_WITHHELD
        assert runs["bandit"].raw_object_key is None
        # and the snippet near the secret was redacted in the persisted finding too
        row = s.query(FindingRow).filter_by(finding_id="bandit:a.py:20").one()
        assert "withheld" in row.data["location"]["snippet"]


def test_ingestion_failure_fails_the_scan_with_a_safe_message(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(tmp_path / "does-not-exist"))
    bus = MemoryPublisher()
    assert run_scan_job(sid, sessions, MemoryStore(), bus, executor_from({})) == "failed"
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.status == "failed" and "not found" in (scan.error or "")
    assert bus.events[-1][1]["status"] == "failed"


def test_unexpected_crash_does_not_leak_internals(
    sessions: sessionmaker[Session], sample_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import core.pipeline as pl

    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    monkeypatch.setattr(
        pl, "detect_context", lambda ws: (_ for _ in ()).throw(KeyError("/etc/secret"))
    )
    assert (
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from({})) == "failed"
    )
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.error == "internal error while running the scan"


def test_rerun_is_idempotent(sessions: sessionmaker[Session], sample_repo: Path) -> None:
    """A redelivered Celery task (acks_late) must not duplicate tool runs or findings."""
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    table = {"bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST)])}
    for _ in range(2):
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        assert s.query(FindingRow).count() == 1
        scan = repo.get_scan(s, sid)
        assert scan is not None and len(scan.tool_runs) == 1


def test_uploaded_archive_is_deleted_after_the_scan(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    z = tmp_path / "up.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.py", "x=1")
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(z), stype="archive")
    table = {"bandit": ToolOutcome("bandit", "ok")}
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    assert not z.exists()


def test_unknown_scan_id_raises(sessions: sessionmaker[Session]) -> None:
    with pytest.raises(LookupError):
        run_scan_job("nope", sessions, MemoryStore(), MemoryPublisher())


# ---- repository queries -------------------------------------------------------------------
@pytest.fixture
def populated(sessions: sessionmaker[Session]) -> tuple[sessionmaker[Session], str]:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], "x")
        repo.add_findings(s, sid, [
            finding("bandit", Category.SAST, "src/b.py", 5, Severity.LOW),
            finding("semgrep", Category.SAST, "src/a.py", 9, Severity.CRITICAL),
            finding("trivy", Category.SCA, "package-lock.json", 1, Severity.HIGH),
            finding("trivy", Category.IAC, "main.tf", 3, Severity.HIGH),
            finding("bandit", Category.SAST, "src/b.py", 5, Severity.LOW),  # same id again: kept as bandit:src/b.py:5#2
        ])  # fmt: skip
    return sessions, sid


def test_query_filters_sort_and_paginate(populated: tuple[sessionmaker[Session], str]) -> None:
    sessions, sid = populated
    with sessions() as s:
        page = repo.query_findings(s, sid)
        assert page.total == 5
        assert [i["scoring"]["normalized_severity"] for i in page.items] == [
            "CRITICAL", "HIGH", "HIGH", "LOW", "LOW",
        ]  # fmt: skip
        assert repo.query_findings(s, sid, severities=["high"]).total == 2
        assert repo.query_findings(s, sid, categories=["sca", "iac"]).total == 2
        assert repo.query_findings(s, sid, tool="trivy").total == 2
        assert repo.query_findings(s, sid, tool="nope").total == 0
        by_path = repo.query_findings(s, sid, sort="path")
        assert [i["location"]["path"] for i in by_path.items][0] == "main.tf"
        assert repo.query_findings(s, sid, sort="risk").total == 5
        p2 = repo.query_findings(s, sid, limit=2, offset=2)
        assert p2.total == 5 and len(p2.items) == 2
        assert repo.severity_counts(s, sid) == {"LOW": 2, "CRITICAL": 1, "HIGH": 2}


def test_path_filter_treats_like_wildcards_literally(
    populated: tuple[sessionmaker[Session], str],
) -> None:
    sessions, sid = populated
    with sessions() as s:
        assert repo.query_findings(s, sid, path_contains="src/").total == 3
        assert repo.query_findings(s, sid, path_contains="%").total == 0  # not a wildcard
        assert repo.query_findings(s, sid, path_contains="_").total == 0


def test_colliding_finding_ids_are_disambiguated_not_dropped(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], "x")
        repo.add_findings(s, sid, [finding("t", Category.SAST, fid="same") for _ in range(3)])
        ids = sorted(r.finding_id for r in s.query(FindingRow).all())
    assert ids == ["same", "same#2", "same#3"]


def _code(tool: str, rule: str, line: int, snippet: str, cwe: str = "CWE-89") -> Finding:
    f = finding(tool, Category.SAST, line=line, fid=f"{tool}:{rule}:{line}")
    f.taxonomy = Taxonomy(Category.SAST, cwe=(cwe,))
    f.location = Location("a.py", line, line, snippet, "h")
    f.evidence.rule_ids = {tool: [rule]}
    return f


def test_pipeline_stores_correlated_findings_and_reports_dedup(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit", "semgrep"], str(sample_repo))
    same = "query = db.execute(build(user_input))"
    table = {
        "bandit": ToolOutcome("bandit", "ok", [_code("bandit", "B608", 5, same)]),
        "semgrep": ToolOutcome("semgrep", "ok", [_code("semgrep", "sqli", 6, same)]),
    }
    bus = MemoryPublisher()
    run_scan_job(sid, sessions, MemoryStore(), bus, executor_from(table))
    with sessions() as s:
        rows = s.query(FindingRow).all()
        assert len(rows) == 1  # 2 raw -> 1 stored
        data = rows[0].data
        assert data["evidence"]["reported_by"] == ["bandit", "semgrep"]
        assert data["evidence"]["agreement_count"] == 2
        assert rows[0].fingerprint.startswith("sha256:") and rows[0].tools == ["bandit", "semgrep"]
    done = bus.events[-1][1]
    assert (done["findings"], done["raw_findings"], done["dedup_rate"]) == (1, 2, 0.5)


def test_correlation_runs_before_redaction(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """Redacted snippets all look alike; if we redacted first, two DIFFERENT defects that sit
    next to a secret would collapse into one. Correlating first keeps them apart."""
    with sessions() as s:
        sid = make_scan(s, ["bandit", "semgrep", "gitleaks"], str(sample_repo))
    secret = finding("gitleaks", Category.SECRETS, line=6)
    secret.taxonomy = Taxonomy(Category.SECRETS, cwe=("CWE-798",))
    table = {
        "bandit": ToolOutcome("bandit", "ok", [_code("bandit", "B608", 5, "x = a(1) + b")]),
        "semgrep": ToolOutcome(
            "semgrep", "ok", [_code("semgrep", "sqli", 6, "render(template, payload); audit(z)")]
        ),
        "gitleaks": ToolOutcome("gitleaks", "ok", [secret]),
    }
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        rows = s.query(FindingRow).all()
        assert len(rows) == 3, "distinct defects must not be merged by redaction placeholders"
        assert all("withheld" in r.data["location"]["snippet"] or r.category == "secrets" for r in rows)  # fmt: skip


def test_stored_findings_carry_cwe_and_owasp_mapping(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """The API path (not just `scan()`) must enrich: a real run once stored SCA findings with no OWASP."""
    (sample_repo / "requirements.txt").write_text("requests==2.0.0\n")  # so Trivy applies
    with sessions() as s:
        sid = make_scan(s, ["bandit", "trivy", "gitleaks"], str(sample_repo))
    sast = finding("bandit", Category.SAST, line=3)
    sast.taxonomy = Taxonomy(Category.SAST, cwe=("89",))  # unnormalized on purpose
    sca = finding("trivy", Category.SCA, path="requirements.txt")  # no CWE at all
    secret = finding("gitleaks", Category.SECRETS, line=9)
    secret.taxonomy = Taxonomy(Category.SECRETS, cwe=("CWE-798",))
    table = {
        "bandit": ToolOutcome("bandit", "ok", [sast]),
        "trivy": ToolOutcome("trivy", "ok", [sca]),
        "gitleaks": ToolOutcome("gitleaks", "ok", [secret]),
    }
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        tax = {r.category: r.data["taxonomy"] for r in s.query(FindingRow).all()}
    assert tax["sast"]["cwe"] == ["CWE-89"] and tax["sast"]["owasp_top_10_2021"] == ["A03:2021"]
    assert tax["sca"]["owasp_top_10_2021"] == ["A06:2021"]
    assert tax["secrets"]["owasp_top_10_2021"] == ["A07:2021"]


def test_risk_is_scored_stored_and_drives_sort(
    sessions: sessionmaker[Session], sample_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KEV/EPSS lifts a finding above a same-severity one, end to end through the API path."""
    import core.postprocess as pp
    from core.risk import Feeds

    feeds = Feeds(
        epss={"CVE-2021-44228": 0.94}, kev={"CVE-2021-44228"}, epss_loaded=True, kev_loaded=True
    )
    real = pp.apply_risk
    monkeypatch.setattr(
        pp,
        "apply_risk",
        lambda fs, _=None, assess=None, verdict_lookup=None: real(fs, feeds, assess),
    )
    (sample_repo / "requirements.txt").write_text("x==1\n")
    with sessions() as s:
        sid = make_scan(s, ["trivy", "bandit"], str(sample_repo))
    hot = finding("trivy", Category.SCA, path="requirements.txt", fid="hot")
    hot.taxonomy = Taxonomy(Category.SCA, cve=("CVE-2021-44228",))
    cold = finding("bandit", Category.SAST, fid="cold")  # same HIGH severity, no exploit data
    table = {
        "trivy": ToolOutcome("trivy", "ok", [hot]),
        "bandit": ToolOutcome("bandit", "ok", [cold]),
    }
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        page = repo.query_findings(s, sid, sort="risk", limit=10)
    assert [f["id"] for f in page.items] == ["hot", "cold"]
    top = page.items[0]["scoring"]
    assert top["in_cisa_kev"] is True and top["epss_score"] == 0.94 and top["risk_score"] >= 90
    assert any("KEV" in x for x in top["risk_factors"])
    assert page.items[1]["scoring"]["risk_score"] < top["risk_score"]


def test_a_stored_triage_verdict_dampens_the_next_scan_of_the_same_asset(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """plan §21.3: a verdict is "one input to the ranker" -- it can't retroactively change a scan
    already persisted, but a verdict recorded against one occurrence must lower the risk score of
    the SAME finding (same fingerprint) reproduced by a LATER scan of the same asset, end to end
    through the real pipeline and `core.persistence.repo.assistant_verdicts_for_asset`."""
    with sessions() as s:
        sid1 = make_scan(s, ["bandit"], str(sample_repo))
    f = finding("bandit", Category.SAST, fid="f1")
    run_scan_job(
        sid1,
        sessions,
        MemoryStore(),
        MemoryPublisher(),
        executor_from({"bandit": ToolOutcome("bandit", "ok", [f])}),
    )
    with sessions() as s:
        baseline_row = s.query(FindingRow).filter_by(scan_id=sid1).one()
        baseline_score = baseline_row.data["scoring"]["risk_score"]
        issue_id = baseline_row.issue_id
        assert issue_id is not None
        repo.set_assistant_verdict(
            s, issue_id, verdict="likely_false_positive", confidence="high",
            rationale="parameterized elsewhere", lines=[1], model="fake-model-1",
        )  # fmt: skip

    with sessions() as s:
        sid2 = make_scan(s, ["bandit"], str(sample_repo))
    run_scan_job(
        sid2,
        sessions,
        MemoryStore(),
        MemoryPublisher(),
        executor_from({"bandit": ToolOutcome("bandit", "ok", [f])}),
    )
    with sessions() as s:
        second_row = s.query(FindingRow).filter_by(scan_id=sid2).one()
        assert second_row.issue_id == issue_id  # same Issue: this really is "the same finding"
        assert second_row.data["scoring"]["risk_score"] < baseline_score
        assert any(
            "Triage assistant: likely false positive" in fac
            for fac in second_row.data["scoring"]["risk_factors"]
        )
        # And the verdict never touched the human triage_status.
        assert repo.get_issue(s, issue_id).triage_status == "open"


def test_default_order_is_severity_then_risk_then_path(
    sessions: sessionmaker[Session],
) -> None:
    """Within one severity tier the riskiest finding comes first (both the SQL and the tool-filter path)."""
    with sessions() as s:
        sid = make_scan(s, ["trivy"], "u")
        fs = []
        for name, risk in [("a.py", 40), ("b.py", 90), ("c.py", None), ("d.py", 65)]:
            f = finding("trivy", Category.SCA, path=name, fid=name)
            f.scoring.risk_score = risk
            fs.append(f)
        low = finding("trivy", Category.SCA, path="z.py", sev=Severity.LOW, fid="z.py")
        low.scoring.risk_score = (
            99  # a high risk number never lifts a finding above a higher severity
        )
        repo.add_findings(s, sid, [*fs, low])
        want = ["b.py", "d.py", "a.py", "c.py", "z.py"]
        assert [i["id"] for i in repo.query_findings(s, sid).items] == want
        assert [i["id"] for i in repo.query_findings(s, sid, tool="trivy").items] == want


def test_issue_lifecycle_across_real_scans_of_the_same_asset(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """End-to-end through run_scan_job (ADR-0012): new -> open -> fixed -> reintroduced, and a
    completely different asset never sees any of it."""

    def scan_with(has_bug: bool) -> tuple[str | None, str | None]:
        with sessions() as s:
            sid = make_scan(s, ["bandit"], str(sample_repo), label="same-repo")
        line = "shell=True" if has_bug else "shell=False"
        table = {"bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST, line=1)])}
        table["bandit"].findings[0].location = Location("a.py", 1, 1, line, "h")
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
        with sessions() as s:
            rows = list(s.query(FindingRow).filter_by(scan_id=sid))
            return rows[0].issue_id if rows else None, rows[0].issue_state if rows else None

    id1, state1 = scan_with(True)
    assert state1 == "new"
    id2, state2 = scan_with(True)
    assert id2 == id1 and state2 == "open"  # same defect, second sighting: settles to open

    # a scan with a *different* asset label must never see this issue
    with sessions() as s:
        other_sid = make_scan(s, ["bandit"], str(sample_repo), label="a-different-repo")
    table = {"bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST, line=1)])}
    run_scan_job(other_sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        other_row = s.query(FindingRow).filter_by(scan_id=other_sid).one()
        assert other_row.issue_id != id1 and other_row.issue_state == "new"

    # fix it: bandit no longer reports anything for "same-repo"
    with sessions() as s:
        fixed_sid = make_scan(s, ["bandit"], str(sample_repo), label="same-repo")
    run_scan_job(fixed_sid, sessions, MemoryStore(), MemoryPublisher(), executor_from({"bandit": ToolOutcome("bandit", "ok", [])}))  # fmt: skip
    with sessions() as s:
        from core.persistence.models import IssueRow

        issue = s.get(IssueRow, id1)
        assert issue is not None and issue.state == "fixed" and issue.fixed_at is not None

    # reintroduce it
    id3, state3 = scan_with(True)
    assert id3 == id1 and state3 == "reintroduced"
    with sessions() as s:
        from core.persistence.models import IssueRow

        issue = s.get(IssueRow, id1)
        assert issue is not None and issue.fixed_at is None


def test_pr_scan_shows_new_in_this_pr_without_touching_the_real_asset(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """Plan §36: a PR-triggered scan (Scan.ref set) classifies its findings against the asset's
    real issue history -- via `asset_label`, the same asset an ordinary scan of this URL would
    resolve to -- but must never mutate that history: an issue elsewhere in the codebase that a
    PR's diff never touches must not look "fixed" just for being absent from this one scan."""
    url = str(sample_repo)
    with sessions() as s:
        main_sid = make_scan(s, ["bandit"], url, label=url)
    table = {"bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST, path="a.py")])}
    run_scan_job(main_sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        from core.persistence.models import IssueRow

        main_scan = repo.get_scan(s, main_sid)
        assert main_scan is not None
        known_issue = s.query(IssueRow).filter_by(asset_id=main_scan.asset_id).one()
        assert known_issue.state == "new"  # its only sighting so far
        known_issue_id = known_issue.id

    with sessions() as s:
        pr_sid = make_scan(
            s, ["bandit"], url, label=f"{url}#7", pr_ref="refs/pull/7/head", asset_label=url
        )
    new_finding = finding("bandit", Category.SAST, path="b.py", fid="bandit:b.py:1")
    # A distinct rule id, or `fallback_key` (correctly) treats this as the *same* defect merely
    # moved to a new path -- real product behavior (ADR-0012), not something to work around here.
    new_finding.evidence.rule_ids = {"bandit": ["B999-different-rule"]}
    pr_table = {
        "bandit": ToolOutcome(
            "bandit",
            "ok",
            [finding("bandit", Category.SAST, path="a.py"), new_finding],  # already known  # new
        )
    }
    run_scan_job(pr_sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(pr_table))

    with sessions() as s:
        from core.persistence.models import IssueRow

        pr_scan, main_scan = repo.get_scan(s, pr_sid), repo.get_scan(s, main_sid)
        assert pr_scan is not None and main_scan is not None
        assert pr_scan.asset_id == main_scan.asset_id  # the PR resolves to the SAME asset

        rows = {r.finding_id: r for r in s.query(FindingRow).filter_by(scan_id=pr_sid)}
        assert rows["bandit:a.py:1"].issue_state == "open"  # already known before this PR
        assert rows["bandit:a.py:1"].issue_id == known_issue_id
        assert rows["bandit:b.py:1"].issue_state == "new"  # introduced by this PR
        assert rows["bandit:b.py:1"].issue_id is None  # no real Issue minted for a PR-only finding

        # the PR scan created no second IssueRow and left the real one completely untouched
        issues = s.query(IssueRow).filter_by(asset_id=main_scan.asset_id).all()
        assert [i.id for i in issues] == [known_issue_id]
        assert issues[0].state == "new" and issues[0].fixed_at is None


def test_a_server_side_scan_keeps_the_code_of_each_taint_path_step(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    """`finalize` reads the lines around each step from the scan workspace. It ran after the
    workspace was deleted, so every step of a scan run by the worker was stored with no code
    (the CLI, which scans a directory that stays, had it)."""
    src = tmp_path / "repo"
    src.mkdir()
    (src / "app.py").write_text(
        "from flask import request\n\n"
        '@app.route("/search")\n'
        "def search():\n"
        '    q = request.args.get("q")\n'
        "    return helper(q)\n\n"
        "def helper(term):\n"
        '    query = "SELECT * FROM t WHERE name = \'" + term + "\'"\n'
        "    return db.execute(query)\n"
    )
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(src))
    sink = finding("bandit", Category.SAST, path="app.py", line=10)
    table = {"bandit": ToolOutcome("bandit", "ok", [sink], 1, 1.0, raw=b"RAW")}
    assert run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table)) == (
        "completed"
    )
    with sessions() as s:
        steps = s.query(FindingRow).one().data["taint_path"]
    assert [st["line"] for st in steps] == [4, 6, 10]
    assert "def search():" in steps[0]["snippet"] and "helper(q)" in steps[1]["snippet"]
    assert "db.execute(query)" in steps[2]["snippet"] and steps[2]["is_sink"]


def test_a_crash_while_saving_fails_the_scan_at_once(
    sessions: sessionmaker[Session], sample_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the tools were inside the failure handling: anything that raised after them left the
    scan "running", with no final event, until housekeeping reaped it thirty minutes later."""
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    table = {"bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST)], 1, 1.0)}

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("the database went away")

    monkeypatch.setattr(repo, "add_findings", boom)
    bus = MemoryPublisher()
    assert run_scan_job(sid, sessions, MemoryStore(), bus, executor_from(table)) == "failed"
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.status == "failed" and scan.finished_at
        assert scan.error == "internal error while saving the scan's results"
    last = bus.events[-1][1]
    assert last["type"] == "scan.finished" and last["status"] == "failed"
