from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cli.main import app
from core.ci import COMMENT_MARKER, breaches, compare, load_scan, markdown_comment
from core.ci.compare import Scan
from core.ci.github import BOT, CommentError, upsert_comment
from core.ci.report import md

runner = CliRunner()


def finding(
    fp: str, sev: str = "HIGH", title: str = "t", path: str = "a.py", line: int = 1, risk: int = 50
) -> dict[str, Any]:
    return {
        "id": f"id-{fp}", "fingerprint": fp, "title": title,
        "location": {"path": path, "start_line": line, "end_line": line},
        "scoring": {"normalized_severity": sev, "risk_score": risk},
        "taxonomy": {"category": "sast", "cwe": [], "owasp_top_10_2021": [], "cve": [], "aliases": []},
        "evidence": {"reported_by": ["bandit"], "agreement_count": 1, "rule_ids": {"bandit": ["B1"]}},
        "remediation": {"summary": "", "references": []}, "description": "", "package": None,
    }  # fmt: skip


def scan_of(*fs: dict[str, Any], status: str = "ok") -> Scan:
    return Scan(
        findings=list(fs),
        tool_status={"bandit": {"status": status}},
        raw_findings=len(fs),
        unique_findings=len(fs),
    )


def write(p: Path, s: Scan) -> Path:
    p.write_text(
        json.dumps(
            {
                "findings": s.findings,
                "tool_status": s.tool_status,
                "stats": {
                    "raw_findings": s.raw_findings,
                    "unique_findings": s.unique_findings,
                    "dedup_rate": 0,
                },
            }
        )
    )
    return p


# ---- compare ------------------------------------------------------------------------------------


def test_new_existing_and_fixed_are_told_apart_by_fingerprint() -> None:
    base = scan_of(finding("a"), finding("b"))
    head = scan_of(finding("b", line=99), finding("c"))  # b moved lines: still the same defect
    c = compare(head, base)
    assert [f["fingerprint"] for f in c.new] == ["c"]
    assert (c.existing, c.fixed, c.baseline_available) == (1, 1, True)
    assert c.gate_set() == c.new


def test_without_a_baseline_everything_counts() -> None:
    c = compare(scan_of(finding("a")), None)
    assert not c.baseline_available and len(c.gate_set()) == 1


def test_a_baseline_with_a_failed_scanner_is_not_trusted() -> None:
    # If the base scan lost a tool, its findings would all look "new" in the head scan.
    c = compare(scan_of(finding("a")), scan_of(status="error"))
    assert not c.baseline_available and len(c.gate_set()) == 1


def test_load_scan_validates(tmp_path: Path) -> None:
    good = write(tmp_path / "g.json", scan_of(finding("a")))
    assert len(load_scan(good).findings) == 1
    for name, text in {
        "bad.json": "nope",
        "nofind.json": "{}",
        "wrong.json": '{"findings": [1]}',
    }.items():
        (tmp_path / name).write_text(text)
        with pytest.raises(ValueError, match="not valid Bulwark scan output"):
            load_scan(tmp_path / name)


# ---- gate ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fail_on,expected", [("none", 0), ("low", 5), ("medium", 4), ("high", 3), ("critical", 1)]
)
def test_threshold_counts(fail_on: str, expected: int) -> None:
    fs = [finding(s, sev=s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")] + [
        finding("i", sev="HIGH")
    ]
    fs[-1]["scoring"]["normalized_severity"] = "HIGH"
    assert (
        len(breaches(fs, fail_on))
        == {"none": 0, "low": 5, "medium": 4, "high": 3, "critical": 1}[fail_on]
        == expected
    )


def test_info_never_trips_a_threshold_and_bad_names_are_rejected() -> None:
    assert breaches([finding("x", sev="INFO")], "low") == []
    with pytest.raises(ValueError):
        breaches([], "severe")


# ---- comment text -------------------------------------------------------------------------------


def test_comment_lists_new_findings_ranked_with_counts() -> None:
    c = compare(
        scan_of(finding("a", risk=10), finding("b", sev="CRITICAL", risk=90, title="Worse")),
        scan_of(),
    )
    body = markdown_comment(c, "high", True)
    assert body.startswith(COMMENT_MARKER)
    assert "**2 new findings introduced by this change** (1 critical, 1 high)" in body
    assert body.index("Worse") < body.index("| 10 |")
    assert "**Failing.**" in body


def test_comment_says_when_nothing_is_new_and_when_no_baseline() -> None:
    assert "No new findings introduced" in markdown_comment(
        compare(scan_of(finding("a")), scan_of(finding("a"))), "high", False
    )
    assert "could not be scanned cleanly" in markdown_comment(
        compare(scan_of(finding("a")), None), "none", False
    )


def test_comment_warns_about_incomplete_scanners() -> None:
    assert "did not complete" in markdown_comment(
        compare(scan_of(finding("a"), status="timeout"), None), "none", False
    )


def test_comment_caps_the_list_and_total_size() -> None:
    many = [finding(str(i), title="x" * 500) for i in range(300)]
    body = markdown_comment(compare(scan_of(*many), scan_of()), "none", False)
    assert "…and 280 more" in body and len(body) < 60_100
    assert body.count("\n| ") <= 22


def test_untrusted_text_cannot_inject_markdown_links_mentions_or_html() -> None:
    evil = finding(
        "e",
        title="[pwn](https://evil) @octocat <img src=x onerror=1> **b** ![i](https://t/x)\nnew line",
        path="a`|b\n.py",
    )
    body = markdown_comment(compare(scan_of(evil), scan_of()), "none", False)
    row = next(ln for ln in body.splitlines() if ln.startswith("| HIGH"))
    assert "[pwn](" not in row.replace("\\[pwn\\]\\(", "")
    assert "@octocat" not in row and "@​octocat" in row
    assert not re.search(
        r"(?<!\\)[<>\[\]()!*]", row.split("|")[2]
    )  # every markup character is escaped
    assert row.count("|") == 5  # the path could not add table cells
    assert "\n" not in row


def test_md_strips_control_and_bidi_characters() -> None:
    assert md("a\u202eb\x00c") == "abc"


def test_run_url_is_only_linked_when_https() -> None:
    c = compare(scan_of(finding("a")), None)
    assert "[Workflow run](https://github.com/o/r/actions/runs/1)" in markdown_comment(
        c, "none", False, "https://github.com/o/r/actions/runs/1"
    )
    assert "Workflow run" not in markdown_comment(c, "none", False, "javascript:alert(1)")


# ---- posting the comment ------------------------------------------------------------------------


class Fake:
    def __init__(
        self, comments: list[dict[str, Any]], status: int = 200, write_status: int = 201
    ) -> None:
        self.comments, self.status, self.write_status, self.calls = (
            comments,
            status,
            write_status,
            [],
        )

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, Any]:
        self.calls.append((method, url, headers, body))
        if method == "GET":
            return self.status, self.comments
        return self.write_status, {}


BODY = f"{COMMENT_MARKER}\nhello"


def test_creates_the_comment_when_none_exists() -> None:
    t = Fake([{"id": 1, "body": "unrelated", "user": {"login": "someone"}}])
    assert upsert_comment("o/r", 7, BODY, "tok", transport=t) == "created"
    method, url, headers, body = t.calls[-1]
    assert (method, url) == ("POST", "https://api.github.com/repos/o/r/issues/7/comments")
    assert headers["Authorization"] == "Bearer tok" and json.loads(body or b"")["body"] == BODY


def test_updates_only_the_bots_own_comment_not_a_users_quote_of_the_marker() -> None:
    t = Fake(
        [
            {"id": 5, "body": BODY, "user": {"login": "attacker"}},
            {"id": 9, "body": BODY, "user": {"login": BOT}},
        ],
        write_status=200,
    )
    assert upsert_comment("o/r", 7, BODY, "tok", transport=t) == "updated"
    assert t.calls[-1][:2] == ("PATCH", "https://api.github.com/repos/o/r/issues/comments/9")


def test_a_spoofed_marker_alone_creates_a_new_comment() -> None:
    t = Fake([{"id": 5, "body": BODY, "user": {"login": "attacker"}}])
    assert upsert_comment("o/r", 7, BODY, "tok", transport=t) == "created"


@pytest.mark.parametrize(
    "kw",
    [
        {"repo": "no-slash"},
        {"repo": "o/r/../x"},
        {"repo": "o/r; rm"},
        {"api_url": "http://api.github.com"},
        {"pr_number": 0},
        {"token": ""},
        {"body": "no marker"},
    ],
)
def test_bad_inputs_are_refused_before_any_request(kw: dict[str, Any]) -> None:
    args = {"repo": "o/r", "pr_number": 7, "body": BODY, "token": "t", **kw}
    t = Fake([])
    with pytest.raises(CommentError):
        upsert_comment(
            args["repo"],
            args["pr_number"],
            args["body"],
            args["token"],
            **({"api_url": kw["api_url"]} if "api_url" in kw else {}),
            transport=t,
        )
    assert t.calls == []


def test_forbidden_listing_and_failed_write_are_reported() -> None:
    with pytest.raises(CommentError, match="fork"):
        upsert_comment("o/r", 7, BODY, "t", transport=Fake([], status=403))
    with pytest.raises(CommentError, match="HTTP 422"):
        upsert_comment("o/r", 7, BODY, "t", transport=Fake([], write_status=422))


# ---- CLI ----------------------------------------------------------------------------------------


def test_cli_compare_gates_on_new_findings_only(tmp_path: Path) -> None:
    base = write(tmp_path / "base.json", scan_of(finding("old", sev="CRITICAL")))
    head = write(
        tmp_path / "head.json", scan_of(finding("old", sev="CRITICAL"), finding("n", sev="LOW"))
    )
    r = runner.invoke(
        app, ["ci", "compare", "--head", str(head), "--base", str(base), "--fail-on", "high"]
    )
    assert r.exit_code == 0, r.output  # the existing critical is not this change's fault
    assert "1 new finding(s); 0 at or above 'high'" in r.output
    head2 = write(tmp_path / "head2.json", scan_of(finding("old"), finding("n2", sev="HIGH")))
    r = runner.invoke(
        app, ["ci", "compare", "--head", str(head2), "--base", str(base), "--fail-on", "high"]
    )
    assert r.exit_code == 1 and "failing the check" in r.output


def test_cli_without_a_base_gates_on_everything(tmp_path: Path) -> None:
    head = write(tmp_path / "h.json", scan_of(finding("x", sev="HIGH")))
    assert (
        runner.invoke(app, ["ci", "compare", "--head", str(head), "--fail-on", "high"]).exit_code
        == 1
    )
    assert (
        runner.invoke(app, ["ci", "compare", "--head", str(head), "--fail-on", "none"]).exit_code
        == 0
    )


def test_cli_writes_sarif_comment_summary_and_outputs(tmp_path: Path) -> None:
    head = write(tmp_path / "h.json", scan_of(finding("x")))
    out = {k: tmp_path / k for k in ("s.sarif", "c.md", "sum.md", "gh.out")}
    (tmp_path / "sum.md").write_text("earlier\n")
    r = runner.invoke(app, ["ci", "compare", "--head", str(head), "--sarif-out", str(out["s.sarif"]), "--comment-out", str(out["c.md"]),
                            "--summary-out", str(out["sum.md"]), "--github-output", str(out["gh.out"]), "--label", "repo"])  # fmt: skip
    assert r.exit_code == 0, r.output
    sarif = json.loads(out["s.sarif"].read_text())
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == 1
    assert out["c.md"].read_text().startswith(COMMENT_MARKER)
    assert (
        out["sum.md"].read_text().startswith("earlier\n")
        and COMMENT_MARKER in out["sum.md"].read_text()
    )
    assert out["gh.out"].read_text().splitlines() == [
        "new-findings=1",
        "total-findings=1",
        "failed=false",
        "baseline=false",
    ]


def test_cli_rejects_bad_input_with_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "b.json"
    bad.write_text("nope")
    r = runner.invoke(app, ["ci", "compare", "--head", str(bad)])
    assert r.exit_code == 2 and "not valid Bulwark scan output" in r.output
    ok = write(tmp_path / "ok.json", scan_of())
    assert (
        runner.invoke(app, ["ci", "compare", "--head", str(ok), "--fail-on", "severe"]).exit_code
        == 2
    )


def test_cli_missing_base_file_is_treated_as_no_baseline(tmp_path: Path) -> None:
    head = write(tmp_path / "h.json", scan_of(finding("x")))
    r = runner.invoke(
        app, ["ci", "compare", "--head", str(head), "--base", str(tmp_path / "none.json")]
    )
    assert r.exit_code == 0 and "1 total finding(s)" in r.output


def test_cli_comment_warns_instead_of_failing_unless_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = tmp_path / "c.md"
    body.write_text(BODY)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    args = ["ci", "comment", "--body", str(body), "--repo", "o/r", "--pr", "1"]
    r = runner.invoke(app, args)
    assert r.exit_code == 0 and "comment not posted" in r.output
    assert runner.invoke(app, [*args, "--strict"]).exit_code == 1
