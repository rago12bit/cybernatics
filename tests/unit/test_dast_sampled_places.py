"""A ZAP report samples the places an alert fires, so a place it stops listing is held open while the
same rule still fires on the same host -- in a native campaign and in an import alike.

Measured 2026-10-08 on one unchanged OWASP Juice Shop v17.3.0 with ZAP 2.17.0 (`zap-baseline.py`):
the two vendored reports (tests/fixtures/dast/zap-baseline-juiceshop-{1,2}.json) are consecutive
runs with default settings. Systemic alerts list 5 places each, and 4 places in the first are not in
the second although nothing changed; before this, the second run closed those 4 Issues.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core.dast.adapters.zap import _parse_report
from core.dast.mapping import crawl_samples, dast_finding, sampled_places, target_of
from core.imports.parsers import get_parser, run_parser_on_bytes
from core.imports.prepare import prepare
from core.imports.reimport import plan_reimport
from core.imports.service import apply_import, preview_import, revert_latest_import
from core.issues import ExistingIssue
from core.models import Finding, Severity
from core.persistence import repo
from core.persistence.models import FindingRow, IssueRow
from tests.unit.test_import_service import ORG, digest, setup

FIXTURES = Path("tests/fixtures/dast")
RUN_1 = json.loads((FIXTURES / "zap-baseline-juiceshop-1.json").read_text())
RUN_2 = json.loads((FIXTURES / "zap-baseline-juiceshop-2.json").read_text())


def _places(report: dict) -> set[tuple[str, str, str]]:
    """(plugin, host, route) for every listed instance, read straight from the report."""
    out = set()
    for site in report["site"]:
        for alert in site["alerts"]:
            for inst in alert.get("instances", []):
                host, route = target_of(inst["uri"])
                out.add((alert["pluginid"], host, route))
    return out


# --- which tools sample --------------------------------------------------------------------------


def test_zap_by_any_of_its_names_samples_and_nuclei_does_not() -> None:
    for tool in ("zap", "zap-baseline", "OWASP Zed Attack Proxy (ZAP)", "zaproxy"):
        assert sampled_places("https://shop.test", {tool: ["10038"]}) == {
            ("10038", "https://shop.test")
        }, tool
    assert sampled_places("https://shop.test", {"nuclei": ["tech-detect"]}) == set()
    assert sampled_places("https://shop.test", {"burp": ["5245344"]}) == set()
    assert sampled_places("", {"zap": ["10038"]}) == set()  # no host, no place


def test_crawl_samples_reads_only_web_findings() -> None:
    web = dast_finding("zap", rule="10038", title="CSP", host="https://shop.test", route="/a",
                       severity=Severity.MEDIUM, native="Medium")  # fmt: skip
    nuclei = dast_finding("nuclei", rule="x", title="X", host="https://shop.test", route="/b",
                          severity=Severity.LOW, native="low")  # fmt: skip
    assert crawl_samples([web, nuclei]) == {("10038", "https://shop.test")}


# --- the decision ---------------------------------------------------------------------------------


def _existing(*ids: str) -> list[ExistingIssue]:
    return [ExistingIssue(i, "dast", f"fp-{i}", None, "open") for i in ids]


def test_held_is_neither_closed_nor_detached_and_detached_wins() -> None:
    plan = plan_reimport(
        [], _existing("a", "b", "c"), previous_issue_ids={"a", "b", "c"},
        other_live_issue_ids={"b"}, held_issue_ids={"a", "b"},
    )  # fmt: skip
    assert plan.held_issue_ids == ("a",)
    assert plan.detached_issue_ids == ("b",)  # another source still reports it: that says more
    assert plan.closed_issue_ids == ("c",)
    assert plan.counts["held"] == 1 and plan.resulting_states() == {"c": "fixed"}


def test_without_close_missing_nothing_is_held_either() -> None:
    plan = plan_reimport(
        [], _existing("a"), previous_issue_ids={"a"}, held_issue_ids={"a"}, close_missing=False
    )
    assert plan.counts == {"new": 0, "unchanged": 0, "reopened": 0, "closed": 0, "detached": 0,
                           "held": 0}  # fmt: skip


# --- a native campaign, on two real runs ----------------------------------------------------------


def _scan(s: Session, findings: list[Finding]) -> list[str]:
    sc = repo.create_scan(s, source_type="git", source_ref="https://x", source_label="a/b",
                          tools=["zap-baseline"], org_id=ORG)  # fmt: skip
    result = repo.sync_issues_for_scan(s, sc.id, findings)
    repo.add_findings(s, sc.id, findings, result.updates)
    repo.finish_scan(s, sc.id, "completed")
    return result.fixed_issue_ids


def _issue_places(s: Session, asset_id: str) -> dict[tuple[str, str, str], str]:
    """(plugin, host, route) -> the Issue's state, from each Issue's latest stored finding."""
    out = {}
    for issue in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id)):
        row = s.scalars(
            select(FindingRow).where(FindingRow.issue_id == issue.id).order_by(FindingRow.pk.desc())
        ).first()
        assert row is not None
        loc, rules = row.data["location"], row.data["evidence"]["rule_ids"]
        (rule,) = {r for rs in rules.values() for r in rs}
        out[(rule, loc["host"], loc["route"])] = issue.state
    return out


def test_a_second_unchanged_zap_run_closes_nothing(sessions: sessionmaker[Session]) -> None:
    first, second = _places(RUN_1), _places(RUN_2)
    gone = first - second
    assert gone and {(p, h) for p, h, _ in gone} <= {(p, h) for p, h, _ in second}

    with sessions() as s:
        asset_id, _ = setup(s)
        assert _scan(s, prepare(_parse_report(RUN_1))) == []
        assert _scan(s, prepare(_parse_report(RUN_2))) == []  # was: the 4 places in `gone`
        states = _issue_places(s, asset_id)
    assert {states[p] for p in gone} == {"new"}  # held: untouched since the first run
    assert "fixed" not in states.values()


def test_once_the_rule_is_gone_from_the_host_every_place_of_it_closes(
    sessions: sessionmaker[Session],
) -> None:
    """The CSP header gets set: the next run has no CSP alert at all. Every CSP Issue closes,
    including the places only the first run listed, which the second had held open."""
    csp = "10038"
    fixed_run = {
        "site": [
            {**site, "alerts": [a for a in site["alerts"] if a["pluginid"] != csp]}
            for site in RUN_2["site"]
        ]
    }
    with sessions() as s:
        asset_id, _ = setup(s)
        _scan(s, prepare(_parse_report(RUN_1)))
        _scan(s, prepare(_parse_report(RUN_2)))
        _scan(s, prepare(_parse_report(fixed_run)))
        states = _issue_places(s, asset_id)
    csp_states = {p: st for p, st in states.items() if p[0] == csp}
    assert len(csp_states) > 5  # both runs' samples
    assert set(csp_states.values()) == {"fixed"}
    assert "fixed" not in {st for p, st in states.items() if p[0] != csp}


# --- an import: held Issues stay this Test's to close ---------------------------------------------

HOST = "https://shop.test"


def zap_json(alerts: dict[str, list[str]]) -> bytes:
    return json.dumps({
        "@programName": "ZAP",
        "site": [{"@name": HOST, "alerts": [
            {"pluginid": p, "alert": f"Rule {p}", "riskcode": "2", "confidence": "2",
             "cweid": "693", "instances": [{"uri": f"{HOST}{r}"} for r in routes]}
            for p, routes in alerts.items()
        ]}],
    }).encode()  # fmt: skip


def _import(s: Session, test_id: str, alerts: dict[str, list[str]], n: int):
    result = run_parser_on_bytes(get_parser("zap"), zap_json(alerts))
    assert result.complete, result.error
    return apply_import(
        s, org_id=ORG, test_id=test_id, findings=prepare(result.findings), parser="zap",
        file_digest=digest(n), file_name=f"zap-{n}.json",
    ).record  # fmt: skip


def test_a_held_issue_is_closed_by_a_later_import_that_shows_the_rule_gone(
    sessions: sessionmaker[Session],
) -> None:
    sample_1 = [f"/a{i}" for i in range(5)]
    sample_2 = [f"/b{i}" for i in range(5)]
    with sessions() as s:
        asset_id, t = setup(s, "ZAP")
        one = _import(s, t["ZAP"], {"10038": sample_1, "10020": ["/x"]}, 1)
        assert one.new_count == 6

        preview = preview_import(
            s, org_id=ORG, test_id=t["ZAP"],
            findings=prepare(run_parser_on_bytes(
                get_parser("zap"), zap_json({"10038": sample_2, "10020": ["/x"]})).findings),
        )  # fmt: skip
        assert (preview.counts["closed"], preview.counts["held"]) == (0, 5)
        assert len(preview.to_dict()["held_issue_ids"]) == 5

        two = _import(s, t["ZAP"], {"10038": sample_2, "10020": ["/x"]}, 2)
        assert (two.new_count, two.unchanged_count, two.closed_count, two.held_count) == (
            5,
            1,
            0,
            5,
        )

        three = _import(s, t["ZAP"], {"10020": ["/x"]}, 3)  # the CSP header was set
        assert (three.closed_count, three.held_count) == (10, 0)  # both samples, held ones too
        states = {i.state for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id))}
    assert states == {"fixed", "open"}


def test_reverting_an_import_brings_back_the_held_issues_of_the_one_before(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, t = setup(s, "ZAP")
        _import(s, t["ZAP"], {"10038": ["/a0", "/a1"]}, 1)
        two = _import(s, t["ZAP"], {"10038": ["/b0"]}, 2)
        assert two.held_count == 2
        three = _import(s, t["ZAP"], {"10038": ["/c0"]}, 3)
        assert (three.closed_count, three.held_count) == (0, 3)  # a0, a1 still held, b0 too
        revert_latest_import(s, org_id=ORG, test_id=t["ZAP"])
        again = _import(s, t["ZAP"], {"10020": ["/x"]}, 4)  # the CSP rule is gone
    assert again.closed_count == 3  # /a0, /a1 (held by import 2) and /b0
