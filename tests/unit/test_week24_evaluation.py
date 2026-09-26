from __future__ import annotations

import pytest

from benchmarks.corpus.run import aggregate
from benchmarks.juliet.regions import blank_comments_and_strings, extract_regions, region_of
from benchmarks.juliet.score import hit, score_cases
from benchmarks.prioritize import by_risk, by_severity, evaluate, precision_at_k

JAVA = """package x;
public class CWE89_Foo extends AbstractTestCase {
    // void bad() { in a comment }
    public void bad() throws Throwable {
        String s = "void good() {";
        run(s);
    }

    private void goodG2B() throws Throwable {
        run("safe");
    }

    public void good() throws Throwable { goodG2B(); }
}
"""


def test_regions_follow_method_bodies_and_ignore_comments_and_strings() -> None:
    r = extract_regions(JAVA, "CWE89_Foo__x_01.java")
    assert r["bad"] == [(4, 7)]
    assert r["good"] == [(9, 11), (13, 13)]
    assert (
        region_of(5, 5, r) == "bad"
        and region_of(10, 10, r) == "good"
        and region_of(2, 2, r) is None
    )


def test_file_name_conventions() -> None:
    assert extract_regions("x\ny", "CWE1_a_bad.java") == {"bad": [(1, 2)], "good": []}
    assert extract_regions("x", "CWE1_a_goodG2B.java") == {"bad": [], "good": [(1, 1)]}
    assert extract_regions("x", "CWE1_a_base.java") == {"bad": [], "good": []}


def test_blanking_keeps_line_numbers() -> None:
    src = 'a // c\n/* x\ny */ b "s{"\n'
    assert blank_comments_and_strings(src).count("\n") == src.count("\n")
    assert "{" not in blank_comments_and_strings(src)


def test_hit_matchers() -> None:
    assert hit(89, ["CWE-89"], "exact")
    assert not hit(89, ["CWE-564"], "exact")
    assert hit(89, ["CWE-564"], "any")
    assert not hit(89, None, "any")
    assert hit(78, ["CWE-77"], "exact") is False


def test_score_cases_counts_per_cwe() -> None:
    cases = {
        "a#bad": {"cwe": 89, "vulnerable": True, "reported": ["CWE-89"]},
        "a#good": {"cwe": 89, "vulnerable": False, "reported": None},
        "b#bad": {"cwe": 22, "vulnerable": True, "reported": None},
        "b#good": {"cwe": 22, "vulnerable": False, "reported": ["CWE-22"]},
    }
    total, by = score_cases(cases, "exact")
    assert (total.tp, total.fn, total.fp, total.tn) == (1, 1, 1, 1)
    assert by[89].tp == 1 and by[89].tn == 1 and by[22].fn == 1 and by[22].fp == 1


def rec(risk: int, sev: str, tp: bool) -> dict:
    return {"case": "c", "cwe": [], "severity": sev, "risk": risk, "true_positive": tp}


def test_precision_at_k_ranks_and_breaks_ties_by_expectation() -> None:
    rs = [
        rec(90, "HIGH", True),
        rec(80, "HIGH", True),
        rec(10, "HIGH", False),
        rec(5, "HIGH", False),
    ]
    assert precision_at_k(rs, by_risk, 2) == 1.0
    assert precision_at_k(rs, by_severity, 2) == 0.5  # all tied: expectation, not input order
    assert precision_at_k(list(reversed(rs)), by_severity, 2) == 0.5
    assert precision_at_k([], by_risk, 5) == 0.0
    assert precision_at_k(rs, by_risk, 100) == 0.5  # k clamps to the list


def test_evaluate_reports_gain_and_ci() -> None:
    rs = [rec(90 - i, "HIGH", i < 15) for i in range(40)] + [rec(1, "MEDIUM", False)] * 20
    ev = evaluate(rs)
    row = next(r for r in ev["rows"] if r["k"] == 20)
    assert row["risk_score"] == pytest.approx(0.75)
    assert row["severity_only"] == pytest.approx(15 / 40)
    lo, hi = row["diff_ci95"]
    assert lo <= row["diff"] <= hi


def test_corpus_aggregate() -> None:
    def row(repo, kind, raw, uniq, wall, **status):
        return {"repo": repo, "kind": kind, "raw_findings": raw, "unique_findings": uniq,
                "dedup_rate": round(1 - uniq / raw, 4), "wall_seconds": wall,
                "tool_status": {t: {"status": s} for t, s in status.items()}}  # fmt: skip

    rows = [
        row("a", "vulnerable", 100, 60, 10.0, bandit="ok", semgrep="ok", trivy="skipped"),
        row("b", "real", 10, 10, 20.0, bandit="ok", semgrep="timeout"),
        {"repo": "c", "error": "clone failed"},
    ]
    a = aggregate(rows)
    assert a["scanned"] == 2 and a["scan_level_failures"] == ["c"]
    assert a["tool_runs"] == 4 and a["crash_rate"] == 0.25  # skipped runs are not counted
    assert a["dedup_rate_pooled"] == round(1 - 70 / 110, 4)
    assert a["dedup_rate_by_kind"]["real"] == 0.0
