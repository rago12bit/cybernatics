from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.owasp.run import evaluate, markdown, predictions_by_case
from benchmarks.owasp.score import (
    RELATED,
    Case,
    Confusion,
    ensemble,
    load_truth,
    positive,
    score,
    wilson,
)

CSV = """# test name, category, real vulnerability, cwe, Benchmark version: 1.2beta, 2015-08-25
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,sqli,false,89
BenchmarkTest00003,hash,true,328
BenchmarkTest00004,hash,false,328
BenchmarkTest00005,xss,true,79
BenchmarkTest00006,xss,false,79
"""


@pytest.fixture
def truth(tmp_path: Path) -> dict[str, Case]:
    p = tmp_path / "expected.csv"
    p.write_text(CSV)
    return load_truth(p)


def test_truth_parses_and_skips_the_comment_line(truth: dict[str, Case]) -> None:
    assert len(truth) == 6
    assert truth["BenchmarkTest00003"] == Case("BenchmarkTest00003", "hash", True, "CWE-328")
    assert not truth["BenchmarkTest00002"].vulnerable


@pytest.mark.parametrize("row", ["T1,sqli,maybe,89", "T1,sqli,true,notanumber"])
def test_a_malformed_truth_row_is_an_error_not_a_guess(tmp_path: Path, row: str) -> None:
    p = tmp_path / "x.csv"
    p.write_text(row + "\n")
    with pytest.raises(ValueError):
        load_truth(p)


# ---- matchers -----------------------------------------------------------------------------------


def case(cat: str, cwe: str) -> Case:
    return Case("BenchmarkTest00001", cat, True, cwe)


def test_exact_needs_the_cases_own_cwe() -> None:
    assert positive(case("sqli", "CWE-89"), ["CWE-89", "CWE-20"], "exact")
    assert not positive(case("sqli", "CWE-89"), ["CWE-20"], "exact")
    assert not positive(case("sqli", "CWE-89"), None, "exact")


def test_related_adds_only_the_listed_equivalent_weaknesses() -> None:
    assert positive(
        case("crypto", "CWE-327"), ["CWE-326"], "related"
    )  # weak key size counts as weak crypto
    assert positive(case("weakrand", "CWE-330"), ["CWE-338"], "related")
    assert not positive(
        case("securecookie", "CWE-614"), ["CWE-1004"], "related"
    )  # HttpOnly is not Secure
    assert not positive(
        case("sqli", "CWE-89"), ["CWE-90"], "related"
    )  # LDAP injection is not SQL injection
    assert "sqli" not in RELATED


def test_any_credits_every_flagged_file_and_is_only_an_upper_bound() -> None:
    assert positive(case("sqli", "CWE-89"), [], "any")  # a finding with no CWE at all still counts
    assert not positive(case("sqli", "CWE-89"), None, "any")


def test_unknown_matcher_is_refused() -> None:
    with pytest.raises(ValueError):
        positive(case("sqli", "CWE-89"), [], "fuzzy")


# ---- confusion matrix and rates -----------------------------------------------------------------


def test_confusion_counts_and_rates_are_computed_by_hand() -> None:
    c = Confusion()
    for vulnerable, predicted in (
        [(True, True)] * 6 + [(True, False)] * 2 + [(False, True)] * 1 + [(False, False)] * 3
    ):
        c.add(vulnerable, predicted)
    r = c.rates()
    assert (r["tp"], r["fn"], r["fp"], r["tn"]) == (6, 2, 1, 3)
    assert r["recall"] == pytest.approx(6 / 8) and r["fpr"] == pytest.approx(1 / 4)
    assert r["precision"] == pytest.approx(6 / 7)
    assert r["f1"] == pytest.approx(2 * (6 / 7) * (6 / 8) / ((6 / 7) + (6 / 8)))
    assert r["benchmark_score"] == pytest.approx(6 / 8 - 1 / 4)


def test_precision_and_f1_are_undefined_not_zero_when_nothing_was_flagged() -> None:
    c = Confusion()
    c.add(True, False)
    c.add(False, False)
    r = c.rates()
    assert (
        r["precision"] is None
        and r["f1"] is None
        and r["recall"] == 0.0
        and r["benchmark_score"] == 0.0
    )


def test_a_tool_that_flags_everything_scores_zero_on_the_benchmark_metric(
    truth: dict[str, Case],
) -> None:
    everything = {n: ["CWE-1"] for n in truth}
    total, _ = score(truth, everything, "any")
    r = total.rates()
    assert (
        r["recall"] == 1.0 and r["fpr"] == 1.0 and r["benchmark_score"] == 0.0
    )  # random guessing line


def test_a_perfect_tool_scores_one(truth: dict[str, Case]) -> None:
    perfect = {n: [c.cwe] for n, c in truth.items() if c.vulnerable}
    total, by_cat = score(truth, perfect, "exact")
    r = total.rates()
    assert (r["recall"], r["fpr"], r["benchmark_score"], r["precision"], r["f1"]) == (
        1.0,
        0.0,
        1.0,
        1.0,
        1.0,
    )
    assert set(by_cat) == {"sqli", "hash", "xss"}


def test_cases_the_tool_never_mentions_count_as_negatives(truth: dict[str, Case]) -> None:
    total, _ = score(truth, {}, "any")
    assert (total.tp, total.fp, total.tn, total.fn) == (0, 0, 3, 3)


def test_wilson_interval_is_wider_for_small_samples_and_contains_the_estimate() -> None:
    small, large = wilson(3, 4), wilson(750, 1000)
    assert small[0] < 0.75 < small[1] and large[0] < 0.75 < large[1]
    assert (small[1] - small[0]) > (large[1] - large[0]) * 5
    assert wilson(0, 0) == (0.0, 1.0)


# ---- ensemble and attribution -------------------------------------------------------------------


def test_ensemble_unions_tools_and_can_require_agreement() -> None:
    a = {"T1": ["CWE-89"], "T2": ["CWE-79"]}
    b = {"T1": ["CWE-89", "CWE-20"], "T3": ["CWE-22"]}
    assert ensemble({"a": a, "b": b}, 1) == {
        "T1": ["CWE-20", "CWE-89"],
        "T2": ["CWE-79"],
        "T3": ["CWE-22"],
    }
    assert ensemble({"a": a, "b": b}, 2) == {"T1": ["CWE-20", "CWE-89"]}


def finding(path: str, *cwes: str) -> SimpleNamespace:
    return SimpleNamespace(location=SimpleNamespace(path=path), taxonomy=SimpleNamespace(cwe=cwes))


def test_findings_are_attributed_to_test_files_and_the_rest_are_counted() -> None:
    preds, other = predictions_by_case([
        finding("src/main/java/x/BenchmarkTest00007.java", "CWE-89"),
        finding("src/main/java/x/BenchmarkTest00007.java", "CWE-20"),
        finding("pom.xml", "CWE-1"),
        finding("src/BenchmarkTest7.java"),  # not a test-case file name
    ])  # fmt: skip
    assert preds == {"BenchmarkTest00007": ["CWE-20", "CWE-89"]} and other == 2


def test_evaluate_produces_all_three_matchers_and_the_report_table(tmp_path: Path) -> None:
    p = tmp_path / "expected.csv"
    p.write_text(CSV)
    doc = {"benchmark": {"tag": "t"}, "measured": "2026-01-01",
           "tools": {"one": {"status": "ok", "predictions": {"BenchmarkTest00001": ["CWE-89"], "BenchmarkTest00002": ["CWE-89"]}},
                     "two": {"status": "ok", "predictions": {"BenchmarkTest00001": ["CWE-89"]}},
                     "silent": {"status": "ok", "predictions": {}},
                     "skipped": {"status": "not-applicable", "predictions": {}}}}  # fmt: skip
    ev = evaluate(doc, p)
    assert set(ev["tools"]) == {
        "one",
        "two",
        "silent",
        "ensemble (any tool)",
        "ensemble (2+ tools agree)",
    }
    assert (
        ev["tools"]["one"]["exact"]["overall"]["fp"] == 1
        and ev["tools"]["two"]["exact"]["overall"]["fp"] == 0
    )
    assert (
        ev["tools"]["ensemble (2+ tools agree)"]["exact"]["overall"]["fp"] == 0
    )  # agreement removed the false positive
    assert (
        "skipped" not in ev["tools"]
    )  # a tool that did not run is not scored as a tool that found nothing
    assert (
        ev["tools"]["silent"]["any"]["overall"]["recall"] == 0.0
    )  # one that ran and found nothing is scored
    assert (
        ev["tools"]["ensemble (2+ tools agree)"]["exact"]["overall"]["tp"] == 1
    )  # a silent tool cannot veto
    assert ev["ensemble_note"] == ""
    assert "| one | related |" in markdown(ev)


def test_with_a_single_analysing_tool_no_ensemble_is_reported(tmp_path: Path) -> None:
    p = tmp_path / "expected.csv"
    p.write_text(CSV)
    doc = {"benchmark": {}, "measured": "x", "tools": {"solo": {"status": "ok", "predictions": {"BenchmarkTest00001": ["CWE-89"]}},
                                                        "silent": {"status": "ok", "predictions": {}}}}  # fmt: skip
    ev = evaluate(doc, p)
    assert (
        set(ev["tools"]) == {"solo", "silent"}
        and "solo" in ev["ensemble_note"]
        and "equal it" in ev["ensemble_note"]
    )
