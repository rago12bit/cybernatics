from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from core.llm import evaluation as ev
from core.models import Category, Finding, Location, Taxonomy
from tests.unit.test_llm import GOOD, FakeModel, kb, reply  # noqa: F401 - kb is a fixture

SNIP = "def f(x):\n    return eval(x)"


def mk(
    fid: str,
    rule: str = "semgrep/r1",
    cat: str = "sast",
    repo: str = "repo/a",
    snippet: str = SNIP,
    cve: str | None = None,
) -> dict[str, Any]:
    f = Finding(
        id=fid, title=f"t {fid}", description="d", location=Location("a.py", 1, 2, snippet, "h"),
        taxonomy=Taxonomy(Category(cat), cwe=("CWE-95",), cve=(cve,) if cve else ()),
    )  # fmt: skip
    if cat != "sca":
        f.evidence.rule_ids = {"semgrep": [rule.split("/")[-1]]}
    return {**f.to_dict(), "_repo": repo}


def pool() -> list[dict[str, Any]]:
    out = [
        mk(f"noisy{i}", "semgrep/noisy") for i in range(60)
    ]  # one rule that makes most of the findings
    out += [mk(f"r{r}_{i}", f"semgrep/rule{r}") for r in range(20) for i in range(3)]
    out += [
        mk(f"d{c}_{i}", cat="sca", cve=f"CVE-2020-{c:04d}", snippet="")
        for c in range(30)
        for i in range(2)
    ]
    out += [
        mk("sec", cat="secrets", snippet="[secret redacted]"),
        mk("nosnip", snippet=""),
        mk("wh", snippet="[snippet withheld: near a detected secret]"),
    ]
    return out


# ---- sampling ----------------------------------------------------------------------------------------------


def test_the_sample_is_deterministic_and_the_right_size() -> None:
    a, b = ev.select_sample(pool(), 50, 1), ev.select_sample(pool(), 50, 1)
    assert a == b and len(a) == 50 and len({x["item_id"] for x in a}) == 50
    assert [x["item_id"] for x in a] != [x["item_id"] for x in ev.select_sample(pool(), 50, 2)]
    assert [x["item_id"] for x in a] == sorted(
        x["item_id"] for x in a
    )  # a fixed, ungrouped scoring order


def test_it_spreads_over_rules_instead_of_drawing_the_noisy_one_fifty_times() -> None:
    s = ev.select_sample(pool(), 50, 1)
    rules = [x["rule"] for x in s if x["finding"]["taxonomy"]["category"] == "sast"]
    assert (
        len(rules) == 35 and len(set(rules)) == 21 and rules.count("semgrep/noisy") <= 2
    )  # 21 rules exist: each used, then repeats
    assert (
        len({x["rule"] for x in s if x["finding"]["taxonomy"]["category"] == "sca"}) == 15
    )  # one per CVE


def test_only_findings_that_can_be_evaluated_are_eligible() -> None:
    ids = {x["finding"]["id"] for x in ev.select_sample(pool(), 200, 1)}
    assert not ids & {
        "sec",
        "nosnip",
        "wh",
    }  # secrets send no code; a missing/withheld snippet gives the model nothing


def test_it_tops_up_with_code_findings_when_there_are_too_few_dependencies() -> None:
    few = [mk(f"c{i}", f"semgrep/r{i}") for i in range(40)] + [
        mk("d1", cat="sca", cve="CVE-2020-1", snippet="")
    ]
    s = ev.select_sample(few, 30, 1, code_share=0.5)
    assert len(s) == 30 and sum(x["finding"]["taxonomy"]["category"] == "sca" for x in s) == 1


def test_a_small_pool_returns_what_exists() -> None:
    assert len(ev.select_sample([mk("a"), mk("b", "semgrep/r2")], 50, 1)) == 2


def test_item_ids_are_stable_and_repo_scoped() -> None:
    assert ev.item_id("r", "f") == ev.item_id("r", "f") != ev.item_id("r2", "f")


def test_the_committed_sample_is_well_formed() -> None:
    sample = ev.read_jsonl(
        Path(__file__).resolve().parents[2] / "benchmarks/remediation/sample.jsonl"
    )
    assert len(sample) == 50 and len({s["item_id"] for s in sample}) == 50
    cats = [s["finding"]["taxonomy"]["category"] for s in sample]
    assert set(cats) <= {"sast", "iac", "container", "sca"} and "secrets" not in cats
    assert all(
        ev.has_code(s["finding"])
        for s in sample
        if s["finding"]["taxonomy"]["category"] in ev.CODE_CATEGORIES
    )
    assert all("_repo" not in s["finding"] and s["repo"].startswith("https://") for s in sample)


# ---- statistics ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "k,n,lo,hi",
    [(0, 10, 0.0, 0.278), (10, 10, 0.722, 1.0), (5, 10, 0.237, 0.763), (45, 50, 0.786, 0.957)],
)
def test_wilson_interval_matches_known_values(k: int, n: int, lo: float, hi: float) -> None:
    got = ev.wilson(k, n)
    assert got[0] == pytest.approx(lo, abs=0.002) and got[1] == pytest.approx(hi, abs=0.002)
    assert ev.wilson(0, 0) == (0.0, 1.0)


def test_score_validation() -> None:
    ok = {"explanation_accurate": 2, "fix_correct": 1, "unsafe": 0, "hallucination": 0}
    assert ev.validate_scores(ok) == []
    assert any("missing" in p for p in ev.validate_scores({**ok, "fix_correct": None}))
    assert any("not one of" in p for p in ev.validate_scores({**ok, "fix_correct": 3}))
    assert any("not one of" in p for p in ev.validate_scores({**ok, "unsafe": 2}))
    assert ev.validate_scores({**ok, "patch_correct": None, "static_fix_correct": 2}) == []


# ---- the report -----------------------------------------------------------------------------------------------


def result(
    iid: str,
    source: str = "ai",
    conf: str = "medium",
    patch: str | None = None,
    status: str | None = None,
    cat: str = "sast",
    reason: str | None = None,
) -> dict[str, Any]:
    f = mk(iid, cat=cat)
    return {"item_id": iid, "repo": "r", "rule": "x", "finding": f, "raw_reply": None,
            "result": {"source": source, "confidence": conf, "suggested_patch": patch, "patch_status": status, "degraded_reason": reason}}  # fmt: skip


def sc(
    fix: int,
    exp: int = 2,
    unsafe: int = 0,
    hall: int = 0,
    patch: int | None = None,
    static: int | None = None,
) -> dict[str, Any]:
    return {
        "explanation_accurate": exp,
        "fix_correct": fix,
        "unsafe": unsafe,
        "hallucination": hall,
        "patch_correct": patch,
        "static_fix_correct": static,
    }


META = {"model": "m", "prompt_version": "p", "date": "2026-01-01"}


def test_report_numbers_are_computed_from_the_scores_by_hand_checkable_arithmetic() -> None:
    res = [result("a", conf="high", patch="P", status="verified"), result("b", conf="high", patch="P", status="unverified"),
           result("c", conf="low"), result("d", cat="sca"), result("e", source="static", reason="model reply rejected: extra key")]  # fmt: skip
    scores = {
        "a": sc(2, patch=2, static=1),
        "b": sc(1, patch=0, static=1),
        "c": sc(0, unsafe=1, static=2),
        "d": sc(2, exp=1, hall=1, static=0),
        "e": sc(0),
    }
    r = ev.report(res, scores, META)
    assert (r["items"], r["answered_by_model"], r["fell_back_to_reference_text"]) == (5, 4, 1)
    assert r["fallback_reasons"] == {"model reply rejected": 1}
    ai = r["ai"]
    assert ai["fix_correct (score 2)"]["k"] == 2 and ai["fix_correct (score 2)"]["n"] == 4
    assert (
        ai["fix_acceptable (score >=1)"]["k"] == 3
        and ai["explanation_accurate (score 2)"]["k"] == 3
    )
    assert ai["unsafe_suggestion"]["k"] == 1 and ai["hallucinated_reference"]["k"] == 1
    p = r["patches"]
    assert (
        p["answers_with_a_patch"]["k"] == 2
        and p["patch_matches_the_code (automatic check)"]["k"] == 1
    )
    assert (
        p["patch_correct (score 2, hand-scored)"] == ev._rate(1, 2)
        and p["patch_helpful (score >=1, hand-scored)"]["k"] == 1
    )
    assert r["by_category"] == {"sast": ev._rate(1, 3), "sca": ev._rate(1, 1)}
    cal = r["calibration (fix_correct by the model's own confidence)"]
    assert cal["high"]["k"] == 1 and cal["high"]["n"] == 2 and cal["low"]["k"] == 0
    v = r["versus_reference_text"]
    assert (v["ai_better"], v["equal"], v["ai_worse"]) == (2, 1, 1)  # a 2>1, b 1=1, c 0<2, d 2>0
    assert v["items_scored_both_ways"] == 4
    for section in (ai, p):
        for m in section.values():
            assert m["ci95"][0] <= (m["rate"] or 0) <= m["ci95"][1]


def test_report_refuses_unscored_unknown_or_malformed_data() -> None:
    res = [result("a"), result("b")]
    with pytest.raises(ValueError, match="not scored yet"):
        ev.report(res, {"a": sc(2)}, META)
    with pytest.raises(ValueError, match="not in the results"):
        ev.report(res, {"a": sc(2), "b": sc(2), "zzz": sc(2)}, META)
    with pytest.raises(ValueError, match="fix_correct"):
        ev.report(res, {"a": sc(2), "b": {**sc(2), "fix_correct": None}}, META)
    with pytest.raises(ValueError, match="not one of"):
        ev.report(res, {"a": sc(2), "b": sc(7)}, META)


def test_markdown_table_is_generated_from_the_report_and_shows_intervals_and_n() -> None:
    res = [result(str(i)) for i in range(10)]
    r = ev.report(res, {str(i): sc(2 if i < 7 else 1) for i in range(10)}, META)
    md = ev.markdown_table(r)
    assert "fix_correct (score 2) | 70% (7/10)" in md and " to " in md and "| 10 |" in md
    assert (
        "Measured 2026-01-01 with `m`" in md and "treat differences smaller than it as noise" in md
    )


# ---- running -----------------------------------------------------------------------------------------------------


def test_run_generation_uses_the_products_own_path_and_records_fallbacks(kb) -> None:  # type: ignore[no-untyped-def]
    items = ev.select_sample(pool(), 6, 1)
    good = FakeModel(reply(suggested_patch=None))
    rows = ev.run_generation(items, kb, good, max_calls=4)
    assert len(rows) == 4 and len(good.calls) == 4
    assert all(
        r["result"]["source"] == "ai"
        and r["result"]["model"] == "fake-model-1"
        and r["raw_reply"] is None
        for r in rows
    )
    bad = FakeModel('{"explanation": "x"}')
    seen: list[int] = []
    rows = ev.run_generation(items, kb, bad, max_calls=2, on_item=lambda i, n, r: seen.append(i))
    assert [r["result"]["source"] for r in rows] == ["static", "static"] and seen == [1, 2]
    assert (
        rows[0]["raw_reply"] == '{"explanation": "x"}'
    )  # kept, so a rejected answer can be inspected
    assert json.dumps(rows)  # everything is serialisable
    _ = (GOOD, copy)


def test_the_scoring_page_generator_embeds_only_blinded_data(kb, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """Bias control: what the scorer sees must not include the model's confidence, the patch check or warnings."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_eval", Path(__file__).resolve().parents[2] / "benchmarks/remediation/run.py"
    )
    run = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(run)  # type: ignore[union-attr]
    monkeypatch.setattr(run, "_kb", lambda: kb)
    items = ev.select_sample(pool(), 3, 1)
    rows = ev.run_generation(
        items, kb, FakeModel(reply(suggested_patch=None, confidence="high")), max_calls=3
    )
    for r in rows:
        r["result"]["warnings"] = ["SECRET-WARNING-TEXT"]
        r["result"]["patch_status"] = "verified-marker"
    d = tmp_path / "run1"
    d.mkdir()
    ev.write_jsonl(d / "results.jsonl", rows)
    ns = type("A", (), {"results": str(d / "results.jsonl"), "out": None})
    run.cmd_scorer(ns)
    page = (d / "scorer.html").read_text()
    for leaked in (
        "SECRET-WARNING-TEXT",
        "verified-marker",
        '"confidence"',
        "degraded_reason",
        "raw_reply",
        "patch_status",
        "fake-model-1",
    ):
        assert leaked not in page, leaked
    assert (
        '"explanation"' in page
        and "</script><script" not in page.split('id="data"')[1].split("</script>")[0]
    )
    data = json.loads(page.split('id="data" type="application/json">')[1].split("</script>")[0])
    assert len(data["items"]) == 3 and set(data["static"]) == {i["item_id"] for i in items}
