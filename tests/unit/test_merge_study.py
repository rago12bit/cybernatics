from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from benchmarks import merge_study as ms
from core.correlation import correlate, partition
from core.models import Category, Finding
from core.scan import ADAPTERS, DEFAULT_TOOLS
from tests.unit.test_correlation import code, sca


def _real() -> list[Finding]:
    out: list[Finding] = []
    for name in DEFAULT_TOOLS:  # the recorded scan of tests/fixtures: 62 raw reports, 38 findings
        out += ADAPTERS[name].parse(Path(f"tests/golden/{name}/raw.json").read_bytes())
    return out


def _doc(raw: list[Finding] | None = None) -> dict[str, Any]:
    row = {"repo": "fixture", "kind": "vulnerable", "commit": "abc123", "url": "https://github.com/o/r",
           "raw": [f.to_dict() for f in (raw if raw is not None else _real())]}  # fmt: skip
    return {"label": "t", "collected_on": "2026-01-01", "repos": [row]}


# ---- partition: the raw reports behind each finding ------------------------------------
def test_partition_is_what_correlate_merges() -> None:
    raw = _real()
    merged, stats = correlate(raw)
    parts = partition(raw)
    assert len(parts) == stats.unique == 38
    assert sorted(id(f) for part in parts for f in part) == sorted(id(f) for f in raw)
    tools = sorted(sorted({t for f in part for t in f.evidence.reported_by}) for part in parts)
    assert tools == sorted(sorted(m.evidence.reported_by) for m in merged)


def test_partition_puts_a_folded_repeat_with_the_report_it_repeats() -> None:
    a = code("semgrep", "r", line=5)
    b = code("semgrep", "r", line=5)  # the same rule twice at one place: never merged, but folded
    c = code("semgrep", "r", line=40)
    parts = partition([a, b, c])
    assert sorted(len(p) for p in parts) == [1, 2]
    assert len(parts) == correlate([a, b, c])[1].unique


# ---- what is drawn -----------------------------------------------------------------------
def test_strata_of_the_recorded_scan() -> None:
    key = ms.draw(_doc())
    assert {s: v["population"] for s, v in key["strata"].items()} == {
        "code": 4, "dependency": 17, "same-tool": 0, "near-code": 3, "near-dependency": 0,
    }  # fmt: skip
    by = {s: [it for it in key["items"] if it["stratum"] == s] for s in key["strata"]}
    # Three of the four code merges are pairs; the shell injection is three reports, so three pairs.
    assert len(by["code"]) == 6 and len({it["group"] for it in by["code"]}) == 4
    assert len(by["dependency"]) == 17  # one pair per group, though one group has three reports
    assert {it["why"] for it in by["near-code"]} == {"same weakness family"}
    assert key["repos"] == [{"repo": "fixture", "kind": "vulnerable", "commit": "abc123",
                             "url": "https://github.com/o/r", "error": None, "failed": [], "raw": 62, "unique": 38}]  # fmt: skip


def test_a_draw_is_reproducible_and_the_seed_matters() -> None:
    a, b, c = ms.draw(_doc()), ms.draw(_doc()), ms.draw(_doc(), seed=7)
    assert [it["id"] for it in a["items"]] == [it["id"] for it in b["items"]]
    assert a["items"] == b["items"]
    assert [it["id"] for it in a["items"]] != [it["id"] for it in c["items"]]
    # Everything is drawn here (a census), so the groups are the same; which pair of a larger
    # group is shown depends on the seed.
    assert {it["group"] for it in a["items"]} == {it["group"] for it in c["items"]}
    assert len({it["id"] for it in a["items"]}) == len(a["items"])


def test_a_quota_samples_groups_and_records_the_population() -> None:
    key = ms.draw(_doc(), quota={"dependency": 5, "near-code": 0})
    assert key["strata"]["dependency"] == {"kind": "merged", "population": 17, "sampled": 5, "by_repo": {"fixture": 17}}  # fmt: skip
    assert sum(it["stratum"] == "dependency" for it in key["items"]) == 5
    assert not any(it["stratum"] == "near-code" for it in key["items"])


def test_a_report_links_to_the_scanned_commit_and_shows_no_secret() -> None:
    key = ms.draw(_doc())
    reports = [r for it in key["items"] for r in it["reports"]]
    sqli = next(r for r in reports if r["rules"] == ["B608"])
    assert sqli["link"] == "https://github.com/o/r/blob/abc123/src/users.py#L6-L6"
    near_secret = [
        r for r in reports if r["path"] == "src/users.py" and r["start_line"] in (18, 20)
    ]
    assert near_secret and all(
        "withheld" in r["snippet"] or "redacted" in r["snippet"] for r in near_secret
    )
    # Correlation itself ran on what the tools reported: the secret and Bandit's B105 still merged.
    assert any({"gitleaks", "bandit"} == {t for r in it["reports"] for t in r["tools"]} for it in key["items"] if it["stratum"] == "code")  # fmt: skip


# ---- look-alikes Bulwark left apart ----------------------------------------------------
def _near(raw: list[Finding]) -> list[tuple[str, str]]:
    parts = partition(raw)
    index = {id(f): i for i, f in enumerate(raw)}
    part_of = {index[id(f)]: p for p, part in enumerate(parts) for f in part}
    return [(s, why) for s, why, _, _ in ms.near_misses(raw, part_of, parts)]


def test_one_weakness_outside_the_line_window_is_a_look_alike() -> None:
    assert _near([code("bandit", "B608", line=10), code("semgrep", "sqli", line=16)]) == [("near-code", "same weakness family")]  # fmt: skip
    assert (
        _near([code("bandit", "B608", line=10), code("semgrep", "sqli", line=30)]) == []
    )  # too far
    assert (
        _near([code("bandit", "B608", line=10), code("semgrep", "sqli", line=11)]) == []
    )  # merged


def test_adjacent_lines_with_another_weakness_are_a_look_alike_but_one_tool_alone_is_not() -> None:
    a = code("bandit", "B602", line=10, cwe="CWE-78")
    assert _near([a, code("semgrep", "eval", line=11, cwe="CWE-94")]) == [
        ("near-code", "adjacent lines")
    ]
    assert _near([a, code("bandit", "B307", line=11, cwe="CWE-94")]) == []
    assert _near([a, code("semgrep", "eval", line=14, cwe="CWE-94")]) == []


def test_dependency_look_alikes() -> None:
    t = sca("trivy", "CVE-2020-1")
    assert _near([t, sca("osv-scanner", "GHSA-xxxx")]) == [
        (
            "near-dependency",
            "same version, neither matched by another tool",
        )  # an alias nobody listed?
    ]
    assert _near([t, sca("osv-scanner", "GHSA-xxxx", aliases=("CVE-2020-1",), ver="4.17.5")]) == [("near-dependency", "shared id")]  # fmt: skip
    assert _near([t, sca("osv-scanner", "GHSA-xxxx", aliases=("CVE-2020-1",))]) == []  # merged
    assert _near([t, sca("osv-scanner", "GHSA-xxxx", ver="4.17.5")]) == []  # nothing in common


def test_web_findings_are_never_look_alikes() -> None:
    a = code("zap", "10038", line=0, path="", cat=Category.DAST)
    assert _near([a, code("nuclei", "csp", line=0, path="", cat=Category.DAST)]) == []


# ---- the labelling page ------------------------------------------------------------------
def test_the_page_says_nothing_about_what_bulwark_did() -> None:
    key = ms.draw(_doc())
    html = ms.page(key)
    data = json.loads(
        re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S).group(1)
    )  # type: ignore[union-attr]
    assert [it["id"] for it in data["items"]] == [it["id"] for it in key["items"]]
    assert all(set(it) == {"id", "reports"} for it in data["items"])
    for hidden in ("stratum", "near-code", "same weakness family", "fixture#", "fixture~"):
        assert hidden not in html
    assert data["codebook"] == ms.CODEBOOK
    assert "innerHTML" not in html  # scanner text is untrusted: it is only ever set as text


def test_scanner_text_cannot_close_the_data_block() -> None:
    evil = code("bandit", "B608", line=10, snippet='x = "</script><script>alert(1)</script>"')
    html = ms.page(ms.draw(_doc([evil, code("semgrep", "sqli", line=16)])))
    assert html.count("</script>") == 2  # the data block and the page's own script
    data = json.loads(
        re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S).group(1)
    )  # type: ignore[union-attr]
    assert any("</script>" in r["snippet"] for it in data["items"] for r in it["reports"])


# ---- scoring -----------------------------------------------------------------------------
def _key(strata: dict[str, tuple[int, list[list[str]]]]) -> tuple[dict[str, Any], dict[str, str]]:
    """A key and one rater's labels from {stratum: (population, [labels of each group's pairs])}."""
    key: dict[str, Any] = {"study": "s", "seed": 1, "strata": {}, "items": []}
    labels: dict[str, str] = {}
    for s, (population, groups) in strata.items():
        key["strata"][s] = {"population": population, "sampled": len(groups)}
        for g, pairs in enumerate(groups):
            for p, label in enumerate(pairs):
                item = f"{s}-{g}-{p}"
                key["items"].append({"id": item, "stratum": s, "group": f"{s}#{g}"})
                if label:
                    labels[item] = label
    return key, labels


def test_precision_counts_groups_and_one_wrong_pair_spoils_a_group() -> None:
    key, labels = _key(
        {"code": (4, [["same"], ["same", "same", "different"], ["same", "unsure"], ["same", ""]])}
    )
    got = ms.score_rater(key, labels)["strata"]["code"]
    assert (got["same"], got["different"], got["unsure"], got["unlabelled"]) == (1, 1, 1, 1)
    assert got["precision"]["rate"] == 0.5 and (got["precision"]["k"], got["precision"]["n"]) == (
        1,
        2,
    )
    assert got["precision_unsure_wrong"]["rate"] == pytest.approx(1 / 3)
    assert got["precision"]["ci95"] == list(ms.wilson(1, 2))


def test_pooled_precision_weights_strata_by_their_size_in_the_corpus() -> None:
    key, labels = _key({
        "code": (2, [["same"], ["different"]]),  # labelled in full: exactly 50%
        "dependency": (98, [["same"]] * 10),  # 10 of 98 sampled, all right
    })  # fmt: skip
    got = ms.score_rater(key, labels)["precision"]
    assert got["rate"] == pytest.approx((2 * 0.5 + 98 * 1.0) / 100)
    lo, hi = ms.wilson(10, 10)
    assert got["ci95"] == pytest.approx([(2 * 0.5 + 98 * lo) / 100, (2 * 0.5 + 98 * hi) / 100])
    assert got["units"] == 100 and got["estimated_wrong_merges"] == 1.0


def test_missed_rate_is_the_share_of_look_alikes_that_are_one_defect() -> None:
    key, labels = _key({"near-code": (40, [["same"], ["different"], ["different"], ["unsure"]])})
    got = ms.score_rater(key, labels)
    assert got["strata"]["near-code"]["missed"]["rate"] == pytest.approx(1 / 3)
    assert got["strata"]["near-code"]["missed_unsure_same"]["rate"] == 0.5
    assert got["missed"]["estimated_missed_merges"] == pytest.approx(40 / 3, abs=0.05)
    assert "precision" not in got


def test_nothing_labelled_gives_no_rate() -> None:
    key, _ = _key({"code": (3, [["", ""]])})
    got = ms.score_rater(key, {})
    assert got["strata"]["code"]["precision"]["rate"] is None and "precision" not in got
    assert "n/a" in ms.markdown(ms.score(key, {"a": {}}))


def test_kappa() -> None:
    a = {"1": "same", "2": "same", "3": "different", "4": "different", "5": "same"}
    b = {"1": "same", "2": "same", "3": "different", "4": "same", "6": "same"}
    got = ms.kappa(a, b)
    assert (got["items"], got["agreement"], got["disagreements"]) == (4, 0.75, ["4"])
    assert got["kappa"] == pytest.approx((0.75 - 0.5) / (1 - 0.5))  # chance: .5*.75 + .5*.25
    assert ms.kappa({"1": "same"}, {"1": "same"})["kappa"] is None  # no variation: undefined, not 1
    assert ms.kappa(a, {})["items"] == 0


def test_labels_file_round_trip_and_bad_rows(tmp_path: Path) -> None:
    key, _ = _key({"code": (2, [["same"], ["same"]])})
    good = tmp_path / "a.csv"
    good.write_text('item,label,note\ncode-0-0,Same,"a, note"\ncode-1-0,,\n')
    assert ms.read_labels(good, key) == {"code-0-0": "same"}
    for bad in ("item,label,note\ncode-0-0,maybe,\n", "item,label,note\nnope,same,\n"):
        (tmp_path / "b.csv").write_text(bad)
        with pytest.raises(ValueError, match="unknown item or label"):
            ms.read_labels(tmp_path / "b.csv", key)


def test_cli_sample_then_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import gzip

    monkeypatch.setattr(ms, "RESULTS", tmp_path)
    raw = tmp_path / "raw.json.gz"
    with gzip.open(raw, "wt") as fh:
        json.dump(_doc(), fh)
    assert ms.main(["sample", str(raw), "--dependency", "4"]) == 0
    key_path = tmp_path / "merge-study-2026-01-01-t.key.json"
    key = json.loads(key_path.read_text())
    assert (
        (tmp_path / "merge-study-2026-01-01-t.label.html").read_text().startswith("<!doctype html>")
    )
    labels = tmp_path / "me.csv"
    labels.write_text("item,label,note\n" + "".join(f"{it['id']},{'same' if it['stratum'] in ms.MERGED else 'different'},\n" for it in key["items"]))  # fmt: skip
    assert ms.main(["score", str(key_path), "--labels", f"me={labels}"]) == 0
    out = capsys.readouterr().out
    assert "| code | 4 | 4 | 0 | 0 | 100.0%" in out and "Merge precision, all merged groups" in out
    scores = json.loads((tmp_path / "merge-study-2026-01-01-t.scores.json").read_text())
    assert scores["raters"]["me"]["precision"]["rate"] == 1.0
    assert scores["raters"]["me"]["missed"]["rate"] == 0.0


def test_a_scan_with_holes_is_never_silent() -> None:
    assert ms._failed({"tool_status": {"bandit": "ok", "trivy": "timeout"}}) == ["trivy (timeout)"]
    assert ms._failed({"error": "IngestError: gone", "tool_status": {}}) == ["IngestError: gone"]
    doc = _doc([])
    doc["repos"][0]["tool_status"] = {"semgrep": "error"}
    assert ms.draw(doc)["repos"][0]["failed"] == ["semgrep (error)"]
