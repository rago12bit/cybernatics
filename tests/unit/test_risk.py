from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.models import Category, Finding, Location, Severity, Taxonomy
from core.risk import Feeds, apply_risk, ensure_fresh, is_stale, read_meta, update_feeds
from core.risk.feeds import EPSS_URL, KEV_URL
from core.risk.score import KEV_FLOOR, epss_likelihood, score_finding


def _vuln(
    sev: Severity = Severity.HIGH, cve: str = "CVE-2021-44228", cvss: float | None = None
) -> Finding:
    f = Finding(
        id="v", title="t", description="", location=Location("pom.xml", 1, 1),
        taxonomy=Taxonomy(Category.SCA, cve=(cve,), aliases=("GHSA-xxxx", cve)),
    )  # fmt: skip
    f.scoring.normalized_severity = sev
    f.scoring.cvss_v3_1 = cvss
    return f


def _code(conf: float = 0.5, sev: Severity = Severity.HIGH) -> Finding:
    f = Finding(id="c", title="t", description="", location=Location("a.py", 1, 1), taxonomy=Taxonomy(Category.SAST))  # fmt: skip
    f.scoring.normalized_severity, f.scoring.confidence = sev, conf
    return f


def epss_gz(rows: int = 1500, extra: str = "") -> bytes:
    body = "#model_version:v2025.03.14,score_date:2026-09-24T12:55:00Z\ncve,epss,percentile\n"
    body += "CVE-2021-44228,0.94358,0.99990\nCVE-2020-0001,0.00043,0.10\n"
    body += "".join(f"CVE-2019-{i:05d},0.001,0.5\n" for i in range(1000, 1000 + rows))
    return gzip.compress((body + extra).encode())


def kev_json(n: int = 150) -> bytes:
    vulns = [{"cveID": "CVE-2021-44228"}] + [{"cveID": f"CVE-2018-{i:05d}"} for i in range(n)]
    return json.dumps({"catalogVersion": "2026.09.24", "dateReleased": "2026-09-24", "vulnerabilities": vulns}).encode()  # fmt: skip


def fake(table: dict[str, bytes | Exception]):  # type: ignore[no-untyped-def]
    def fetch(url: str) -> bytes:
        v = table[url]
        if isinstance(v, Exception):
            raise v
        return v

    return fetch


# ---- scoring -----------------------------------------------------------------------------------


def test_kev_is_floored_and_explained() -> None:
    f = score_finding(_vuln(Severity.MEDIUM), Feeds(kev={"CVE-2021-44228"}, kev_loaded=True))
    assert f.scoring.in_cisa_kev and (f.scoring.risk_score or 0) >= KEV_FLOOR
    assert any("KEV" in x for x in f.scoring.risk_factors)


def test_epss_orders_otherwise_identical_findings() -> None:
    low = score_finding(_vuln(), Feeds(epss={"CVE-2021-44228": 0.001}, epss_loaded=True))
    high = score_finding(_vuln(), Feeds(epss={"CVE-2021-44228": 0.6}, epss_loaded=True))
    assert (high.scoring.risk_score or 0) > (low.scoring.risk_score or 0)
    assert high.scoring.epss_score == 0.6 and not high.scoring.in_cisa_kev
    assert any("EPSS 60.0%" in x for x in high.scoring.risk_factors)


def test_severity_still_matters_more_than_noise() -> None:
    feeds = Feeds(epss={"CVE-2021-44228": 0.01}, epss_loaded=True)
    crit = score_finding(_vuln(Severity.CRITICAL), feeds).scoring.risk_score or 0
    low = score_finding(_vuln(Severity.LOW), feeds).scoring.risk_score or 0
    assert crit > 2 * low


def test_cvss_is_preferred_over_the_severity_bucket() -> None:
    a = score_finding(_vuln(Severity.HIGH, cvss=9.8), Feeds(epss_loaded=True)).scoring.risk_score
    b = score_finding(_vuln(Severity.HIGH, cvss=7.0), Feeds(epss_loaded=True)).scoring.risk_score
    assert a is not None and b is not None and a > b


def test_alias_cves_are_used_and_epss_takes_the_max() -> None:
    f = _vuln(cve="CVE-2020-0001")
    f.taxonomy = Taxonomy(
        Category.SCA, cve=("CVE-2020-0001",), aliases=("CVE-2021-44228", "GHSA-1")
    )
    out = score_finding(
        f, Feeds(epss={"CVE-2020-0001": 0.0004, "CVE-2021-44228": 0.94}, epss_loaded=True)
    )
    assert out.scoring.epss_score == 0.94


def test_missing_feeds_degrade_gracefully_and_say_so() -> None:
    f = score_finding(_vuln(), Feeds())  # nothing loaded
    assert f.scoring.risk_score is not None and f.scoring.epss_score is None
    assert "Exploit feeds not loaded" in f.scoring.risk_factors
    known = score_finding(_vuln(), Feeds(epss_loaded=True))  # loaded, CVE just not scored
    assert "No exploit data for this CVE" in known.scoring.risk_factors


def test_findings_without_a_cve_use_confidence() -> None:
    lo = score_finding(_code(0.2), Feeds()).scoring.risk_score or 0
    hi = score_finding(_code(0.95), Feeds()).scoring.risk_score or 0
    assert hi > lo


def test_score_bounds_and_likelihood_curve() -> None:
    assert epss_likelihood(0) == 0 and epss_likelihood(0.5) == 1 and epss_likelihood(2) == 1
    for sev in Severity:
        for kev in (False, True):
            s = score_finding(
                _vuln(sev, cvss=10.0), Feeds(kev={"CVE-2021-44228"} if kev else set())
            )
            assert 0 <= (s.scoring.risk_score or 0) <= 100


def test_apply_risk_does_not_mutate_inputs() -> None:
    f = _vuln()
    out = apply_risk([f], Feeds(kev={"CVE-2021-44228"}))
    assert f.scoring.risk_score is None and out[0].scoring.risk_score is not None


# ---- triage-assistant verdict (plan §21.3) ------------------------------------------------------


def test_a_likely_false_positive_verdict_dampens_but_never_zeroes_the_score() -> None:
    from core.triage_assistant.contract import TriageVerdict

    baseline = score_finding(_code(0.9), Feeds()).scoring.risk_score or 0
    verdict = TriageVerdict("likely_false_positive", "high", "no sanitizer seen", (10,))
    dampened = score_finding(_code(0.9), Feeds(), verdict=verdict).scoring.risk_score or 0
    assert 0 < dampened < baseline


def test_a_likely_real_verdict_can_only_nudge_up_not_dominate() -> None:
    from core.triage_assistant.contract import TriageVerdict

    baseline = score_finding(_code(0.5), Feeds()).scoring.risk_score or 0
    verdict = TriageVerdict("likely_real", "high", "reaches the sink", (10,))
    nudged = score_finding(_code(0.5), Feeds(), verdict=verdict).scoring.risk_score or 0
    assert baseline <= nudged <= 100


def test_an_unsure_verdict_never_changes_the_score() -> None:
    from core.triage_assistant.contract import TriageVerdict

    baseline = score_finding(_code(0.6), Feeds()).scoring.risk_score
    verdict = TriageVerdict("unsure", "low", "not enough information", (10,))
    same = score_finding(_code(0.6), Feeds(), verdict=verdict).scoring.risk_score
    assert baseline == same


def test_the_verdict_factor_never_overrides_the_kev_floor() -> None:
    from core.triage_assistant.contract import TriageVerdict

    verdict = TriageVerdict("likely_false_positive", "high", "x", (1,))
    f = score_finding(_vuln(cvss=1.0), Feeds(kev={"CVE-2021-44228"}), verdict=verdict)
    assert (f.scoring.risk_score or 0) >= KEV_FLOOR


def test_the_verdict_is_named_in_risk_factors() -> None:
    from core.triage_assistant.contract import TriageVerdict

    verdict = TriageVerdict("likely_false_positive", "medium", "x", (1,))
    f = score_finding(_code(0.8), Feeds(), verdict=verdict)
    assert any("Triage assistant: likely false positive" in fac for fac in f.scoring.risk_factors)


def test_apply_risk_threads_the_verdict_lookup_by_fingerprint() -> None:
    from core.triage_assistant.contract import TriageVerdict

    f = _code(0.9)
    f.fingerprint = "fp-1"
    verdict = TriageVerdict("likely_false_positive", "high", "x", (1,))
    with_verdict = apply_risk(
        [f], Feeds(), verdict_lookup=lambda x: verdict if x.fingerprint == "fp-1" else None
    )
    without = apply_risk([f], Feeds())
    assert (with_verdict[0].scoring.risk_score or 0) < (without[0].scoring.risk_score or 0)


# ---- feeds -------------------------------------------------------------------------------------


def test_update_validates_caches_and_load_filters(tmp_path: Path) -> None:
    meta = update_feeds(tmp_path, fake({EPSS_URL: epss_gz(), KEV_URL: kev_json()}))
    assert (
        meta["errors"] == {}
        and meta["epss"]["date"].startswith("2026-09-24")
        and meta["kev"]["entries"] == 151
    )
    feeds = Feeds.load({"CVE-2021-44228", "CVE-2020-0001", "CVE-1999-9999"}, tmp_path)
    assert feeds.epss == {"CVE-2021-44228": 0.94358, "CVE-2020-0001": 0.00043}
    assert feeds.kev == {"CVE-2021-44228"} and feeds.epss_loaded and feeds.kev_loaded
    assert not is_stale(read_meta(tmp_path))


@pytest.mark.parametrize(
    "bad",
    [b"not gzip at all", gzip.compress(b"a,b\n1,2\n"), epss_gz(rows=5), OSError("network down")],
)
def test_bad_epss_never_replaces_a_good_cache(tmp_path: Path, bad: bytes | Exception) -> None:
    update_feeds(tmp_path, fake({EPSS_URL: epss_gz(), KEV_URL: kev_json()}))
    before = (tmp_path / "epss.csv.gz").read_bytes()
    meta = update_feeds(tmp_path, fake({EPSS_URL: bad, KEV_URL: kev_json()}))
    assert "epss" in meta["errors"] and "kev" not in meta["errors"]
    assert (tmp_path / "epss.csv.gz").read_bytes() == before


@pytest.mark.parametrize(
    "bad", [b"{}", b"nope", json.dumps({"vulnerabilities": [{"cveID": "CVE-2020-0001"}]}).encode()]
)
def test_bad_kev_is_rejected(tmp_path: Path, bad: bytes) -> None:
    meta = update_feeds(tmp_path, fake({EPSS_URL: epss_gz(), KEV_URL: bad}))
    assert "kev" in meta["errors"] and not (tmp_path / "kev.json").exists()


def test_hostile_rows_are_ignored(tmp_path: Path) -> None:
    junk = "not-a-cve,0.5,0.5\nCVE-2020-11111,7,0.5\nCVE-2020-22222,abc,0\n"
    update_feeds(tmp_path, fake({EPSS_URL: epss_gz(extra=junk), KEV_URL: kev_json()}))
    assert Feeds.load({"CVE-2020-11111", "CVE-2020-22222", "not-a-cve"}, tmp_path).epss == {}


def test_total_failure_records_errors_and_stays_stale(tmp_path: Path) -> None:
    down = OSError("offline")
    meta = update_feeds(tmp_path, fake({EPSS_URL: down, KEV_URL: down}))
    assert set(meta["errors"]) == {"epss", "kev"} and "fetched_at" not in meta and is_stale(meta)
    assert not Feeds.load({"CVE-2021-44228"}, tmp_path).epss_loaded


def test_staleness_window() -> None:
    now = datetime.now(timezone.utc)
    assert not is_stale({"fetched_at": (now - timedelta(hours=47)).isoformat()}, now)
    assert is_stale({"fetched_at": (now - timedelta(hours=49)).isoformat()}, now)
    assert is_stale({}) and is_stale({"fetched_at": "garbage"})


def test_ensure_fresh_respects_offline_and_swallows_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def spy(url: str) -> bytes:
        calls.append(url)
        raise OSError("down")

    ensure_fresh(spy)  # BULWARK_OFFLINE=1 from conftest
    assert calls == []
    monkeypatch.delenv("BULWARK_OFFLINE")
    ensure_fresh(spy)  # tries, fails, does not raise
    assert len(calls) == 2


def test_https_only_and_size_cap() -> None:
    from core.risk.feeds import http_get

    with pytest.raises(ValueError):
        http_get("http://example.com/x")
    with pytest.raises(ValueError):
        http_get("file:///etc/passwd")


def test_dependency_without_a_cve_is_unknown_not_confident() -> None:
    f = _vuln(Severity.CRITICAL)
    f.taxonomy = Taxonomy(Category.SCA, aliases=("GHSA-aaaa-bbbb-cccc",))
    f.scoring.confidence = 0.99
    out = score_finding(f, Feeds(epss_loaded=True))
    assert "No CVE id to look up exploit data" in out.scoring.risk_factors
    assert out.scoring.risk_score == round(100 * 0.95 * (0.5 + 0.5 * 0.3))
