from core.models import Category, Finding, Location, Taxonomy
from core.taxonomy import (
    CATEGORY_DEFAULTS,
    _load,
    cwe_name,
    enrich,
    normalize_cwe,
    normalize_owasp,
    owasp_for_cwe,
    owasp_name,
)


def _f(category: Category, cwe: tuple[str, ...] = (), owasp: tuple[str, ...] = ()) -> Finding:
    return Finding(
        id="x", title="t", description="", location=Location("a.py", 1, 1),
        taxonomy=Taxonomy(category, cwe=cwe, owasp_top_10_2021=owasp),
    )  # fmt: skip


def test_table_covers_all_ten_categories_and_matches_owasp_counts():
    cats = _load()
    assert sorted(cats) == [f"A{n:02d}:2021" for n in range(1, 11)]
    # Counts of CWEs OWASP lists per category (2021), a tripwire against a truncated data file.
    counts = {k: len(v["cwes"]) for k, v in cats.items()}  # type: ignore[arg-type]
    assert counts == {
        "A01:2021": 34, "A02:2021": 30, "A03:2021": 33, "A04:2021": 40, "A05:2021": 20,
        "A06:2021": 3, "A07:2021": 22, "A08:2021": 10, "A09:2021": 4, "A10:2021": 1,
    }  # fmt: skip


def test_well_known_mappings():
    assert owasp_for_cwe("CWE-79") == ("A03:2021",)
    assert owasp_for_cwe("CWE-89") == ("A03:2021",)
    assert owasp_for_cwe("CWE-22") == ("A01:2021",)
    assert owasp_for_cwe("CWE-798") == ("A07:2021",)
    assert owasp_for_cwe("CWE-327") == ("A02:2021",)
    assert owasp_for_cwe("CWE-918") == ("A10:2021",)
    assert owasp_for_cwe("CWE-259") == ("A02:2021", "A07:2021")  # in two categories
    assert owasp_for_cwe("CWE-99999") == ()


def test_normalizers_accept_variants_and_reject_junk():
    assert [normalize_cwe(x) for x in (79, "79", "cwe-79", "CWE_79", " CWE-79 ")] == ["CWE-79"] * 5
    assert [normalize_cwe(x) for x in ("", "CWE-", "abc", "0", "CWE-1;DROP", None)] == [None] * 6
    assert normalize_owasp("OWASP-A03:2021") == "A03:2021"
    assert normalize_owasp("A3") == "A03:2021"
    assert normalize_owasp("A11:2021") is None and normalize_owasp("A00") is None
    assert owasp_name("A03:2021") == "Injection" and owasp_name("nope") is None
    assert (
        cwe_name("79")
        == "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
    )


def test_enrich_fills_normalizes_and_never_drops():
    f = enrich(_f(Category.SAST, cwe=("79", "CWE-79", "junk")))
    assert f.taxonomy.cwe == ("CWE-79",) and f.taxonomy.owasp_top_10_2021 == ("A03:2021",)
    keep = enrich(_f(Category.SAST, owasp=("OWASP-A05:2021",)))  # scanner-only tag is kept
    assert keep.taxonomy.owasp_top_10_2021 == ("A05:2021",)


def test_category_defaults_only_when_nothing_else_is_known():
    assert enrich(_f(Category.SCA)).taxonomy.owasp_top_10_2021 == ("A06:2021",)
    assert enrich(_f(Category.IAC)).taxonomy.owasp_top_10_2021 == ("A05:2021",)
    assert (
        enrich(_f(Category.SAST)).taxonomy.owasp_top_10_2021 == ()
    )  # never guess for code findings
    assert enrich(_f(Category.SCA, cwe=("CWE-79",))).taxonomy.owasp_top_10_2021 == ("A03:2021",)
    assert set(CATEGORY_DEFAULTS) == {Category.SCA, Category.IAC}


def test_enrich_is_idempotent_and_returns_same_object_when_unchanged():
    once = enrich(_f(Category.SAST, cwe=("79",)))
    assert enrich(once) is once
