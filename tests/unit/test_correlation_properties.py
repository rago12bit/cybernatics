"""Property-based tests for fingerprinting and matching (Week 48 task 1, plan §22.3): the three
invariants the plan names explicitly -- whitespace changes never change a fingerprint, a different
CWE always does, and matching is symmetric -- proven against many generated inputs, not just the
specific examples test_correlation.py's example-based tests happen to cover. Complements that file,
doesn't replace it.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from core.correlation import normalize as norm
from core.correlation.engine import fingerprint, same_defect
from core.models import Category, Finding, Location, Taxonomy

_TOKEN_TEXT = st.sampled_from(
    ["foo", "bar_baz", "userId", "helper", "if", "return", "for", "(", ")", "=", "==", "+", ","]
)
_WHITESPACE = st.sampled_from([" ", "  ", "   ", "\t", "\n", "\n    ", "\n\t"])

# CWEs deliberately excluding CWE-259/321/260 and their alias target CWE-798 (core.correlation.
# engine.CWE_FAMILY): those are SUPPOSED to fingerprint identically, by design -- including them here
# would make this test fail on a feature, not a bug.
_UNALIASED_CWES = st.sampled_from(["CWE-79", "CWE-89", "CWE-22", "CWE-918", "CWE-611", "CWE-502"])


def _join_with(tokens: list[str], spacers: list[str]) -> str:
    if not tokens:
        return ""
    out = tokens[0]
    for tok, sp in zip(tokens[1:], spacers, strict=True):
        out += sp + tok
    return out


@st.composite
def _snippet_whitespace_variants(draw: st.DrawFn) -> tuple[str, str]:
    """Two renderings of the SAME token sequence, differing only in how much/what kind of
    whitespace separates each pair of tokens -- never in whether a separator exists at all, since
    `_WHITESPACE` never draws the empty string (removing a separator entirely can change
    tokenization, e.g. merging two identifiers, which is a different claim than the one being
    tested here)."""
    tokens = draw(st.lists(_TOKEN_TEXT, min_size=1, max_size=10))
    gaps = max(0, len(tokens) - 1)
    spacers_a = draw(st.lists(_WHITESPACE, min_size=gaps, max_size=gaps))
    spacers_b = draw(st.lists(_WHITESPACE, min_size=gaps, max_size=gaps))
    return _join_with(tokens, spacers_a), _join_with(tokens, spacers_b)


def _code_finding(
    *, path: str = "app.py", snippet: str = "foo()", cwe: str = "CWE-89", rule: str = "R1"
) -> Finding:
    return Finding(
        id="f1", title="t", description="d",
        location=Location(path, 10, 10, snippet=snippet),
        taxonomy=Taxonomy(Category.SAST, cwe=(cwe,)),
    )  # fmt: skip


@given(_snippet_whitespace_variants())
def test_snippet_hash_is_whitespace_invariant(pair: tuple[str, str]) -> None:
    a, b = pair
    assert norm.snippet_hash(a) == norm.snippet_hash(b)


@given(_snippet_whitespace_variants())
def test_fingerprint_is_whitespace_invariant(pair: tuple[str, str]) -> None:
    a, b = pair
    fa = fingerprint(_code_finding(snippet=a))
    fb = fingerprint(_code_finding(snippet=b))
    assert fa == fb


@given(_UNALIASED_CWES, _UNALIASED_CWES)
def test_a_different_cwe_always_changes_the_fingerprint(cwe_a: str, cwe_b: str) -> None:
    fa = fingerprint(_code_finding(cwe=cwe_a))
    fb = fingerprint(_code_finding(cwe=cwe_b))
    if cwe_a == cwe_b:
        assert fa == fb
    else:
        assert fa != fb


@given(
    st.sampled_from(["app.py", "other.py"]),
    st.sampled_from(["app.py", "other.py"]),
    _UNALIASED_CWES,
    _UNALIASED_CWES,
    st.sampled_from(["foo()", "bar_baz(x, y)", "if foo: return bar_baz", ""]),
    st.sampled_from(["foo()", "bar_baz(x, y)", "if foo: return bar_baz", ""]),
)
def test_same_defect_is_symmetric(
    path_a: str, path_b: str, cwe_a: str, cwe_b: str, snippet_a: str, snippet_b: str
) -> None:
    a = _code_finding(path=path_a, cwe=cwe_a, snippet=snippet_a)
    b = _code_finding(path=path_b, cwe=cwe_b, snippet=snippet_b)
    assert same_defect(a, b) == same_defect(b, a)
