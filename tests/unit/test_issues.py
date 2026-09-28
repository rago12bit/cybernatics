from __future__ import annotations

from core.correlation import correlate
from core.issues import ExistingIssue, fallback_key, match_keys, sync
from core.models import Category, Finding, Location, Package, Severity, Taxonomy


def code(
    *,
    cwe: str = "CWE-89",
    snippet: str = "x = db.run(q)",
    path: str = "a.py",
    line: int = 10,
    finding_id: str = "semgrep:sqli:a.py:10",
    rule_id: str = "sqli",
) -> Finding:
    f = Finding(
        id=finding_id,
        title="t",
        description="d",
        location=Location(path, line, line, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(Category.SAST, cwe=(cwe,)),
    )
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = ["semgrep"]
    f.evidence.rule_ids = {"semgrep": [rule_id]}
    return f


def sca_finding(*, name: str = "lodash", ver: str = "4.17.4", cve: str = "CVE-2020-1"):
    f = Finding(
        id=f"osv:{cve}:{name}",
        title="t",
        description="d",
        location=Location("package.json", 1, 1),
        taxonomy=Taxonomy(Category.SCA, cve=(cve,)),
        package=Package(ecosystem="npm", name=name, version=ver),
    )
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = ["osv-scanner"]
    return f


def finalized(*findings: Finding) -> list[Finding]:
    """Findings the way the pipeline hands them to issue-sync: after correlate(), so .fingerprint
    is populated (only correlate() computes it)."""
    merged, _ = correlate(findings)
    return merged


def test_fallback_key_ignores_path_but_not_cwe_or_content() -> None:
    a = finalized(code(path="a.py"))[0]
    b = finalized(code(path="b.py"))[0]  # same CWE, same snippet, different file
    assert fallback_key(a) == fallback_key(b)

    c = finalized(code(path="a.py", cwe="CWE-79"))[0]
    assert fallback_key(a) != fallback_key(c)

    d = finalized(code(path="a.py", snippet="totally different code"))[0]
    assert fallback_key(a) != fallback_key(d)


def test_fallback_key_is_none_only_for_sca_findings() -> None:
    """SCA's package/version/CVE identity is already location-independent, so its primary
    fingerprint already serves as its own fallback (ADR-0004) -- a second, duplicate key here would
    be redundant, not wrong, but the point of `fallback_key` is a *different* location-independent
    key from the primary one."""
    sca = finalized(sca_finding())[0]
    assert fallback_key(sca) is None


def test_fallback_key_handles_placeholder_and_empty_snippets_via_rule_id() -> None:
    """A placeholder (redacted) or genuinely empty snippet gives nothing to hash on its own -- but
    unlike an earlier version of this function, that no longer means "give up and return None": the
    rule id anchors it instead, so a redacted secret (or a Dockerfile-style whole-line check with no
    snippet at all) still gets a real, *distinct* fallback identity per rule, and can still be
    tracked across a file move. Without the rule id, two different rules that both redact to
    "[secret redacted]" -- or both quote nothing at all -- would collide onto the same key anywhere
    in the asset, which is exactly the real bug this guards against (see
    core.correlation.engine.fingerprint's docstring for the confirmed real-world case)."""
    a = finalized(code(snippet="[secret redacted]", rule_id="generic-api-key"))[0]
    b = finalized(code(snippet="[secret redacted]", rule_id="aws-access-key"))[0]
    assert fallback_key(a) is not None
    assert fallback_key(a) != fallback_key(b)  # different rules, same placeholder text
    assert fallback_key(a) == fallback_key(finalized(code(snippet="[secret redacted]", rule_id="generic-api-key", path="elsewhere.py"))[0])  # fmt: skip

    empty_a = finalized(code(snippet="", rule_id="DS002"))[0]
    empty_b = finalized(code(snippet="", rule_id="DS026"))[0]
    assert fallback_key(empty_a) is not None
    assert fallback_key(empty_a) != fallback_key(empty_b)


def test_match_keys_primary_is_the_correlation_fingerprint() -> None:
    f = finalized(code())[0]
    assert match_keys(f).primary == f.fingerprint
    assert f.fingerprint  # never empty once correlated


def _issue(
    id_: str, fp: str, state: str, fallback: str | None = None, category: str = "sast"
) -> ExistingIssue:
    return ExistingIssue(
        id=id_, category=category, fingerprint=fp, fallback_fingerprint=fallback, state=state
    )


def _ids(prefix: str = "new"):
    n = [0]

    def gen() -> str:
        n[0] += 1
        return f"{prefix}-{n[0]}"

    return gen


def test_unmatched_finding_becomes_a_new_issue() -> None:
    f = finalized(code())[0]
    result = sync([f], existing=[], new_issue_id=_ids())
    assert len(result.updates) == 1
    u = result.updates[0]
    assert u.is_new_issue and u.state == "new" and u.fingerprint == f.fingerprint
    assert result.new_count == 1 and result.reintroduced_count == 0 and result.fixed_count == 0


def test_second_sighting_of_a_new_issue_settles_to_open() -> None:
    f = finalized(code())[0]
    existing = [_issue("i1", f.fingerprint, "new")]
    result = sync([f], existing=existing, new_issue_id=_ids())
    u = result.updates[0]
    assert u.issue_id == "i1" and u.state == "open" and not u.is_new_issue


def test_matched_finding_reuses_the_issue_and_stays_open() -> None:
    f = finalized(code())[0]
    existing = [_issue("i1", f.fingerprint, "open")]
    result = sync([f], existing=existing, new_issue_id=_ids())
    u = result.updates[0]
    assert u.issue_id == "i1" and u.state == "open" and not u.is_new_issue
    assert result.new_count == 0


def test_fixed_issue_that_reappears_is_reintroduced() -> None:
    f = finalized(code())[0]
    existing = [_issue("i1", f.fingerprint, "fixed")]
    result = sync([f], existing=existing, new_issue_id=_ids())
    u = result.updates[0]
    assert u.issue_id == "i1" and u.state == "reintroduced"
    assert result.reintroduced_count == 1


def test_moved_file_matches_by_fallback_and_keeps_the_issue_identity() -> None:
    old = finalized(code(path="old/place.py"))[0]
    existing = [_issue("i1", old.fingerprint, "open", fallback_key(old))]
    moved = finalized(code(path="new/place.py"))[0]  # same CWE + snippet, different path
    result = sync([moved], existing=existing, new_issue_id=_ids())
    u = result.updates[0]
    assert u.issue_id == "i1" and not u.is_new_issue
    # the primary fingerprint stored going forward is the NEW one (it includes the path)
    assert u.fingerprint == moved.fingerprint and u.fingerprint != old.fingerprint


def test_issue_absent_from_the_scan_is_marked_fixed() -> None:
    present = finalized(code(path="a.py"))[0]
    existing = [
        _issue("i1", present.fingerprint, "open"),
        _issue("i2", "sha256:doesnotmatchanything", "open"),
        _issue("i3", "sha256:alreadyfixed", "fixed"),  # already fixed: not fixed again
    ]
    result = sync([present], existing=existing, new_issue_id=_ids())
    assert result.fixed_issue_ids == ["i2"]
    assert result.fixed_count == 1


def test_two_findings_in_one_scan_never_collapse_to_one_issue() -> None:
    a = finalized(code(path="a.py", line=1, finding_id="s:a:1"))[0]
    b = finalized(code(path="b.py", line=1, finding_id="s:b:1", cwe="CWE-79"))[0]
    result = sync([a, b], existing=[], new_issue_id=_ids())
    assert len({u.issue_id for u in result.updates}) == 2
    assert result.new_count == 2


def _redacted(finding_id: str, cat: Category) -> Finding:
    f = Finding(
        id=finding_id,
        title="t",
        description="d",
        location=Location("a.py", 20, 20, "[secret redacted]", "h"),
        taxonomy=Taxonomy(cat),  # no CWE, deliberately
    )
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = ["some-tool"]
    return f


def test_different_categories_never_collapse_even_with_the_same_raw_fingerprint() -> None:
    # A finding with no CWE, on a redacted (placeholder) line, hashes to `none|path|placeholder|
    # line` regardless of category (fingerprint() does not know about category, by design: it is
    # also used by correlate(), which checks category compatibility separately via same_defect()).
    # Two genuinely different findings that happen to share that shape must still become two Issues.
    sast = _redacted("bandit:a.py:20", Category.SAST)
    secret = _redacted("gitleaks:a.py:20", Category.SECRETS)
    merged = finalized(sast, secret)
    assert len(merged) == 2  # correlate() must not merge these either: different categories
    assert merged[0].fingerprint == merged[1].fingerprint  # the ambiguity this test is about

    result = sync(merged, existing=[], new_issue_id=_ids())
    assert len({u.issue_id for u in result.updates}) == 2
    assert result.new_count == 2

    # And the second scan of the same asset must reuse both issues, not collide on insert.
    second_scan_existing = [
        ExistingIssue(u.issue_id, f.taxonomy.category.value, u.fingerprint, None, u.state)
        for f, u in zip(merged, result.updates, strict=True)
    ]
    again = sync(merged, existing=second_scan_existing, new_issue_id=_ids("should-not-be-used"))
    assert {u.issue_id for u in again.updates} == {u.issue_id for u in result.updates}
    assert again.new_count == 0
