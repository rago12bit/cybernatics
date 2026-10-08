from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.correlation import correlate, fingerprint, same_defect
from core.correlation import normalize as norm
from core.models import Category, Finding, Location, Package, Severity, Taxonomy
from core.scan import ADAPTERS, DEFAULT_TOOLS


def code(
    tool: str,
    rule: str,
    line: int,
    *,
    cwe: str = "CWE-89",
    snippet: str = "x = db.run(q)",
    path: str = "a.py",
    sev: Severity = Severity.HIGH,
    conf: float = 0.6,
    cat: Category = Category.SAST,
    end: int | None = None,
) -> Finding:
    f = Finding(
        id=f"{tool}:{rule}:{path}:{line}",
        title=f"{tool} {rule}",
        description="d",
        location=Location(path, line, end or line, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(cat, cwe=(cwe,)),
    )
    f.scoring.normalized_severity, f.scoring.confidence = sev, conf
    f.scoring.native_severity = {tool: sev.value}
    f.evidence.reported_by, f.evidence.rule_ids = [tool], {tool: [rule]}
    return f


def sca(
    tool: str,
    vid: str,
    *,
    name: str = "lodash",
    ver: str = "4.17.4",
    eco: str = "npm",
    aliases: tuple[str, ...] = (),
    cves: tuple[str, ...] = (),
    sev: Severity = Severity.HIGH,
    cvss: float | None = None,
) -> Finding:
    f = Finding(
        id=f"{tool}:{vid}",
        title=f"{name} {ver}: {vid}",
        description="d",
        location=Location("package-lock.json", 1, 1, f"{name}@{ver}", "h"),
        taxonomy=Taxonomy(Category.SCA, cve=cves, aliases=(vid, *aliases)),
        package=Package(name, ver, eco),
    )
    f.scoring.normalized_severity, f.scoring.confidence, f.scoring.cvss_v3_1 = sev, 0.9, cvss
    f.evidence.reported_by, f.evidence.rule_ids = [tool], {tool: [vid]}
    return f


# ---- SCA ---------------------------------------------------------------------------------
def test_sca_merges_across_tools_via_shared_alias() -> None:
    trivy = sca("trivy", "CVE-1", cves=("CVE-1",))
    osv = sca("osv-scanner", "GHSA-x", aliases=("CVE-1",), cves=("CVE-1",), cvss=7.5)
    merged, stats = correlate([trivy, osv])
    assert len(merged) == 1 and stats.dedup_rate == 0.5
    m = merged[0]
    assert m.evidence.reported_by == ["trivy", "osv-scanner"] and m.evidence.agreement_count == 2
    assert m.scoring.cvss_v3_1 == 7.5  # taken from whichever tool had it
    assert set(m.taxonomy.aliases) == {"CVE-1", "GHSA-x"}


def test_sca_different_version_or_package_or_ecosystem_never_merges() -> None:
    base = sca("trivy", "CVE-1", cves=("CVE-1",))
    for other in (
        sca("osv-scanner", "CVE-1", ver="4.17.5", cves=("CVE-1",)),
        sca("osv-scanner", "CVE-1", name="express", cves=("CVE-1",)),
        sca("osv-scanner", "CVE-1", eco="pypi", cves=("CVE-1",)),
    ):
        assert len(correlate([base, other])[0]) == 2


def test_sca_without_shared_id_stays_separate() -> None:
    a = sca("trivy", "CVE-1", cves=("CVE-1",))
    b = sca("osv-scanner", "CVE-2", cves=("CVE-2",))
    assert len(correlate([a, b])[0]) == 2


def test_one_osv_group_bridges_two_trivy_cves() -> None:
    """OSV groups CVE-A and CVE-B as one advisory; Trivy lists them separately."""
    t1 = sca("trivy", "CVE-A", cves=("CVE-A",))
    t2 = sca("trivy", "CVE-B", cves=("CVE-B",))
    osv = sca("osv-scanner", "GHSA-1", aliases=("CVE-A", "CVE-B"), cves=("CVE-A", "CVE-B"))
    merged, _ = correlate([t1, t2, osv])
    assert len(merged) == 1 and set(merged[0].taxonomy.cve) == {"CVE-A", "CVE-B"}


# ---- code findings ----------------------------------------------------------------------
def test_line_disagreement_within_window_merges() -> None:
    a = code(
        "bandit",
        "B608",
        6,
        snippet='5 def f(q):\n6     query = "S" + q\n7     return db.execute(query)',
    )
    b = code("semgrep", "sqli", 7, snippet="return db.execute(query)")
    assert same_defect(a, b) and len(correlate([a, b])[0]) == 1


@pytest.mark.parametrize("gap,expect", [(0, 1), (3, 1), (4, 2), (10, 2)])
def test_line_window_boundary(gap: int, expect: int) -> None:
    a = code("bandit", "B1", 10, snippet="x = db.run(query)")
    b = code("semgrep", "S1", 10 + gap, snippet="x = db.run(query)")
    assert len(correlate([a, b])[0]) == expect


def test_containment_beats_jaccard_when_one_tool_quotes_more_context() -> None:
    big = "1 import os\n2 def run(cmd):\n3     return subprocess.call(cmd, shell=True)\n4 x = 1\n5 y = 2"
    small = "return subprocess.call(cmd, shell=True)"
    assert norm.overlap(norm.tokens(big), norm.tokens(small)) == 1.0
    a, b = code("bandit", "B602", 3, snippet=big, cwe="CWE-78"), code("semgrep", "s", 3, snippet=small, cwe="CWE-78")  # fmt: skip
    assert same_defect(a, b)


def test_unrelated_code_on_nearby_lines_does_not_merge() -> None:
    a = code("bandit", "B1", 10, snippet="password = get_pw()")
    b = code("semgrep", "S1", 11, snippet="for item in items: total += item.price * qty")
    assert not same_defect(a, b)


@pytest.mark.parametrize(
    "kw",
    [
        {"cwe": "CWE-79"},  # different weakness
        {"path": "b.py"},  # different file
    ],
)
def test_different_cwe_or_file_never_merges(kw: dict[str, str]) -> None:
    a = code("bandit", "B1", 5)
    b = code("semgrep", "S1", 5, **kw)
    assert len(correlate([a, b])[0]) == 2


def test_cwe_family_lets_hardcoded_password_meet_generic_credential() -> None:
    """Bandit says CWE-259, Gitleaks says CWE-798 (its parent): one defect to a user."""
    ph = "[snippet withheld: hardcoded credential]"
    a = code("bandit", "B105", 20, cwe="CWE-259", snippet=ph, sev=Severity.LOW)
    b = code("gitleaks", "generic-api-key", 20, cwe="CWE-798", snippet="[secret redacted]",
             cat=Category.SECRETS, conf=0.7)  # fmt: skip
    (m,), _ = correlate([a, b])
    assert m.taxonomy.category is Category.SECRETS  # the higher-severity secret finding leads
    assert set(m.taxonomy.cwe) == {"CWE-798", "CWE-259"} and m.scoring.normalized_severity is Severity.HIGH  # fmt: skip


def test_placeholder_snippets_require_adjacent_lines() -> None:
    """Redacted snippets carry no evidence, so a 2-line gap must NOT merge (PASSWORD vs SECRET)."""
    ph = "[snippet withheld: hardcoded credential]"
    a = code("bandit", "B105", 18, cwe="CWE-259", snippet=ph)
    b = code("gitleaks", "gl", 20, cwe="CWE-798", snippet="[secret redacted]", cat=Category.SECRETS)
    c = code(
        "gitleaks", "gl2", 19, cwe="CWE-798", snippet="[secret redacted]", cat=Category.SECRETS
    )
    assert not same_defect(a, b) and same_defect(a, c)


def test_short_snippets_fall_back_to_adjacency() -> None:
    assert len(norm.tokens("run()")) < 4  # too short to compare meaningfully
    a, b = code("bandit", "B1", 5, snippet="run()"), code("semgrep", "S1", 7, snippet="run()")
    assert not same_defect(a, b)  # no evidence at distance 2
    assert same_defect(a, code("semgrep", "S1", 6, snippet="run()"))  # adjacent is enough


def test_same_tool_same_rule_occurrences_are_never_merged() -> None:
    """Two identical call sites are two defects, even if a wide finding from another tool spans both."""
    a1 = code("bandit", "B602", 10, snippet="subprocess.call(a, shell=True)", cwe="CWE-78")
    a2 = code("bandit", "B602", 11, snippet="subprocess.call(b, shell=True)", cwe="CWE-78")
    wide = code("semgrep", "S", 10, end=11, snippet="subprocess.call(a, shell=True)\nsubprocess.call(b, shell=True)", cwe="CWE-78")  # fmt: skip
    merged, _ = correlate([a1, a2, wide])
    assert len(merged) == 2  # wide joins one occurrence; the other survives on its own
    assert sorted(len(m.evidence.reported_by) for m in merged) == [1, 2]


def test_same_tool_different_rules_on_one_defect_merge_and_keep_both_rules() -> None:
    a = code("semgrep", "audit-rule", 11, snippet="subprocess.call(cmd, shell=True)", cwe="CWE-78")
    b = code("semgrep", "shell-true", 11, snippet="subprocess.call(cmd, shell=True)", cwe="CWE-78")
    (m,), _ = correlate([a, b])
    assert m.evidence.rule_ids == {"semgrep": ["audit-rule", "shell-true"]}
    assert m.evidence.agreement_count == 1  # one *tool*, so no fake agreement bonus


def test_findings_without_cwe_are_never_cross_merged() -> None:
    a, b = code("trivy", "R1", 3), code("trivy", "R2", 3)
    a.taxonomy = b.taxonomy = Taxonomy(Category.IAC)
    assert len(correlate([a, b])[0]) == 2


# ---- merge semantics --------------------------------------------------------------------
def test_merge_takes_max_severity_keeps_native_labels_and_boosts_confidence() -> None:
    a = code("bandit", "B1", 5, sev=Severity.MEDIUM, conf=0.6, snippet="x = db.run(q)")
    b = code("semgrep", "S1", 5, sev=Severity.HIGH, conf=0.6, snippet="x = db.run(q)")
    (m,), _ = correlate([a, b])
    assert m.scoring.normalized_severity is Severity.HIGH
    assert m.scoring.native_severity == {"bandit": "MEDIUM", "semgrep": "HIGH"}
    assert m.scoring.confidence == pytest.approx(0.84)  # noisy-OR: 1 - 0.4*0.4
    assert m.evidence.agreement_count == 2 and m.id == b.id  # highest-severity member leads


def test_confidence_is_capped_below_certainty() -> None:
    findings = [code(t, "r", 5, conf=0.95) for t in ("bandit", "semgrep", "gitleaks")]
    assert correlate(findings)[0][0].scoring.confidence == 0.99


def test_singletons_pass_through_unchanged_and_output_is_sorted() -> None:
    lo = code("bandit", "B1", 30, cwe="CWE-1", sev=Severity.LOW, snippet="unrelated_a()")
    hi = code("semgrep", "S1", 90, cwe="CWE-2", sev=Severity.CRITICAL, snippet="unrelated_b()")
    merged, stats = correlate([lo, hi])
    assert [m.id for m in merged] == [hi.id, lo.id] and stats.dedup_rate == 0.0
    assert merged[1].scoring.confidence == lo.scoring.confidence


def test_correlate_is_order_independent_and_does_not_mutate_inputs() -> None:
    fs = [
        code("bandit", "B602", 11, cwe="CWE-78", snippet="subprocess.call(c, shell=True)"),
        code("semgrep", "S1", 11, cwe="CWE-78", snippet="subprocess.call(c, shell=True)"),
        code("semgrep", "S2", 11, cwe="CWE-78", snippet="subprocess.call(c, shell=True)"),
        sca("trivy", "CVE-9", cves=("CVE-9",)),
        sca("osv-scanner", "GHSA-9", aliases=("CVE-9",)),
    ]
    before = [f.to_dict() for f in fs]
    fwd = [m.fingerprint for m in correlate(fs)[0]]
    rev = [m.fingerprint for m in correlate(list(reversed(fs)))[0]]
    assert sorted(fwd) == sorted(rev)
    assert [f.to_dict() for f in fs] == before


# ---- repeats: one tool, one defect, one place, reported more than once ---------------------
def test_a_rule_reported_several_times_on_one_line_is_one_finding() -> None:
    """Semgrep reported `no-replaceall` 5 times on one line of Juice Shop (different columns)."""
    repeats = [code("semgrep", "no-replaceall", 59, snippet="s.replaceAll(a, b)", conf=0.6)
               for _ in range(5)]  # fmt: skip
    merged, stats = correlate(repeats)
    assert len(merged) == 1 and (stats.raw, stats.unique, stats.repeats) == (5, 1, 4)
    (m,) = merged
    assert m.scoring.confidence == 0.6  # a tool repeating itself is not a second opinion
    assert m.evidence.agreement_count == 1
    assert m.description.endswith("Reported 4 more times at this place in this scan.")


def test_two_tools_at_one_place_are_not_repeats_of_each_other() -> None:
    """With no CWE and no rule id, a Bandit and a Gitleaks finding on one line share a fingerprint;
    the merge rules keep them apart (nothing says they are one defect), and folding must not undo
    that -- a repeat is one tool reporting again."""
    a, b = code("bandit", "", 20), code("gitleaks", "", 20)
    for f in (a, b):
        f.taxonomy, f.evidence.rule_ids = Taxonomy(Category.SAST), {}
    merged, stats = correlate([a, b])
    assert len(merged) == 2 and stats.repeats == 0


def test_identical_code_on_two_lines_is_two_findings_though_one_issue() -> None:
    """Juice Shop's server.ts has the same `app.use(..., serveIndex(...))` on lines 270, 274 and
    278: three places to fix. They share a fingerprint (it ignores the line, so a moved defect stays
    one Issue), so they are one Issue -- but the scan still lists all three."""
    snippet = "app.use('/x', serveIndex('y', { icons: true }))"
    found = [code("semgrep", "dir-listing", n, snippet=snippet) for n in (270, 274, 278)]
    merged, stats = correlate(found)
    assert (len(merged), stats.repeats) == (3, 0)
    assert len({m.fingerprint for m in merged}) == 1 and len({m.id for m in merged}) == 3


def test_a_web_alert_on_one_url_with_different_evidence_is_one_finding() -> None:
    from core.dast.mapping import zap_alert_findings

    alert = {"pluginid": "10096", "alert": "Timestamp Disclosure - Unix", "riskcode": "0",
             "instances": [{"uri": "http://t/styles.css", "evidence": e}
                           for e in ("1650485437", "1981395349", "2038834951")]
             + [{"uri": "http://t/main.js", "evidence": "1650485437"}]}  # fmt: skip
    merged, stats = correlate(zap_alert_findings(alert, "http://t"))
    assert sorted(m.location.route for m in merged) == ["/main.js", "/styles.css"]
    assert stats.repeats == 2 and len({m.id for m in merged}) == 2


def test_the_recorded_juice_shop_scans_have_one_finding_per_issue_place() -> None:
    """The site's first recording (real scans of Juice Shop v17.3.0, kept in tests/fixtures) said
    139 unique code findings with 124 distinct ids, and 49 runtime findings for 39 Issues."""
    from core.models.finding import finding_from_dict

    data = json.loads(Path("tests/fixtures/correlation/juiceshop-2026-10-07-findings.json").read_text())
    for raw, unique, issues in ((data["code"], 124, 113), (data["runtime"], 39, 39)):
        merged, stats = correlate([finding_from_dict(f) for f in raw])
        assert stats.unique == len(merged) == unique
        assert len({m.id for m in merged}) == unique  # every id is one finding
        assert len({m.fingerprint for m in merged}) == issues


def test_empty_input() -> None:
    assert correlate([]) == ([], correlate([])[1]) and correlate([])[1].dedup_rate == 0.0


# ---- fingerprints ----------------------------------------------------------------------
def test_code_fingerprint_survives_whitespace_comments_and_renames() -> None:
    a = code("bandit", "B1", 5, snippet='query = "SELECT " + user_id  # build query')
    b = code(
        "bandit", "B1", 40, snippet='q  =   "SELECT x"   +   uid'
    )  # moved, renamed, reformatted
    c = code("bandit", "B1", 5, snippet='query = "SELECT " + user_id + extra')  # different code
    assert fingerprint(a) == fingerprint(b) != fingerprint(c)


def test_code_fingerprint_depends_on_cwe_and_path() -> None:
    base = code("bandit", "B1", 5)
    assert fingerprint(base) != fingerprint(code("bandit", "B1", 5, cwe="CWE-79"))
    assert fingerprint(base) != fingerprint(code("bandit", "B1", 5, path="b.py"))


def test_code_fingerprint_distinguishes_different_rules_with_no_snippet() -> None:
    """Real bug, confirmed against this repo's own golden scan data (see fingerprint()'s
    docstring): Trivy's Dockerfile checks quote no snippet at all, so two *different* rules on the
    same line -- DS002 "runs as root" and DS026 "no HEALTHCHECK" -- used to hash identically and
    silently collapse into one tracked Issue."""
    ds002 = code("trivy", "DS002", 1, cwe="", snippet="")
    ds026 = code("trivy", "DS026", 1, cwe="", snippet="")
    assert fingerprint(ds002) != fingerprint(ds026)


def test_code_fingerprint_distinguishes_different_rules_sharing_one_quoted_block() -> None:
    """Real bug, confirmed against this repo's own golden scan data: an IaC linter (Trivy's
    Terraform checks, for one) routinely quotes the *entire resource block* verbatim for every rule
    that fires against it, so several genuinely different misconfiguration findings on one resource
    used to share a snippet and hash identically."""
    block = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "public-read"\n}'
    public_acl = code("trivy", "AVD-AWS-0086", 1, cwe="", snippet=block)
    no_versioning = code("trivy", "AVD-AWS-0090", 1, cwe="", snippet=block)
    assert fingerprint(public_acl) != fingerprint(no_versioning)


def test_sca_fingerprint_is_exact_and_tool_independent() -> None:
    t = sca("trivy", "CVE-1", cves=("CVE-1",))
    o = sca("osv-scanner", "GHSA-x", aliases=("CVE-1",), cves=("CVE-1",))
    assert fingerprint(t) == fingerprint(o)  # same package + same CVE, whichever tool saw it
    assert fingerprint(t) != fingerprint(sca("trivy", "CVE-1", ver="4.17.5", cves=("CVE-1",)))
    assert fingerprint(t) != fingerprint(sca("trivy", "CVE-2", cves=("CVE-2",)))
    assert fingerprint(t).startswith("sha256:") and len(fingerprint(t)) == 71


# ---- normalization ---------------------------------------------------------------------
def test_normalizer_masks_names_strings_numbers_and_drops_comments() -> None:
    assert norm.tokens('total = price * 12  # sales tax\nname = "bob"') == [
        "ID", "=", "ID", "*", "NUM", "ID", "=", "STR",
    ]  # fmt: skip
    assert norm.tokens("def f(x): return x") == ["def", "ID", "(", "ID", ")", ":", "return", "ID"]


def test_line_number_prefixes_stripped_only_when_all_lines_have_them() -> None:
    assert norm.tokens("3 def f():\n4     pass") == norm.tokens("def f():\n    pass")
    assert norm.strip_line_numbers("x = 1\n2 y") == "x = 1\n2 y"  # mixed: leave alone


def test_placeholder_detection() -> None:
    assert norm.is_placeholder("[secret redacted]") and norm.is_placeholder("[snippet withheld: x]")
    assert not norm.is_placeholder("password = 'x'")
    assert norm.overlap([], ["a"]) == 0.0


# ---- real scanner output (regression snapshot) ----------------------------------------
def _real() -> list[Finding]:
    out: list[Finding] = []
    for name in DEFAULT_TOOLS:  # the published snapshot covers the original five scanners
        out += ADAPTERS[name].parse(Path(f"tests/golden/{name}/raw.json").read_bytes())
    return out


def test_real_scanner_output_snapshot() -> None:
    merged, stats = correlate(_real())
    assert (stats.raw, stats.unique) == (62, 38)
    summary = [
        {"fp": m.fingerprint, "tools": m.evidence.reported_by, "sev": m.scoring.normalized_severity.value,
         "path": m.location.path, "line": m.location.start_line, "n": m.evidence.agreement_count}
        for m in merged
    ]  # fmt: skip
    golden = Path("tests/golden/correlation/expected.json")
    if not golden.exists():  # first run records the snapshot; afterwards it guards regressions
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(json.dumps(summary, indent=1, sort_keys=True))
    assert summary == json.loads(golden.read_text())


def test_real_output_key_merges_and_key_non_merges() -> None:
    merged, _ = correlate(_real())
    by_line = {(m.location.path, m.location.start_line): m for m in merged if m.location.path.endswith("users.py")}  # fmt: skip
    assert set(by_line[("src/users.py", 7)].evidence.reported_by) == {"bandit", "semgrep"}  # SQLi
    assert set(by_line[("src/users.py", 11)].evidence.reported_by) == {"bandit", "semgrep"}  # shell
    assert len(by_line[("src/users.py", 11)].evidence.rule_ids["semgrep"]) == 2
    assert set(by_line[("src/users.py", 20)].evidence.reported_by) == {
        "bandit",
        "gitleaks",
    }  # secret
    assert by_line[("src/users.py", 2)].evidence.reported_by == ["bandit"]  # `import subprocess`
    assert by_line[("src/users.py", 18)].evidence.reported_by == ["bandit"]  # low-entropy PASSWORD
    sca_pairs = [m for m in merged if m.package and m.evidence.agreement_count == 2]
    assert len(sca_pairs) == 17  # every OSV finding matched a Trivy one


# ---- severity matrix -------------------------------------------------------------------
def test_severity_matrix_matches_the_design_doc_and_the_published_table() -> None:
    from core.scoring.severity import MATRIX, as_markdown, from_cvss, normalize

    assert normalize("semgrep", "error") is Severity.HIGH  # SARIF level casing tolerated
    assert normalize("semgrep", "WARNING") is Severity.MEDIUM and normalize("semgrep", "INFO") is Severity.LOW  # fmt: skip
    assert normalize("bandit", "HIGH") is Severity.HIGH
    assert normalize("trivy", "CRITICAL") is Severity.CRITICAL and normalize("trivy", "UNKNOWN") is Severity.INFO  # fmt: skip
    assert normalize("gitleaks", "anything at all") is Severity.HIGH  # "(all) -> HIGH"
    assert normalize("mystery-tool", "HIGH") is Severity.INFO  # unknown tools never inflate risk
    assert [from_cvss(x) for x in (10, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0)] == [
        Severity.CRITICAL, Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM,
        Severity.MEDIUM, Severity.LOW, Severity.LOW, Severity.INFO,
    ]  # fmt: skip
    doc = Path("docs/severity-matrix.md").read_text()
    assert as_markdown() in doc, "docs/severity-matrix.md is stale: run scripts/gen-api-docs.py"
    assert set(MATRIX) >= set(ADAPTERS), "every scanner needs a row in the matrix"
