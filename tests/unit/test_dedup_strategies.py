"""Deduplication strategies (Week 58, plan §42.3, ADR-0042): what each one treats as the same Issue,
what it ignores, and that a key is stable, namespaced and validated."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from core.correlation import correlate
from core.dast.mapping import zap_alert_findings
from core.dedup.strategies import (
    DEFAULT,
    FIELDS,
    STRATEGIES,
    describe,
    is_namespaced,
    key_for,
    source_of,
    validate,
)
from core.models import Category, Finding, Location, Package, Severity, Taxonomy


def code(
    path: str = "a.py",
    line: int = 10,
    rule: str = "r1",
    cwe: str = "CWE-89",
    tool: str = "semgrep",
    snippet: str = "danger(x)",
    title: str = "SQL injection",
) -> Finding:
    f = Finding(
        id=f"{tool}:{rule}:{path}:{line}", title=title, description="d",
        location=Location(path, line, line, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(Category.SAST, cwe=(cwe,)),
    )  # fmt: skip
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = [tool]
    f.evidence.rule_ids = {tool: [rule]}
    return correlate([f])[0][0]


def web(
    route: str = "/a", host: str = "https://t.example", rule: str = "10020", cwe: str = "1021"
) -> Finding:
    alert = {"pluginid": rule, "alert": "XFO", "riskcode": "2", "cweid": cwe,
             "instances": [{"uri": f"{host}{route}"}]}  # fmt: skip
    return correlate(zap_alert_findings(alert, host, "zap"))[0][0]


def lib(version: str = "4.17.4", cve: str = "CVE-2019-10744") -> Finding:
    f = Finding(
        id="grype:x", title="lodash: pp", description="d",
        location=Location("package-lock.json", 1, 1, "lodash@4.17.4", ""),
        taxonomy=Taxonomy(Category.SCA, cve=(cve,), aliases=(cve,)),
        package=Package("lodash", version, "npm"),
    )  # fmt: skip
    f.evidence.reported_by = ["grype"]
    f.evidence.rule_ids = {"grype": [cve]}
    return correlate([f])[0][0]


def test_the_default_changes_nothing_and_package_is_the_same_key_for_a_package() -> None:
    for f in (code(), web(), lib()):
        assert key_for("fingerprint_v2", f) == f.fingerprint
        assert key_for("package", f) == f.fingerprint
    assert DEFAULT == "fingerprint_v2" and set(STRATEGIES) == {
        "fingerprint_v2", "tool_id", "hash_fields", "tool_id_or_hash", "package"}  # fmt: skip


def test_tool_id_is_the_rule_and_the_place_and_ignores_line_snippet_and_cwe() -> None:
    base = key_for("tool_id", code())
    assert (
        key_for("tool_id", code(line=99, snippet="other(y)", cwe="CWE-20", title="renamed")) == base
    )
    assert key_for("tool_id", code(path="b.py")) != base  # another file
    assert key_for("tool_id", code(rule="r2")) != base  # another rule
    assert key_for("tool_id", code(tool="bandit")) != base  # another source


def test_tool_id_for_a_web_finding_is_rule_host_and_route() -> None:
    base = key_for("tool_id", web())
    assert key_for("tool_id", web(cwe="693")) == base  # a CWE that moves between tool versions
    assert key_for("tool_id", web(route="/b")) != base
    assert key_for("tool_id", web(host="https://other.example")) != base
    assert key_for("tool_id", web(rule="10038")) != base


def test_tool_id_for_a_package_does_not_include_the_version() -> None:
    """The scanner's id for 'lodash has this CVE' is the same before and after an upgrade that did
    not fix it -- unlike `package`, which is version-exact."""
    assert key_for("tool_id", lib("4.17.4")) == key_for("tool_id", lib("4.17.11"))
    assert key_for("package", lib("4.17.4")) != key_for("package", lib("4.17.11"))


def test_hash_fields_uses_exactly_the_chosen_fields() -> None:
    a = key_for("hash_fields", code(), ("title", "path"))
    assert key_for("hash_fields", code(line=50, cwe="CWE-20", rule="zzz"), ("title", "path")) == a
    assert key_for("hash_fields", code(title="other"), ("title", "path")) != a
    assert key_for("hash_fields", code(path="b.py"), ("title", "path")) != a
    assert (
        key_for("hash_fields", code(title="  SQL   Injection "), ("title", "path")) == a
    )  # case, space
    assert key_for("hash_fields", code(), ("path", "title")) == a  # order does not matter


def test_tool_id_or_hash_uses_the_rule_when_there_is_one_and_the_fields_when_not() -> None:
    with_rule = code()
    no_rule = code()
    no_rule.evidence.rule_ids = {}
    assert key_for("tool_id_or_hash", with_rule) == key_for("tool_id", with_rule)
    fallback = key_for("tool_id_or_hash", no_rule, ("title",))
    assert fallback == key_for("hash_fields", no_rule, ("title",)) != key_for("tool_id", no_rule)


def test_keys_are_namespaced_and_cannot_collide_with_a_fingerprint() -> None:
    f = code()
    for strategy, fields in (("tool_id", ()), ("hash_fields", ("title",)), ("tool_id_or_hash", ())):
        assert is_namespaced(key_for(strategy, f, fields)) and key_for(
            strategy, f, fields
        ).startswith("dd1:")
    assert not is_namespaced(f.fingerprint) and f.fingerprint.startswith("sha256:")


def test_a_key_depends_only_on_the_finding_not_on_its_identity_or_run() -> None:
    a, b = code(), code()
    b.id, b.fingerprint = "different", "sha256:other"
    assert key_for("tool_id", a) == key_for("tool_id", b)
    assert key_for("hash_fields", a, ("title",)) == key_for("hash_fields", b, ("title",))


@pytest.mark.parametrize(
    "strategy,fields,message",
    [
        ("nope", (), "unknown strategy"),
        ("hash_fields", (), "needs at least one field"),
        ("hash_fields", ("title", "colour"), "unknown field"),
        ("tool_id", ("title",), "takes no fields"),
        ("package", ("title",), "takes no fields"),
    ],
)
def test_a_bad_setting_is_refused_with_the_reason(
    strategy: str, fields: tuple[str, ...], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        validate(strategy, fields)


def test_every_strategy_and_field_is_described_or_known() -> None:
    assert all(describe(s) for s in STRATEGIES) and "title" in FIELDS and "host" in FIELDS
    assert source_of(code(tool="bandit")) == "bandit"


@given(st.sampled_from(sorted(FIELDS)), st.integers(1, 5), st.text(min_size=1, max_size=20))
def test_a_hash_fields_key_is_deterministic_for_any_field_and_title(
    field: str, n: int, title: str
) -> None:
    f = code(title=title)
    chosen = (field,) * n  # duplicates are one field
    assert key_for("hash_fields", f, chosen) == key_for("hash_fields", f, chosen[:1])
