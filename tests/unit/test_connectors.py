"""Connectors (Week 60, plan §42.5, §55.7, ADR-0045). The remote APIs are a recorded fake here;
response bodies follow each vendor's documented examples (GitHub REST "List code scanning alerts for
a repository" and "List Dependabot alerts", GitLab GraphQL `Project.vulnerabilities`, DefectDojo API
v2 `/findings/`), and the GitLab query is checked against gitlab.com's published schema and a real
gitlab.com response recorded on 2026-10-05. What is tested is what Bulwark does with them: the
mapping, pagination that stays on its host, never applying a partial or suspicious pull, and health.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from core.connectors import defectdojo, github, gitlab, service
from core.connectors.http import ConnectorError, Response, check_url, next_link
from core.models import Category, Severity
from core.persistence.models import (
    AuditEntry,
    Connector,
    ConnectorRun,
    GithubInstallation,
    IssueRow,
)
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    SARIF,
    Env,
    env,  # noqa: F401  (the fixture)
)

GOLDEN = Path("tests/golden/connectors")
OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


class Fake:
    """A remote API: `routes` maps (method, url) to a Response, or a list served in order."""

    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> Response:
        self.calls.append((method, url, headers, body))
        hit = self.routes.get((method, url))
        if hit is None:
            return Response(404, {}, {"message": "Not Found"})
        if isinstance(hit, list):
            return hit.pop(0) if len(hit) > 1 else hit[0]
        return hit


def ok(body: Any, link: str | None = None) -> Response:
    return Response(200, {"link": link} if link else {}, body)


# --- GitHub ---------------------------------------------------------------------------------------


def cs_alert(
    n: int, path: str = "src/app.js", line: int = 10, level: str | None = "high"
) -> dict[str, Any]:
    return {
        "number": n, "state": "open", "html_url": f"https://github.com/acme/web/security/code-scanning/{n}",
        "rule": {"id": f"js/rule-{n}", "severity": "error", "description": f"Problem {n}",
                 "name": f"js/rule-{n}", "tags": ["security", "external/cwe/cwe-079"],
                 "security_severity_level": level},
        "tool": {"name": "CodeQL", "version": "2.19.0"},
        "most_recent_instance": {"ref": "refs/heads/main", "state": "open",
                                 "message": {"text": f"User input reaches sink {n}."},
                                 "location": {"path": path, "start_line": line, "end_line": line}},
    }  # fmt: skip


def dependabot_alert(n: int, name: str = "lodash", cve: str = "CVE-2021-23337") -> dict[str, Any]:
    return {
        "number": n, "state": "open", "html_url": f"https://github.com/acme/web/security/dependabot/{n}",
        "dependency": {"package": {"ecosystem": "npm", "name": name}, "manifest_path": "package-lock.json",
                       "scope": "runtime"},
        "security_advisory": {"ghsa_id": "GHSA-35jh-r3h4-6jhm", "cve_id": cve, "summary": "Command injection",
                              "description": "Templates allow code execution.", "severity": "high",
                              "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "score": 7.2},
                              "cwes": [{"cwe_id": "CWE-94", "name": "Code Injection"}],
                              "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]},
        "security_vulnerability": {"package": {"ecosystem": "npm", "name": name}, "severity": "high",
                                   "vulnerable_version_range": "< 4.17.21",
                                   "first_patched_version": {"identifier": "4.17.21"}},
    }  # fmt: skip


CS_URL = "https://api.github.com/repos/acme/web/code-scanning/alerts?state=open&per_page=100"
DB_URL = "https://api.github.com/repos/acme/web/dependabot/alerts?state=open&per_page=100"


def test_code_scanning_alerts_follow_link_pagination_and_map_like_sarif() -> None:
    page2 = (
        "https://api.github.com/repositories/1/code-scanning/alerts?state=open&per_page=100&page=2"
    )
    fake = Fake({
        ("GET", CS_URL): ok([cs_alert(1), cs_alert(2, level=None)], link=f'<{page2}>; rel="next", <{page2}>; rel="last"'),
        ("GET", page2): ok([cs_alert(3, path="")]),
    })  # fmt: skip
    got = github.fetch_code_scanning(fake, "tok", "acme/web")
    assert (got.items, got.requests, len(got.findings)) == (3, 2, 2)
    assert got.warnings == ["1 alert(s) had no location and were skipped"]
    first, second = got.findings
    assert first.evidence.reported_by == ["codeql"] and first.evidence.rule_ids == {
        "codeql": ["js/rule-1"]
    }
    assert first.taxonomy.cwe == ("CWE-79",) and first.scoring.normalized_severity is Severity.HIGH
    assert second.scoring.normalized_severity is Severity.HIGH  # rule severity "error", no level
    assert (first.location.path, first.location.start_line) == ("src/app.js", 10)
    assert fake.calls[0][2]["Authorization"] == "Bearer tok"


def test_pagination_to_another_host_is_refused() -> None:
    fake = Fake(
        {("GET", CS_URL): ok([cs_alert(1)], link='<https://evil.example/next>; rel="next"')}
    )
    with pytest.raises(ConnectorError, match="another host"):
        github.fetch_code_scanning(fake, "tok", "acme/web")


def test_dependabot_alerts_become_package_findings() -> None:
    got = github.fetch_dependabot(
        Fake({("GET", DB_URL): ok([dependabot_alert(1)])}), "tok", "acme/web"
    )
    (f,) = got.findings
    assert f.package is not None and (f.package.name, f.package.ecosystem) == ("lodash", "npm")
    assert f.taxonomy.category is Category.SCA and f.taxonomy.cve == ("CVE-2021-23337",)
    assert (
        f.scoring.cvss_v3_1 == 7.2
        and f.remediation.summary == "Upgrade lodash to 4.17.21 or later."
    )
    assert f.title == "CVE-2021-23337: Command injection"


def test_a_refused_credential_is_an_auth_error() -> None:
    with pytest.raises(ConnectorError) as caught:
        github.fetch_code_scanning(
            Fake({("GET", CS_URL): Response(403, {}, {})}), "tok", "acme/web"
        )
    assert caught.value.auth is True


def test_link_header_parsing() -> None:
    assert (
        next_link({"link": '<https://a/x?page=2>; rel="next", <https://a/x?page=9>; rel="last"'})
        == "https://a/x?page=2"
    )
    assert next_link({"link": '<https://a/x?page=9>; rel="last"'}) is None and next_link({}) is None


# --- GitLab ---------------------------------------------------------------------------------------

GL = "https://gitlab.example.com/api/graphql"


def gl_node(i: int, kind: str) -> dict[str, Any]:
    base = {"id": f"gid://gitlab/Vulnerability/{i}", "title": f"Vuln {i}", "description": "d",
            "solution": "Fix it", "severity": "HIGH", "state": "DETECTED",
            "webUrl": f"https://gitlab.example.com/g/p/-/security/vulnerabilities/{i}",
            "identifiers": [{"externalType": "cwe", "externalId": "89", "name": "CWE-89", "url": None}],
            "links": [], "scanner": {"name": "Semgrep", "vendor": "GitLab"}}  # fmt: skip
    if kind == "sast":
        return {
            **base,
            "reportType": "SAST",
            "location": {
                "__typename": "VulnerabilityLocationSast",
                "file": "app/db.py",
                "startLine": 12,
                "endLine": 12,
            },
        }
    if kind == "dep":
        return {
            **base,
            "reportType": "DEPENDENCY_SCANNING",
            "severity": "CRITICAL",
            "identifiers": [
                {
                    "externalType": "cve",
                    "externalId": "CVE-2022-42889",
                    "name": "CVE-2022-42889",
                    "url": None,
                }
            ],
            "location": {
                "__typename": "VulnerabilityLocationDependencyScanning",
                "file": "pom.xml",
                "dependency": {
                    "version": "1.9",
                    "package": {"name": "org.apache.commons/commons-text"},
                },
            },
        }
    if kind == "dast":
        return {
            **base,
            "reportType": "DAST",
            "severity": "MEDIUM",
            "location": {
                "__typename": "VulnerabilityLocationDast",
                "hostname": "https://shop.example",
                "path": "/search?q=1",
                "requestMethod": "GET",
                "param": "q",
            },
        }
    return {**base, "reportType": "SAST", "location": {"__typename": "VulnerabilityLocationGeneric"}}  # fmt: skip


def gl_page(nodes: list[dict[str, Any]], more: bool = False, cursor: str | None = None) -> Response:
    return ok({"data": {"project": {"id": "gid://gitlab/Project/1", "vulnerabilities": {
        "pageInfo": {"hasNextPage": more, "endCursor": cursor}, "nodes": nodes}}}})  # fmt: skip


def test_gitlab_pulls_every_page_and_reads_nodes_like_an_uploaded_report() -> None:
    fake = Fake({("POST", GL): [gl_page([gl_node(1, "sast"), gl_node(2, "dep")], True, "c1"),
                                gl_page([gl_node(3, "dast"), gl_node(4, "other")])]})  # fmt: skip
    got = gitlab.fetch(fake, "https://gitlab.example.com", "glpat-x", "g/p")
    assert (got.items, got.requests, len(got.findings)) == (4, 2, 3)
    sast, dep, dast = got.findings
    assert (sast.location.path, sast.location.start_line, sast.taxonomy.cwe) == (
        "app/db.py",
        12,
        ("CWE-89",),
    )
    assert dep.package is not None and dep.package.name == "org.apache.commons/commons-text"
    assert (
        dep.taxonomy.cve == ("CVE-2022-42889",)
        and dep.scoring.normalized_severity is Severity.CRITICAL
    )
    assert (dast.location.host, dast.location.route) == ("https://shop.example", "/search")
    second = json.loads(fake.calls[1][3] or b"{}")
    assert second["variables"] == {"fullPath": "g/p", "after": "c1", "first": 100}
    assert fake.calls[0][2]["Authorization"] == "Bearer glpat-x"


def test_gitlabs_real_answer_to_a_viewer_who_cannot_read_the_report_is_an_auth_error() -> None:
    real = json.loads((GOLDEN / "gitlab-anonymous-empty-page.json").read_text())["response"]
    fake = Fake({("POST", GL): ok(real)})
    with pytest.raises(ConnectorError, match="not allowed to see") as caught:
        gitlab.fetch(fake, "https://gitlab.example.com", "t", "gitlab-org/gitlab")
    assert caught.value.auth is True and len(fake.calls) == 1  # it did not page on


def test_gitlab_graphql_errors_and_a_missing_project_are_errors() -> None:
    errs = Fake({("POST", GL): ok({"errors": [{"message": "Field 'x' doesn't exist"}]})})
    with pytest.raises(ConnectorError, match="doesn't exist"):
        gitlab.fetch(errs, "https://gitlab.example.com", "t", "g/p")
    missing = Fake({("POST", GL): ok({"data": {"project": None}})})
    with pytest.raises(ConnectorError, match="not found"):
        gitlab.fetch(missing, "https://gitlab.example.com", "t", "g/p")


# The object type each selected object field returns, from gitlab.com's schema.
_GL_TYPES = {
    ("Query", "project"): "Project", ("Project", "vulnerabilities"): "VulnerabilityConnection",
    ("VulnerabilityConnection", "pageInfo"): "PageInfo",
    ("VulnerabilityConnection", "nodes"): "Vulnerability",
    ("Vulnerability", "identifiers"): "VulnerabilityIdentifier",
    ("Vulnerability", "links"): "VulnerabilityLink", ("Vulnerability", "scanner"): "VulnerabilityScanner",
    ("Vulnerability", "location"): "_union VulnerabilityLocation",
    ("VulnerabilityLocationDependencyScanning", "dependency"): "VulnerableDependency",
    ("VulnerabilityLocationContainerScanning", "dependency"): "VulnerableDependency",
    ("VulnerableDependency", "package"): "VulnerablePackage",
}  # fmt: skip


def _check_selection(tokens: list[str], i: int, owner: str, schema: dict[str, Any]) -> int:
    """Walk one `{ ... }` selection set starting after its `{`; assert each field exists on
    `owner`. Returns the index after the closing `}`."""
    while tokens[i] != "}":
        tok = tokens[i]
        if tok == "...":
            assert tokens[i + 1] == "on" and tokens[i + 3] == "{"
            fragment = tokens[i + 2]
            assert fragment in schema["_union VulnerabilityLocation"], fragment
            i = _check_selection(tokens, i + 4, fragment, schema)
            continue
        if tok != "__typename":
            assert tok in schema[owner], (owner, tok)
        i += 1
        if tokens[i] == "(":
            while tokens[i] != ")":
                i += 1
            i += 1
        if tokens[i] == "{":
            i = _check_selection(tokens, i + 1, _GL_TYPES[(owner, tok)], schema)
    return i + 1


def test_the_gitlab_query_only_uses_fields_gitlabs_schema_has() -> None:
    """Every field the query selects, on the type it is selected from, checked against the extract
    of gitlab.com's published schema (and the query itself ran against gitlab.com without a schema
    error on 2026-10-05: tests/golden/connectors/gitlab-anonymous-empty-page.json)."""
    schema = json.loads((GOLDEN / "gitlab-schema-extract.json").read_text())
    body = gitlab.QUERY[gitlab.QUERY.index("{") :]
    tokens = re.findall(r"\.\.\.|[A-Za-z_][A-Za-z0-9_]*|[{}()]", re.sub(r"\([^)]*\)", "()", body))
    assert tokens[0] == "{" and tokens[1] == "project"
    end = _check_selection(tokens, 1, "Query", {**schema, "Query": ["project"]})
    assert end == len(tokens)
    assert {"DETECTED", "CONFIRMED"} <= set(schema["_enum VulnerabilityState"])
    assert {"state", "first", "after"} <= set(schema["_args Project.vulnerabilities"])


# --- DefectDojo -----------------------------------------------------------------------------------

DD = "https://dojo.example.com"
DD_P1 = f"{DD}/api/v2/findings/?product=7&active=true&duplicate=false&limit=100&offset=0"
DD_P2 = f"{DD}/api/v2/findings/?product=7&active=true&duplicate=false&limit=100&offset=100"


def dd(i: int, **over: Any) -> dict[str, Any]:
    return {"id": i, "title": f"Finding {i}", "severity": "High", "description": "<p>d</p>",
            "mitigation": "Fix", "impact": "Bad", "references": "See https://example.com/a and more",
            "cwe": 89, "vulnerability_ids": [], "file_path": "app/x.py", "line": 7,
            "component_name": None, "component_version": None, "static_finding": True,
            "dynamic_finding": False, "cvssv3_score": None, **over}  # fmt: skip


def test_defectdojo_pull_follows_next_and_maps_kinds() -> None:
    fake = Fake({
        ("GET", DD_P1): ok({"count": 3, "next": DD_P2, "results": [dd(1), dd(2, component_name="log4j-core",
            component_version="2.14.1", vulnerability_ids=[{"vulnerability_id": "CVE-2021-44228"}])]}),
        ("GET", DD_P2): ok({"count": 3, "next": None, "results": [dd(3, file_path=None, static_finding=False,
            dynamic_finding=True, severity="Informational")]}),
    })  # fmt: skip
    got = defectdojo.fetch(fake, DD, "key", 7)
    assert (got.items, got.requests) == (3, 2)
    code, pkg, web = got.findings
    assert code.evidence.rule_ids == {"defectdojo": ["dd-1"]} and code.taxonomy.cwe == ("CWE-89",)
    assert code.remediation.references == ["https://example.com/a"] and code.description.startswith(
        "d"
    )
    assert pkg.package is not None and pkg.taxonomy.cve == ("CVE-2021-44228",)
    assert (
        web.taxonomy.category is Category.DAST and web.scoring.normalized_severity is Severity.INFO
    )
    assert fake.calls[0][2]["Authorization"] == "Token key"


def test_defectdojo_next_on_another_host_is_refused() -> None:
    fake = Fake(
        {
            ("GET", DD_P1): ok(
                {"next": "http://internal:8080/api/v2/findings/?offset=100", "results": [dd(1)]}
            )
        }
    )
    with pytest.raises(ConnectorError, match="another host"):
        defectdojo.fetch(fake, DD, "key", 7)


def test_defectdojo_push_imports_then_reimports_into_the_same_test() -> None:
    fake = Fake({("POST", f"{DD}/api/v2/import-scan/"): ok({"test": 42, "engagement": 3}),
                 ("POST", f"{DD}/api/v2/reimport-scan/"): ok({"test": 42})})  # fmt: skip
    sarif = defectdojo.sarif_for([], "acme/web")
    first = defectdojo.push(fake, DD, "key", sarif, test_id=None, engagement_id=3, product_name=None,
                            engagement_name=None)  # fmt: skip
    again = defectdojo.push(fake, DD, "key", sarif, test_id=first, engagement_id=3, product_name=None,
                            engagement_name=None)  # fmt: skip
    assert (first, again) == (42, 42)
    body = fake.calls[0][3] or b""
    assert b'name="scan_type"\r\n\r\nSARIF' in body and b'name="engagement"\r\n\r\n3' in body
    assert b'"version": "2.1.0"' in body and b'name="close_old_findings"\r\n\r\ntrue' in body
    assert fake.calls[1][1].endswith("/reimport-scan/") and b'name="test"\r\n\r\n42' in (
        fake.calls[1][3] or b""
    )


# --- the SSRF guard -------------------------------------------------------------------------------


def test_connector_urls_must_be_public_https() -> None:
    public = lambda host: ["93.184.216.34"]  # noqa: E731
    assert (
        check_url("https://dojo.example.com/", public, private_ok=False)
        == "https://dojo.example.com"
    )
    for bad, why in [("http://dojo.example.com", "https"), ("https://u:p@dojo.example.com", "credentials"),
                     ("https://169.254.169.254", "private"), ("https://10.0.0.5", "private")]:  # fmt: skip
        with pytest.raises(ConnectorError, match=why):
            check_url(bad, public, private_ok=False)
    with pytest.raises(ConnectorError, match="private"):
        check_url("https://dojo.internal", lambda h: ["192.168.1.9"], private_ok=False)
    assert check_url("http://localhost:8080", private_ok=True) == "http://localhost:8080"


# --- the service, over HTTP -----------------------------------------------------------------------

INSTALLATION = "777"


@pytest.fixture
def installed(env: Env) -> Env:
    with env.sessions() as s:
        s.add(GithubInstallation(id=INSTALLATION, account_login="acme", org_id=DEFAULT_ORG_ID))
        s.commit()
    return env


def add(env: Env, kind: str = "github_code_scanning", **over: Any) -> Any:
    config = {"repo": "acme/web", "installation_id": INSTALLATION}
    body = {
        "project_id": env.asset_id,
        "kind": kind,
        "name": "Web code scanning",
        "config": config,
        **over,
    }
    return env.client.post("/v2/connectors", json=body, headers=AUTH)


def use(monkeypatch: pytest.MonkeyPatch, fake: Fake) -> None:
    monkeypatch.setattr(service, "TRANSPORT", fake)
    monkeypatch.setattr(service, "GITHUB_TOKEN", lambda inst, settings: f"inst-token-{inst}")


def run(env: Env, cid: str) -> dict[str, Any]:
    r = env.client.post(f"/v2/connectors/{cid}/run", headers=AUTH)
    assert r.status_code == 202, r.text
    return r.json()  # type: ignore[no-any-return]


def issue_states(env: Env) -> list[str]:
    with env.sessions() as s:
        return sorted(i.state for i in s.scalars(select(IssueRow)))


def test_a_pull_is_a_reimport_unchanged_is_a_no_op_and_gone_is_closed(
    installed: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = installed
    fake = Fake({("GET", CS_URL): [ok([cs_alert(1), cs_alert(2, line=20)]), ok([cs_alert(1), cs_alert(2, line=20)]),
                                   ok([cs_alert(1)])]})  # fmt: skip
    use(monkeypatch, fake)
    c = add(env).json()
    assert (
        c["status"] == "never_run" and c["credential_store"] == "none" and c["direction"] == "pull"
    )
    one = run(env, c["id"])
    assert one["status"] == "ok" and one["last_items"] == 2
    assert (
        one["runs"][0]["counts"]["new"] == 2
        and fake.calls[0][2]["Authorization"] == "Bearer inst-token-777"
    )
    two = run(env, c["id"])
    assert two["runs"][0]["counts"]["duplicate"] is True
    three = run(env, c["id"])
    assert three["runs"][0]["counts"]["closed"] == 1
    assert issue_states(env) == ["fixed", "open"]  # seen again on the second pull: open


def test_an_empty_pull_after_a_full_one_closes_nothing_and_says_so(
    installed: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = installed
    use(monkeypatch, Fake({("GET", CS_URL): [ok([cs_alert(1), cs_alert(2, line=20)]), ok([])]}))
    c = add(env).json()
    run(env, c["id"])
    after = run(env, c["id"])
    assert after["status"] == "empty" and "Nothing was closed" in after["warning"]
    assert after["runs"][0]["outcome"] == "empty" and after["runs"][0]["import_id"] is None
    assert issue_states(env) == ["new", "new"]


def test_with_close_on_empty_an_empty_pull_does_close(
    installed: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = installed
    use(monkeypatch, Fake({("GET", CS_URL): [ok([cs_alert(1)]), ok([])]}))
    c = add(env, close_on_empty=True).json()
    run(env, c["id"])
    run(env, c["id"])
    assert issue_states(env) == ["fixed"]


def test_connected_but_fetched_nothing_from_the_start_is_flagged(
    installed: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = installed
    use(monkeypatch, Fake({("GET", CS_URL): ok([])}))
    c = run(env, add(env).json()["id"])
    assert c["status"] == "empty" and c["warning"].startswith("Connected, but fetched nothing.")


def test_a_failed_page_applies_nothing_and_backs_off(
    installed: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = installed
    page2 = "https://api.github.com/repositories/1/code-scanning/alerts?page=2"
    use(monkeypatch, Fake({("GET", CS_URL): ok([cs_alert(1)], link=f'<{page2}>; rel="next"'),
                           ("GET", page2): Response(502, {}, None)}))  # fmt: skip
    c = add(env).json()
    first = run(env, c["id"])
    assert first["status"] == "failing" and "HTTP 502" in first["last_error"]
    assert issue_states(env) == []  # page 1 was never applied on its own
    second = run(env, c["id"])
    assert second["consecutive_failures"] == 2
    with env.sessions() as s:
        row = s.get(Connector, c["id"])
        assert row is not None and row.next_run_at is not None and row.last_run_at is not None
        assert (row.next_run_at - row.last_run_at).total_seconds() == 360 * 60 * 2  # doubled


def test_a_credential_is_write_only_and_says_where_it_lives(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BULWARK_CONNECTOR_ALLOW_PRIVATE", "1")
    r = add(env, kind="defectdojo_import", name="Dojo",
            config={"base_url": "http://localhost:8080", "product_id": 7}, credential="dd-secret-key")  # fmt: skip
    assert r.status_code == 201, r.text
    body = r.json()
    assert "dd-secret-key" not in json.dumps(body)
    assert body["credential_store"] == "database" and "unencrypted" in body["warning"]
    listed = env.client.get("/v2/connectors", headers=AUTH).text
    assert "dd-secret-key" not in listed
    with env.sessions() as s:
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "connector.created")).one()
        assert entry.target == f"connector:{body['id']}"


def test_a_credential_goes_to_openbao_when_it_is_configured(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored: dict[str, str] = {}

    class Bao:
        def ensure_kv_engine_enabled(self) -> None: ...
        def put_secret(self, path: str, value: str) -> None:
            stored[path] = value

        def get_secret(self, path: str) -> str | None:
            return stored.get(path)

    monkeypatch.setattr(service, "_openbao", lambda settings: Bao())
    monkeypatch.setenv("BULWARK_CONNECTOR_ALLOW_PRIVATE", "1")
    body = add(env, kind="defectdojo_import", config={"base_url": "http://localhost:8080", "product_id": 7},
               credential="dd-secret-key").json()  # fmt: skip
    assert body["credential_store"] == "openbao" and body["warning"] is None
    assert stored == {f"bulwark/connectors/{DEFAULT_ORG_ID}/{body['id']}": "dd-secret-key"}
    with env.sessions() as s:
        row = s.get(Connector, body["id"])
        assert row is not None and row.credential is None


def test_config_is_validated_with_the_field_named(installed: Env) -> None:
    env = installed
    cases = [
        ({"kind": "nope"}, "kind"),
        ({"config": {"repo": "not a repo", "installation_id": INSTALLATION}}, "repo"),
        ({"config": {"repo": "acme/web", "installation_id": "999"}}, "installation_id"),
        ({"kind": "gitlab", "config": {"base_url": "https://169.254.169.254", "project": "g/p"},
          "credential": "x"}, "base_url"),
        ({"kind": "gitlab", "config": {"base_url": "https://gitlab.com", "project": "g/p"}}, "credential"),
        ({"kind": "defectdojo_export", "config": {"base_url": "https://example.com"},
          "credential": "x"}, "engagement_id"),
    ]  # fmt: skip
    for over, field in cases:
        r = add(env, **over)
        assert r.status_code == 422, (over, r.text)
        assert r.json()["detail"]["field"] == field, over


def test_another_orgs_installation_cannot_be_used(env: Env) -> None:
    with env.sessions() as s:
        s.add(GithubInstallation(id="888", account_login="theirs", org_id=OTHER_ORG))
        s.commit()
    r = add(env, config={"repo": "acme/web", "installation_id": "888"})
    assert r.status_code == 422 and r.json()["detail"]["field"] == "installation_id"


def test_another_org_cannot_see_change_or_run_a_connector(
    installed: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = installed
    use(monkeypatch, Fake({("GET", CS_URL): ok([])}))
    cid = add(env).json()["id"]
    assert env.client.get("/v2/connectors", headers=OTHER).json() == []
    assert env.client.get(f"/v2/connectors/{cid}", headers=OTHER).status_code == 404
    assert env.client.post(f"/v2/connectors/{cid}/run", headers=OTHER).status_code == 404
    assert (
        env.client.patch(
            f"/v2/connectors/{cid}", json={"enabled": False}, headers=OTHER
        ).status_code
        == 404
    )
    assert env.client.delete(f"/v2/connectors/{cid}", headers=OTHER).status_code == 404


def test_disable_enable_and_due(installed: Env) -> None:
    env = installed
    cid = add(env).json()["id"]
    off = env.client.patch(f"/v2/connectors/{cid}", json={"enabled": False}, headers=AUTH).json()
    assert off["status"] == "disabled"
    assert env.client.post(f"/v2/connectors/{cid}/run", headers=AUTH).status_code == 409
    with env.sessions() as s:
        assert service.due(s, DEFAULT_ORG_ID) == []
    env.client.patch(
        f"/v2/connectors/{cid}", json={"enabled": True, "interval_minutes": 1}, headers=AUTH
    )
    with env.sessions() as s:
        (c,) = service.due(s, DEFAULT_ORG_ID)
        assert c.id == cid and c.interval_minutes == service.MIN_INTERVAL  # clamped


def test_defectdojo_export_sends_open_issues_but_not_those_that_came_from_defectdojo(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BULWARK_CONNECTOR_ALLOW_PRIVATE", "1")
    assert env.import_and_get(SARIF)["status"] == "applied"  # 3 open Issues from Semgrep
    pulls = Fake({("GET", "http://localhost:8080/api/v2/findings/?product=7&active=true&duplicate=false"
                          "&limit=100&offset=0"): ok({"next": None, "results": [dd(1)]}),
                  ("POST", "http://localhost:8080/api/v2/import-scan/"): ok({"test": 5}),
                  ("POST", "http://localhost:8080/api/v2/reimport-scan/"): ok({"test": 5})})  # fmt: skip
    use(monkeypatch, pulls)
    imp = add(env, kind="defectdojo_import", name="From Dojo",
              config={"base_url": "http://localhost:8080", "product_id": 7}, credential="k").json()  # fmt: skip
    assert run(env, imp["id"])["last_items"] == 1
    exp = add(env, kind="defectdojo_export", name="To Dojo",
              config={"base_url": "http://localhost:8080", "engagement_id": 3}, credential="k").json()  # fmt: skip
    first = run(env, exp["id"])
    assert first["status"] == "ok" and first["runs"][0]["counts"] == {
        "exported": 3,
        "defectdojo_test_id": 5,
    }
    sarif_body = pulls.calls[1][3] or b""
    start = sarif_body.index(b'{"$schema"')
    doc = json.loads(sarif_body[start : sarif_body.index(b"\r\n--", start)])
    sources = {r["properties"]["reported_by"][0] for r in doc["runs"][0]["results"]}
    assert len(doc["runs"][0]["results"]) == 3 and "defectdojo" not in sources
    run(env, exp["id"])
    assert pulls.calls[2][1].endswith("/reimport-scan/")  # the same DefectDojo Test after that


def test_kinds_say_what_each_needs() -> None:
    assert service.KINDS["github_dependabot"].needs_credential is False
    assert "read_api" in service.KINDS["gitlab"].permissions
    assert {k.direction for k in service.KINDS.values()} == {"pull", "push"}


def test_run_history_is_kept(installed: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env = installed
    use(monkeypatch, Fake({("GET", CS_URL): ok([cs_alert(1)])}))
    cid = add(env).json()["id"]
    run(env, cid)
    run(env, cid)
    detail = env.client.get(f"/v2/connectors/{cid}", headers=AUTH).json()
    assert [r["outcome"] for r in detail["runs"]] == ["ok", "ok"]
    with env.sessions() as s:
        assert len(list(s.scalars(select(ConnectorRun)))) == 2
