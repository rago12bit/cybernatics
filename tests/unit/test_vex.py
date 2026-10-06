"""VEX (plan §46.3, §55.5): what the code uses, read from Go source; drafts only where there is
evidence; a person confirms each one, with a personal token; confirming dismisses the Issue with
the justification, reopening the Issue withdraws the statement; OpenVEX and CycloneDX exports; a
dependency Issue triaged with a justification; nothing of another organization. The advisory
records are the real ones in tests/fixtures/osv (GO-2021-0238 names golang.org/x/net/html.Parse)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from core import inventory
from core.persistence import repo
from core.persistence.models import IssueRow, VexStatement
from core.reachability import analyze
from core.reachability.golang import GoUsage, candidates, read_go_mod, scan_file, symbol_use
from core.tenancy import DEFAULT_ORG_ID
from core.vex import vocab
from core.vex.evidence import record_usage
from tests.unit.test_advisories import OTHER, load_all, project
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_pipeline import make_scan
from tests.unit.test_risk_acceptance import token

X_NET = "pkg:golang/golang.org/x/net@v0.0.0-20210428140749-89ef3d95e781"
PARAMIKO = "pkg:pypi/paramiko@2.0.0"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

CALLS_PARSE = b"""package main
import (
  "fmt"
  "golang.org/x/net/html"
)
func handler(body string) { doc, _ := html.Parse(strings.NewReader(body)); fmt.Println(doc) }
"""
TOKENIZER_ONLY = b"""package main
import h "golang.org/x/net/html"
func main() { z := h.NewTokenizer(nil); for z.Next() != h.ErrorToken {} }
"""


# ------------------------------------------------------------------ reading Go


def test_go_source_says_which_names_of_each_package_are_used(tmp_path: Path) -> None:
    f = scan_file(b"""package main
import (
  "fmt"
  h "golang.org/x/net/html"
  . "strings"
  _ "embed"
  "gopkg.in/yaml.v3"
  "github.com/mattn/go-sqlite3"
  "github.com/acme/weird"
)
func main() {
  z := h.NewTokenizer(nil); z.Next(); fmt.Println(ToUpper("x"))
  yaml.Unmarshal(nil, nil); f := h.Parse; _ = f; sqlite3.Version()
  var n h.Node; _ = n
}
""")
    assert f.parsed and f.imports["golang.org/x/net/html"] == "h"
    assert set(f.refs["golang.org/x/net/html"]) == {"NewTokenizer", "Parse", "Node"}
    assert "Next" in f.selectors and "Next" not in f.refs["golang.org/x/net/html"]
    assert set(f.refs["gopkg.in/yaml.v3"]) == {"Unmarshal"}  # bound to yaml, from yaml.v3
    assert set(f.refs["github.com/mattn/go-sqlite3"]) == {"Version"}  # go-sqlite3 -> sqlite3
    assert "ToUpper" in f.refs["strings"]  # a dot import: bare calls count
    # Go rejects an unused import, so an import none of whose possible names is used is bound to
    # a name the path does not tell: unknown, and nothing is claimed about it.
    assert f.unknown == {"github.com/acme/weird"}
    assert "yaml" in candidates("gopkg.in/yaml.v3")
    assert "v2" not in candidates("github.com/x/y/v2") and "y" in candidates("github.com/x/y/v2")

    module, direct, indirect = read_go_mod(
        'module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.1.0\n'
        '\tgithub.com/x/y v1.0.0 // indirect\n)\nrequire gopkg.in/yaml.v3 v3.0.1\n'
    )  # fmt: skip
    assert (module, direct, indirect) == (
        "example.com/app",
        {"golang.org/x/net", "gopkg.in/yaml.v3"},
        {"github.com/x/y"},
    )

    u = GoUsage()
    u.add("main.go", f, test=False)
    assert symbol_use(u, "golang.org/x/net/html", ["Parse", "ParseFragment"]).used is True
    assert symbol_use(u, "golang.org/x/net/html", ["ParseFragment"]).used is False
    assert symbol_use(u, "golang.org/x/net/html", ["Tokenizer.Next"]).used is True  # a method
    assert symbol_use(u, "golang.org/x/net/html", []).used is True  # the whole package
    assert symbol_use(u, "golang.org/x/text/language", []).used is False
    assert symbol_use(u, "github.com/acme/weird", ["Do"]).used is None

    (tmp_path / "go.mod").write_text("module example.com/app\nrequire golang.org/x/net v0.1.0\n")
    (tmp_path / "main.go").write_bytes(TOKENIZER_ONLY)
    (tmp_path / "x_test.go").write_bytes(b'package main\nimport "github.com/stretchr/testify/assert"\nfunc T() { assert.True(nil, true) }\n')  # fmt: skip
    from core.models import Package

    idx = analyze(tmp_path)
    assert idx.go.files == 2 and idx.go.module == "example.com/app"
    assert idx.assess_package(Package("golang.org/x/net", "v0.1.0", "go")).reachable is True
    test_only = idx.assess_package(Package("github.com/stretchr/testify", "v1", "go"))
    assert test_only.reachable is False and "test code" in test_only.reason
    assert idx.assess_package(Package("github.com/other/mod", "v1", "go")).reachable is None


# ------------------------------------------------------------------ drafting and deciding


def _sbom(s, asset_id: str, purl: str, reachable: bool | None, reason: str = "") -> None:  # type: ignore[no-untyped-def]
    sid = make_scan(s, [], "x")
    scan = repo.get_scan(s, sid)
    assert scan is not None
    scan.asset_id = asset_id
    s.commit()
    inventory.record(
        s, org_id=DEFAULT_ORG_ID, asset_id=asset_id, scan_id=sid, source="scan",
        packages=[{"purl": purl, "path": "go.mod", "reachable": reachable,
                   "reachable_reason": reason}],
    )  # fmt: skip


def _go(s, asset_id: str, source: bytes) -> None:  # type: ignore[no-untyped-def]
    u = GoUsage(module="example.com/app", direct={"golang.org/x/net"})
    u.add("main.go", scan_file(source), test=False)
    record_usage(s, org_id=DEFAULT_ORG_ID, asset_id=asset_id, scan_id="scan-1", go=u)


def seed(env: Env) -> dict[str, str]:
    with env.sessions() as s:
        load_all(s)
        ids = {n: project(s, n) for n in ("calls-parse", "tokenizer-only", "never-scanned", "py-unused", "java")}  # fmt: skip
        _sbom(s, ids["calls-parse"], X_NET, True, "Imported by application code (main.go)")
        _go(s, ids["calls-parse"], CALLS_PARSE)
        _sbom(s, ids["tokenizer-only"], X_NET, True, "Imported by application code (main.go)")
        _go(s, ids["tokenizer-only"], TOKENIZER_ONLY)
        _sbom(s, ids["never-scanned"], X_NET, None)  # an imported SBOM: no code was read
        _sbom(s, ids["py-unused"], PARAMIKO, False,
              "No source file of the application imports it (another dependency may still load it)")  # fmt: skip
        _sbom(s, ids["java"], LOG4J, None, "Reachability is not analysed for maven packages")
    return ids


def test_drafts_only_where_there_is_evidence_and_a_person_decides(env: Env) -> None:
    ids = seed(env)
    view = env.client.get("/v2/advisories/CVE-2021-33194", headers=AUTH).json()
    by = {u["project"]: u["vex"] for u in view["uses"]}
    assert by["calls-parse"]["draftable"] is False and by["calls-parse"]["uses_code"] is True
    assert "html.Parse" in by["calls-parse"]["summary"] and "main.go:6" in by["calls-parse"]["where"]  # fmt: skip
    assert by["tokenizer-only"]["draftable"] is True
    assert by["tokenizer-only"]["evidence"]["kind"] == "symbols"
    assert "does not call Parse, ParseFragment" in by["tokenizer-only"]["summary"]
    assert by["never-scanned"]["draftable"] is False and "not scanned" in by["never-scanned"]["summary"]  # fmt: skip
    assert view["summary_counts"]["vex_draftable"] == 1

    out = env.client.post("/v2/advisories/CVE-2021-33194/vex-drafts", headers=AUTH)
    assert out.status_code == 200, out.text
    assert out.json()["proposed"] == 1 and sum(out.json()["skipped"].values()) == 2
    [sid] = out.json()["ids"]
    again = env.client.post("/v2/advisories/CVE-2021-33194/vex-drafts", headers=AUTH).json()
    assert again["proposed"] == 0 and again["already"] == 1  # no second proposal

    # Import-level evidence for Python; nothing for Maven, whose code use is not analysed.
    py = env.client.post("/v2/advisories/CVE-2018-7750/vex-drafts", headers=AUTH).json()
    assert py["proposed"] == 1
    with env.sessions() as s:
        st = s.get(VexStatement, py["ids"][0])
        assert st is not None and st.evidence["kind"] == "imports" and st.state == "proposed"
    java = env.client.post("/v2/advisories/CVE-2021-44228/vex-drafts", headers=AUTH).json()
    assert java["proposed"] == 0

    # A proposal is exported nowhere until confirmed.
    vexdoc = env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex/openvex", headers=AUTH).json()  # fmt: skip
    assert [st["status"] for st in vexdoc["statements"]] == ["affected"]

    # Deciding needs a person: the shared token could be anyone; another org sees nothing.
    shared = env.client.post(f"/v2/vex/{sid}/confirm", json={}, headers=AUTH)
    assert shared.status_code == 403 and "personal" in shared.json()["detail"]
    assert env.client.post(f"/v2/vex/{sid}/confirm", json={}, headers=OTHER).status_code == 404
    reader = token(env, "Reader", ["scans:read"])
    assert env.client.post(f"/v2/vex/{sid}/confirm", json={}, headers=reader).status_code == 403
    meera = token(env, "Meera")
    ok = env.client.post(f"/v2/vex/{sid}/confirm", json={"note": "reviewed main.go"}, headers=meera)  # fmt: skip
    assert ok.status_code == 200 and ok.json()["state"] == "confirmed"
    assert env.client.post(f"/v2/vex/{sid}/confirm", json={}, headers=meera).status_code == 409


def test_confirming_dismisses_the_issue_and_reopening_it_withdraws_the_claim(env: Env) -> None:
    ids = seed(env)
    created = env.client.post("/v2/advisories/CVE-2021-33194/issues", json={}, headers=AUTH).json()
    [issue_id] = created["issue_ids"][ids["tokenizer-only"]]
    [sid] = env.client.post("/v2/advisories/CVE-2021-33194/vex-drafts", headers=AUTH).json()["ids"]
    meera = token(env, "Meera")
    assert env.client.post(f"/v2/vex/{sid}/confirm", json={}, headers=meera).status_code == 200
    with env.sessions() as s:
        issue = s.get(IssueRow, issue_id)
        assert issue is not None and issue.triage_status == "not_a_risk"
        assert issue.triage_justification == "vulnerable_code_not_in_execute_path"
        assert issue.triage_reason and issue.triage_reason.startswith("VEX: Application code does not call")  # fmt: skip

    doc = env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex/openvex", headers=AUTH)
    assert doc.status_code == 200 and "attachment" in doc.headers["content-disposition"]
    ov = doc.json()
    assert ov["@context"] == "https://openvex.dev/ns/v0.2.0" and ov["@id"].startswith("urn:uuid:")
    [st] = ov["statements"]
    assert st["status"] == "not_affected"
    assert st["justification"] == "vulnerable_code_not_in_execute_path"
    assert st["vulnerability"]["name"] == "CVE-2021-33194"
    assert "GO-2021-0238" in st["vulnerability"]["aliases"]
    assert st["products"][0]["@id"] == "https://tokenizer-only" or st["products"][0]["@id"].startswith("urn:uuid:")  # fmt: skip
    assert st["products"][0]["subcomponents"][0]["@id"] == X_NET
    assert "does not call" in st["impact_statement"] and "Limits:" in st["impact_statement"]
    assert "Confirmed by token:" in st["impact_statement"]

    cdx = env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex/cyclonedx", headers=AUTH).json()  # fmt: skip
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6"
    [v] = cdx["vulnerabilities"]
    assert v["analysis"]["state"] == "not_affected"
    assert v["analysis"]["justification"] == "code_not_reachable"
    assert v["affects"] == [{"ref": X_NET, "versions": [{"version": "v0.0.0-20210428140749-89ef3d95e781", "status": "unaffected"}]}]  # fmt: skip
    props = {p["name"]: p["value"] for p in v["properties"]}
    assert props["bulwark:openvex:justification"] == "vulnerable_code_not_in_execute_path"
    assert json.loads(props["bulwark:evidence"])["kind"] == "symbols"
    assert cdx["components"][0]["purl"] == X_NET

    # The project that calls Parse exports "affected", with the fix.
    other = env.client.get(f"/v2/projects/{ids['calls-parse']}/vex/openvex", headers=AUTH).json()
    assert other["statements"][0]["status"] == "affected"
    assert "Upgrade golang.org/x/net to" in other["statements"][0]["action_statement"]

    # A person reopens the Issue: the claim is withdrawn and the export says affected again.
    r = env.client.post(f"/assets/{ids['tokenizer-only']}/issues/{issue_id}/triage",
                        json={"action": "reopen"}, headers=meera)  # fmt: skip
    assert r.status_code == 200 and r.json()["triage_justification"] is None
    with env.sessions() as s:
        assert s.get(VexStatement, sid).state == "withdrawn"  # type: ignore[union-attr]
    again = env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex/openvex", headers=AUTH).json()  # fmt: skip
    assert again["statements"][0]["status"] == "affected"
    listed = env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex", headers=AUTH).json()
    assert listed["counts"] == {"affected": 1} and listed["statements"][0]["state"] == "withdrawn"
    assert env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex", headers=OTHER).status_code == 404  # fmt: skip

    # When a later scan finds the code calling it, a confirmed claim is not exported as true.
    [sid2] = env.client.post("/v2/advisories/CVE-2021-33194/vex-drafts", headers=AUTH).json()["ids"]
    assert env.client.post(f"/v2/vex/{sid2}/confirm", json={}, headers=meera).status_code == 200
    with env.sessions() as s:
        _go(s, ids["tokenizer-only"], CALLS_PARSE)
    stale = env.client.get(f"/v2/projects/{ids['tokenizer-only']}/vex/openvex", headers=AUTH).json()  # fmt: skip
    assert stale["statements"][0]["status"] == "under_investigation"
    assert "no longer matches" in stale["statements"][0]["status_notes"]


def test_a_dependency_issue_is_dismissed_in_vex_vocabulary(env: Env) -> None:
    ids = seed(env)
    created = env.client.post("/v2/advisories/CVE-2021-44228/issues", json={}, headers=AUTH).json()
    [issue_id] = created["issue_ids"][ids["java"]]
    url = f"/assets/{ids['java']}/issues/{issue_id}/triage"
    bad = env.client.post(url, json={"action": "not_a_risk", "reason": "x", "justification": "nope"}, headers=AUTH)  # fmt: skip
    assert bad.status_code == 422
    wrong = env.client.post(url, json={"action": "reopen", "justification": "component_not_present"}, headers=AUTH)  # fmt: skip
    assert wrong.status_code == 422
    r = env.client.post(url, json={"action": "not_a_risk", "reason": "JndiLookup class removed at build",
                                   "justification": "vulnerable_code_not_present"}, headers=AUTH)  # fmt: skip
    assert (
        r.status_code == 200 and r.json()["triage_justification"] == "vulnerable_code_not_present"
    )
    doc = env.client.get(f"/v2/projects/{ids['java']}/vex/openvex", headers=AUTH).json()
    [st] = doc["statements"]
    assert (st["status"], st["justification"]) == ("not_affected", "vulnerable_code_not_present")
    assert st["impact_statement"] == "JndiLookup class removed at build"
    cdx = env.client.get(f"/v2/projects/{ids['java']}/vex/cyclonedx", headers=AUTH).json()
    v = cdx["vulnerabilities"][0]
    assert v["analysis"]["justification"] == "code_not_present"
    assert cdx["components"][0]["group"] == "org.apache.logging.log4j"
    assert cdx["components"][0]["name"] == "log4j-core"

    # Justifications are for dependency Issues only.
    with env.sessions() as s:
        sast = IssueRow(asset_id=ids["java"], fingerprint="sha256:x", state="open", category="sast",
                        severity="HIGH", path="a.py", title="t")  # fmt: skip
        s.add(sast)
        s.commit()
        sast_id = sast.id
    r = env.client.post(f"/assets/{ids['java']}/issues/{sast_id}/triage",
                        json={"action": "not_a_risk", "reason": "x",
                              "justification": "component_not_present"}, headers=AUTH)  # fmt: skip
    assert r.status_code == 422 and "dependency" in r.json()["detail"]

    assert set(vocab.CDX_JUSTIFICATION) == set(vocab.JUSTIFICATIONS)


def test_a_full_scan_records_what_its_go_code_uses(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """The scan pipeline keeps the Go code's usage (the evidence a VEX draft cites) and the Go
    components' reachability, from the real source tree."""
    from core.events import MemoryPublisher
    from core.persistence.models import CodeUsage, ComponentRow
    from core.persistence.storage import MemoryStore
    from core.pipeline import run_scan_job
    from core.scan import ToolOutcome
    from tests.unit.test_inventory import bom
    from tests.unit.test_pipeline import executor_from

    (sample_repo / "go.mod").write_text(
        "module example.com/gw\nrequire (\n\tgolang.org/x/net v0.0.0-20210428140749-89ef3d95e781\n"
        "\tgithub.com/x/unused v1.0.0\n)\n"
    )
    (sample_repo / "main.go").write_bytes(TOKENIZER_ONLY)
    with sessions() as s:
        sid = make_scan(s, ["syft"], str(sample_repo))
    sbom = bom(("pkg:golang/golang.org/x/net", "v0.0.0-20210428140749-89ef3d95e781"),
               ("pkg:golang/github.com/x/unused", "v1.0.0"))  # fmt: skip
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(),
                 executor_from({"syft": ToolOutcome("syft", "ok", [], raw=sbom)}))  # fmt: skip
    with sessions() as s:
        usage = s.scalars(select(CodeUsage)).one()
        assert usage.scan_id == sid and usage.data["go"]["module"] == "example.com/gw"
        assert set(usage.data["go"]["refs"]["golang.org/x/net/html"]) == {
            "NewTokenizer",
            "ErrorToken",
        }
        assert "Next" in usage.data["go"]["selectors"]
        reach = {c.purl.split("@")[0]: (c.reachable, c.reachable_reason) for c in s.scalars(select(ComponentRow))}  # fmt: skip
        assert reach["pkg:golang/golang.org/x/net"][0] is True
        assert reach["pkg:golang/github.com/x/unused"][0] is False  # declared, never imported
