from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cli.main import app
from core.adapters.checkov import CheckovAdapter
from core.adapters.dockle import IMAGE_ARCHIVE, DockleAdapter
from core.adapters.gosec import GosecAdapter
from core.adapters.grype import GrypeAdapter
from core.adapters.helpers import JsonAdapter, make_finding
from core.models import Category
from core.runner import build_docker_argv
from core.scan import ADAPTERS, DEFAULT_TOOLS, detect_context

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "golden"
TIER2 = ("grype", "checkov", "gosec", "dockle")
runner = CliRunner()


# ---- registry -----------------------------------------------------------------------------------


def test_tier_two_tools_are_registered_but_not_run_by_default() -> None:
    assert set(TIER2) <= set(ADAPTERS) and not set(TIER2) & set(DEFAULT_TOOLS)
    assert set(DEFAULT_TOOLS) <= set(ADAPTERS)


def test_every_image_is_pinned_and_has_a_dockerfile() -> None:
    for name, adapter in ADAPTERS.items():
        if name in ("gitleaks",):
            continue  # upstream image, pinned by tag in its spec
        image = adapter.spec.image
        assert re.fullmatch(r"bulwark/[a-z-]+:\d+\.\d+\.\d+", image), image
        assert (ROOT / "docker" / name).is_dir() or name == "osv-scanner", name


def test_dockerfile_versions_match_the_adapters() -> None:
    expect = {"grype": "v0.119.0", "gosec": "v2.29.0", "checkov": "3.3.19", "dockle": "v0.4.15"}
    for tool, ver in expect.items():
        # grype is built from its release (THREAT-MODEL T10): `ARG GRYPE_VERSION=0.119.0`
        assert ver.lstrip("v") in (ROOT / "docker" / tool / "Dockerfile").read_text(), tool
        assert ver.lstrip("v") in ADAPTERS[tool].spec.image


def test_scanners_built_from_releases_build_the_version_their_adapter_runs() -> None:
    """Dependabot cannot bump these (release files or Go source, not images), so a version is changed
    by hand: the Dockerfile's ARG and the image tag the adapter runs must move together."""
    from core.dast.adapters.nuclei import NUCLEI_IMAGE
    from core.sbom.syft import SYFT_IMAGE

    for tool, arg, image in [
        ("grype", "GRYPE_VERSION", ADAPTERS["grype"].spec.image),
        ("osv-scanner", "OSV_VERSION", ADAPTERS["osv-scanner"].spec.image),
        ("syft", "SYFT_VERSION", SYFT_IMAGE),
        ("checkov", "CHECKOV_VERSION", ADAPTERS["checkov"].spec.image),
        ("gitleaks", "GITLEAKS_VERSION", ADAPTERS["gitleaks"].spec.image),
        ("dockle", "DOCKLE_VERSION", ADAPTERS["dockle"].spec.image),
        ("nuclei", "NUCLEI_VERSION", NUCLEI_IMAGE),
    ]:
        text = (ROOT / "docker" / tool / "Dockerfile").read_text()
        versions = set(re.findall(rf"(?m)^ARG {arg}=(\S+)$", text))
        assert versions == {image.rsplit(":", 1)[1].lstrip("v")}, (tool, versions, image)


# ---- the "about forty lines" claim, as a guard --------------------------------------------------


def _code_lines(path: Path) -> int:
    src = path.read_text()
    doc: set[int] = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body:
            e = n.body[0]
            if (
                isinstance(e, ast.Expr)
                and isinstance(getattr(e, "value", None), ast.Constant)
                and isinstance(e.value.value, str)
            ):
                doc.update(range(e.lineno, (e.end_lineno or e.lineno) + 1))
    return sum(
        1
        for i, ln in enumerate(src.splitlines(), 1)
        if ln.strip() and not ln.strip().startswith("#") and i not in doc
    )


@pytest.mark.parametrize("tool", TIER2)
def test_a_new_scanner_stays_small(tool: str) -> None:
    n = _code_lines(ROOT / "core" / "adapters" / f"{tool}.py")
    assert n <= 50, f"{tool}.py is {n} code lines; move what repeats into core/adapters/helpers.py"


# ---- parsing details ----------------------------------------------------------------------------


def test_gosec_reads_line_ranges_cwe_and_the_flagged_line_of_code() -> None:
    issue = {"severity": "HIGH", "confidence": "MEDIUM", "cwe": {"id": "89", "url": "https://cwe.mitre.org/data/definitions/89.html"},
             "rule_id": "G202", "details": "SQL string concatenation", "file": "/target/db/q.go",
             "code": "9: a\n10: b := \"x\" + y\n11: c\n", "line": "10-11", "column": "3"}  # fmt: skip
    [f] = GosecAdapter().parse(json.dumps({"Issues": [issue]}).encode())
    assert (f.location.path, f.location.start_line, f.location.end_line) == ("db/q.go", 10, 11)
    assert (
        f.location.snippet == 'b := "x" + y'
        and f.taxonomy.cwe == ("CWE-89",)
        and f.scoring.confidence == 0.6
    )
    assert f.scoring.normalized_severity.value == "HIGH"


def test_gosec_with_no_issues_is_a_clean_pass_not_an_error() -> None:
    assert GosecAdapter().parse(b'{"Issues": null, "Golang errors": {}}') == []


def test_checkov_accepts_one_report_or_a_list_of_them_and_defaults_severity() -> None:
    check = {"check_id": "CKV_X_1", "check_name": "Something", "file_path": "/main.tf", "file_line_range": [4, 9],
             "resource": "aws_s3_bucket.b", "severity": None, "guideline": "https://docs.example/x", "description": None}  # fmt: skip
    one = {"results": {"failed_checks": [check]}}
    for doc in (one, [one, {"results": {"failed_checks": [check]}}]):
        fs = CheckovAdapter().parse(json.dumps(doc).encode())
        assert len(fs) == (1 if doc is one else 2)
        f = fs[0]
        assert f.location.path == "main.tf" and (f.location.start_line, f.location.end_line) == (
            4,
            9,
        )
        assert (
            f.scoring.normalized_severity.value == "MEDIUM" and f.taxonomy.category is Category.IAC
        )
        assert f.remediation.references == ["https://docs.example/x"]


def test_dockle_drops_passes_and_skips_and_maps_levels() -> None:
    doc = {"details": [{"code": "CIS-DI-0001", "title": "Create a user", "level": "WARN", "alerts": ["root"]},
                       {"code": "CIS-DI-0002", "title": "x", "level": "FATAL", "alerts": []},
                       {"code": "CIS-DI-0003", "title": "y", "level": "PASS", "alerts": []},
                       {"code": "CIS-DI-0004", "title": "z", "level": "SKIP", "alerts": []},
                       {"code": "CIS-DI-0005", "title": "w", "level": "INFO", "alerts": ["a", "b"]}]}  # fmt: skip
    fs = DockleAdapter().parse(json.dumps(doc).encode())
    assert [(f.evidence.rule_ids["dockle"][0], f.scoring.normalized_severity.value) for f in fs] == [
        ("CIS-DI-0001", "MEDIUM"), ("CIS-DI-0002", "HIGH"), ("CIS-DI-0005", "LOW")]  # fmt: skip
    assert fs[2].description == "w: a; b" and fs[0].taxonomy.category is Category.CONTAINER


def test_grype_merges_related_ids_picks_the_v3_score_and_normalizes_the_ecosystem() -> None:
    m = {"vulnerability": {"id": "GHSA-aaaa", "severity": "High", "description": "d", "dataSource": "https://x",
                           "cvss": [{"version": "2.0", "metrics": {"baseScore": 9.9}}, {"version": "3.1", "metrics": {"baseScore": 7.2}}],
                           "cwes": [{"cwe": "CWE-94"}, {"cwe": "CWE-94"}], "fix": {"versions": ["1.2.3"]}},
         "relatedVulnerabilities": [{"id": "CVE-2021-1"}],
         "artifact": {"name": "lodash", "version": "1.0.0", "purl": "pkg:golang/lodash@1.0.0", "locations": [{"path": "/go.sum"}]}}  # fmt: skip
    [f] = GrypeAdapter().parse(json.dumps({"matches": [m]}).encode())
    assert f.taxonomy.aliases == ("GHSA-aaaa", "CVE-2021-1") and f.taxonomy.cve == ("CVE-2021-1",)
    assert f.scoring.cvss_v3_1 == 7.2 and f.taxonomy.cwe == (
        "CWE-94",
    )  # the 2.0 score is ignored, cwes deduplicated
    assert f.package is not None and f.package.ecosystem == "go"
    assert (
        f.location.path == "go.sum" and f.remediation.summary == "Upgrade lodash to 1.2.3 or later."
    )


def test_one_bad_record_does_not_lose_the_rest() -> None:
    good = {"severity": "LOW", "rule_id": "G1", "details": "d", "file": "/target/a.go", "line": "1"}
    fs = GosecAdapter().parse(json.dumps({"Issues": [{"bogus": 1}, good, {"line": "x"}]}).encode())
    assert [f.evidence.rule_ids["gosec"][0] for f in fs] == ["G1"]


def test_make_finding_builds_the_canonical_shape() -> None:
    f = make_finding("gosec", Category.SAST, rule="G1", title="t" * 400, path="a.go", start=3, native="high",
                     cwe=["CWE-1", "CWE-1"], refs=[None, "https://r"], snippet="x")  # fmt: skip
    assert f.id == "gosec:G1:a.go:3" and len(f.title) == 300 and f.location.end_line == 3
    assert f.taxonomy.cwe == ("CWE-1",) and f.remediation.references == ["https://r"]
    assert f.scoring.native_severity == {"gosec": "HIGH"} and f.location.snippet_hash.startswith(
        "sha256:"
    )
    assert f.evidence.reported_by == ["gosec"]


def test_json_adapter_base_never_raises() -> None:
    class Broken(JsonAdapter):
        spec = GosecAdapter.spec

        def build_command(self, *a: Any, **k: Any) -> list[str]:
            return []

        def records(self, doc: Any) -> list[dict[str, Any]]:
            return doc["items"]

        def to_finding(self, rec: dict[str, Any]):  # type: ignore[no-untyped-def]
            raise RuntimeError(
                "not a recognised failure"
            )  # a genuine bug must surface, not be swallowed

    assert Broken().parse(b"nope") == [] and Broken().parse(b'{"items": []}') == []
    with pytest.raises(RuntimeError):
        Broken().parse(b'{"items": [{}]}')


# ---- how the runner and detection treat them ----------------------------------------------------


def test_runner_reads_the_tools_own_output_name_and_sizes_tmp_per_tool() -> None:
    argv = build_docker_argv(ADAPTERS["checkov"], Path("/t"), Path("/o"), "n")
    assert "/out" in " ".join(argv) and any(
        a.startswith("--output-file-path") or a == "/out" for a in argv
    )
    assert (
        ADAPTERS["checkov"].spec.output_name == "results_json.json"
        and ADAPTERS["bandit"].spec.output_name == "result.json"
    )
    assert any(
        a.endswith("size=512m")
        for a in build_docker_argv(ADAPTERS["gosec"], Path("/t"), Path("/o"), "n")
    )
    assert any(
        a.endswith("size=64m")
        for a in build_docker_argv(ADAPTERS["bandit"], Path("/t"), Path("/o"), "n")
    )


def test_only_the_named_image_archive_triggers_dockle(tmp_path: Path) -> None:
    (tmp_path / "some.tar").write_bytes(b"x")
    ctx = detect_context(tmp_path)
    assert not ctx.has_image_archive and not ADAPTERS["dockle"].applies_to(ctx)
    (tmp_path / IMAGE_ARCHIVE).write_bytes(b"x")
    ctx = detect_context(tmp_path)
    assert ctx.has_image_archive and ADAPTERS["dockle"].applies_to(ctx)
    # Only the secret scanner looks at every file; nothing language- or lockfile-based runs on an archive.
    assert {t for t in DEFAULT_TOOLS if ADAPTERS[t].applies_to(ctx)} <= {"gitleaks"}


def test_grype_and_checkov_and_gosec_apply_to_their_own_repositories(tmp_path: Path) -> None:
    ctx = detect_context(tmp_path)
    assert not any(ADAPTERS[t].applies_to(ctx) for t in TIER2)
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "main.go").write_text("package main\n")
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    ctx = detect_context(tmp_path)
    assert (
        ADAPTERS["grype"].applies_to(ctx)
        and ADAPTERS["gosec"].applies_to(ctx)
        and ADAPTERS["checkov"].applies_to(ctx)
    )


def test_the_default_scan_command_lists_tier_two_tools_as_available() -> None:
    r = runner.invoke(app, ["scan", "--help"])
    assert "Also available" in r.output.replace("\n", " ") or "grype" in r.output


@pytest.mark.parametrize("ref", ["--evil", "-x", "a b", "img;rm -rf /", "", "x" * 300, "$(id)"])
def test_scan_image_rejects_anything_that_is_not_an_image_reference(ref: str) -> None:
    r = runner.invoke(app, ["scan-image", "--", ref])
    assert r.exit_code != 0


def test_golden_files_exist_for_every_tier_two_tool() -> None:
    for t in TIER2:
        assert (GOLDEN / t / "raw.json").is_file() and (GOLDEN / t / "expected.json").is_file()
