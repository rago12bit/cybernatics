from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.models import Category, Finding, Location, Package, Severity, Taxonomy
from core.reachability import Reachability, analyze, analyze_or_none
from core.reachability.imports import js_imports, js_package, python_imports
from core.reachability.manifests import read_manifest
from core.risk import Feeds, apply_risk
from core.risk.score import KEV_FLOOR, UNREACHED_FACTOR, UNREACHED_KEV_FLOOR, score_finding


def dep(
    name: str, eco: str = "npm", cve: str = "CVE-2020-1", sev: Severity = Severity.HIGH
) -> Finding:
    f = Finding(
        id=f"{eco}-{name}", title="t", description="", location=Location("lock", 1, 1),
        taxonomy=Taxonomy(Category.SCA, cve=(cve,)), package=Package(name, "1.0.0", eco),
    )  # fmt: skip
    f.scoring.normalized_severity = sev
    return f


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def verdict(root: Path, f: Finding) -> Reachability:
    r = analyze(root).assess(f)
    assert r is not None
    return r


# ---- import extraction --------------------------------------------------------------------------


def test_python_imports_top_level_names_only() -> None:
    src = "import os, yaml.constructor\nfrom flask import Flask\nfrom . import sibling\nfrom .x import y\nimport importlib\nimportlib.import_module('jwt.algorithms')\n__import__('redis')\n"
    got = python_imports(src)
    assert got.packages == {"os", "yaml", "flask", "importlib", "jwt", "redis"}


def test_python_syntax_error_is_reported_not_raised() -> None:
    got = python_imports("def broken(:\n")
    assert got.parsed is False and got.packages == set()


def test_python_import_in_string_or_comment_does_not_count() -> None:
    got = python_imports("# import evil\nx = 'import evil'\n")
    assert "evil" not in got.packages and "import evil" in got.strings


@pytest.mark.parametrize(
    "spec,expected",
    [("lodash", "lodash"), ("lodash/fp", "lodash"), ("@scope/pkg/deep", "@scope/pkg"), ("./local", None),
     ("../up", None), ("/abs", None), ("node:fs", None), ("fs", None), ("", None), ("http://x", None)],
)  # fmt: skip
def test_js_package_names(spec: str, expected: str | None) -> None:
    assert js_package(spec) == expected


def test_js_imports_all_forms() -> None:
    src = b"""
import a from 'alpha';
import {b} from "@beta/core/sub";
export * from 'gamma';
const c = require('delta');
const d = await import('epsilon');
import fs from 'fs';
import rel from './rel';
// require('commented')
const s = "require('instring')";
"""
    got = js_imports(src)
    assert got.packages == {"alpha", "@beta/core", "gamma", "delta", "epsilon"}
    assert got.parsed


def test_js_require_of_variable_is_not_counted() -> None:
    assert js_imports(b"const x = require(name);").packages == set()


def test_typescript_syntax_parses() -> None:
    got = js_imports(b"import type { T } from 'zeta';\nconst v: number = 1;\n", typescript=True)
    assert got.packages == {"zeta"} and got.parsed


def test_js_syntax_error_marks_file_unparsed() -> None:
    assert js_imports(b"import {{{ from 'x'").parsed is False


# ---- manifests ----------------------------------------------------------------------------------


def test_manifests(tmp_path: Path) -> None:
    write(tmp_path, {
        "package.json": json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"b": "1"}, "scripts": {"lint": "eslint ."}}),
        "requirements.txt": "Flask==2.0  # web\n-r other.txt\n# c\nPyYAML>=5\n",
        "pyproject.toml": '[project]\ndependencies = ["requests>=2"]\n[project.optional-dependencies]\ndev = ["pytest"]\n',
        "bad/package.json": "{not json",
    })  # fmt: skip
    assert read_manifest(tmp_path / "package.json") == ("npm", {"a", "b"}, "eslint .")
    assert read_manifest(tmp_path / "requirements.txt")[1] == {"flask", "pyyaml"}
    assert read_manifest(tmp_path / "pyproject.toml")[1] == {"requests", "pytest"}
    assert read_manifest(tmp_path / "bad/package.json") == ("", set(), "")


# ---- verdicts -----------------------------------------------------------------------------------


def test_imported_by_app_code_is_reachable(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"dependencies":{"lodash":"4"}}',
            "src/app.js": "const _ = require('lodash');",
        },
    )
    r = verdict(tmp_path, dep("lodash"))
    assert r.reachable is True and "src/app.js" in r.reason


def test_declared_but_never_imported_is_unreachable(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"package.json": '{"dependencies":{"lodash":"4"}}', "src/app.js": "console.log(1)"},
    )
    assert verdict(tmp_path, dep("lodash")).reachable is False


def test_imported_only_by_tests_is_unreachable(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"dependencies":{"lodash":"4"}}',
            "test/a.test.js": "require('lodash')",
            "src/a.js": "1",
        },
    )
    r = verdict(tmp_path, dep("lodash"))
    assert r.reachable is False and "test code" in r.reason


def test_transitive_dependency_is_unknown_not_unreachable(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"package.json": '{"dependencies":{"express":"4"}}', "src/app.js": "require('express')"},
    )
    r = verdict(tmp_path, dep("qs"))
    assert r.reachable is None and "Transitive" in r.reason


def test_package_named_in_string_is_unknown(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"dependencies":{"babel-plugin-x":"1"}}',
            "webpack.config.js": "module.exports={plugins:['babel-plugin-x']}",
        },
    )
    assert verdict(tmp_path, dep("babel-plugin-x")).reachable is None


def test_package_used_as_cli_in_scripts_is_unknown(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"devDependencies":{"mocha":"1"},"scripts":{"test":"mocha tests"}}',
            "src/a.js": "1",
        },
    )
    assert verdict(tmp_path, dep("mocha")).reachable is None


def test_unparsable_source_makes_it_unknown(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"package.json": '{"dependencies":{"lodash":"4"}}', "src/broken.js": "import {{{ nope"},
    )
    assert verdict(tmp_path, dep("lodash")).reachable is None


def test_no_source_files_is_unknown(tmp_path: Path) -> None:
    write(tmp_path, {"package.json": '{"dependencies":{"lodash":"4"}}'})
    assert verdict(tmp_path, dep("lodash")).reachable is None


def test_unsupported_ecosystem_is_unknown(tmp_path: Path) -> None:
    write(tmp_path, {"app.py": "x=1"})
    assert verdict(tmp_path, dep("log4j-core", eco="maven")).reachable is None


def test_finding_without_package_has_no_assessment(tmp_path: Path) -> None:
    f = dep("x")
    f.package = None
    assert analyze(tmp_path).assess(f) is None


def test_python_import_name_differs_from_distribution(tmp_path: Path) -> None:
    write(tmp_path, {"requirements.txt": "PyYAML==5.1\n", "app.py": "import yaml\n"})
    assert verdict(tmp_path, dep("PyYAML", eco="pypi")).reachable is True


def test_python_declared_unused(tmp_path: Path) -> None:
    write(tmp_path, {"requirements.txt": "jinja2==2.0\n", "app.py": "import os\n"})
    assert verdict(tmp_path, dep("Jinja2", eco="pypi")).reachable is False


def test_python_hyphenated_unknown_import_name_stays_unknown(tmp_path: Path) -> None:
    # "some-odd-dist" may import as anything; not finding it proves nothing.
    write(tmp_path, {"requirements.txt": "some-odd-dist==1\n", "app.py": "import os\n"})
    assert verdict(tmp_path, dep("some-odd-dist", eco="pypi")).reachable is None


def test_python_import_in_tests_only(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "requirements.txt": "requests==2\n",
            "tests/test_a.py": "import requests\n",
            "app.py": "x=1\n",
        },
    )
    assert verdict(tmp_path, dep("requests", eco="pypi")).reachable is False


def test_dependency_and_build_dirs_are_not_scanned(tmp_path: Path) -> None:
    write(tmp_path, {
        "package.json": '{"dependencies":{"lodash":"4"}}',
        "src/a.js": "1",
        "node_modules/x/index.js": "require('lodash')",
        ".venv/lib/a.py": "import lodash",
    })  # fmt: skip
    assert verdict(tmp_path, dep("lodash")).reachable is False


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    write(outside, {"evil.js": "require('lodash')"})
    root = write(
        tmp_path / "repo", {"package.json": '{"dependencies":{"lodash":"4"}}', "a.js": "1"}
    )
    os.symlink(outside / "evil.js", root / "link.js")
    assert verdict(root, dep("lodash")).reachable is False


def test_oversized_and_too_many_files_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import core.reachability.index as ix

    monkeypatch.setattr(ix, "MAX_FILES", 3)
    write(
        tmp_path,
        {f"f{i}.js": "1" for i in range(10)} | {"package.json": '{"dependencies":{"lodash":"4"}}'},
    )
    idx = analyze(tmp_path)
    assert idx.truncated
    assert idx.assess(dep("lodash")).reachable is None  # type: ignore[union-attr]


def test_analyze_or_none_swallows_failure(tmp_path: Path) -> None:
    assert analyze_or_none(tmp_path / "does-not-exist") is not None  # empty walk, not an error


# ---- scoring ------------------------------------------------------------------------------------


def test_unreachable_lowers_score_and_says_why() -> None:
    base = score_finding(dep("x"), Feeds()).scoring.risk_score
    low = score_finding(dep("x"), Feeds(), Reachability(False, "nothing imports it"))
    assert low.scoring.reachable is False
    assert base is not None and abs(low.scoring.risk_score - base * UNREACHED_FACTOR) <= 1  # type: ignore[operator]
    assert "nothing imports it" in low.scoring.risk_factors


def test_reachable_and_unknown_do_not_change_score() -> None:
    base = score_finding(dep("x"), Feeds()).scoring.risk_score
    yes = score_finding(dep("x"), Feeds(), Reachability(True, "imported"))
    unk = score_finding(dep("x"), Feeds(), Reachability(None, "transitive"))
    assert yes.scoring.risk_score == unk.scoring.risk_score == base
    assert yes.scoring.reachable is True and unk.scoring.reachable is None


def test_kev_floor_is_lowered_but_kept_when_unreachable() -> None:
    feeds = Feeds(kev={"CVE-2020-1"})
    hot = score_finding(dep("x", sev=Severity.LOW), feeds, Reachability(False, "n"))
    assert hot.scoring.risk_score == UNREACHED_KEV_FLOOR < KEV_FLOOR
    assert score_finding(dep("x", sev=Severity.LOW), feeds).scoring.risk_score == KEV_FLOOR


def test_apply_risk_uses_assess_callback() -> None:
    f = dep("x")
    out = apply_risk([f], Feeds(), lambda _f: Reachability(False, "n"))
    assert out[0].scoring.reachable is False


def test_finalize_end_to_end(tmp_path: Path) -> None:
    from core.postprocess import finalize

    write(tmp_path, {"package.json": '{"dependencies":{"lodash":"4"}}', "a.js": "1"})
    out = finalize([dep("lodash")], Feeds(), analyze(tmp_path))
    assert out[0].scoring.reachable is False
    assert any(
        "No source file of the application imports it" in x for x in out[0].scoring.risk_factors
    )
