#!/usr/bin/env python3
"""Vendor DefectDojo's sample reports and read its parsers' expected results out of its tests.

    git clone --depth 1 https://github.com/DefectDojo/django-DefectDojo.git /tmp/dd
    python scripts/sync-dd-fixtures.py --checkout /tmp/dd zap nuclei

Plan §59 Week 57: "ported from DefectDojo with its sample reports as golden fixtures", and §60
measures "issues produced and field-level agreement with DefectDojo's expected results". Those
expectations are not written anywhere as data -- they are the assertions in DefectDojo's own unit
tests -- so this reads them out of the test files (with `ast`, never by running them) into one
`MANIFEST.json` per tool:

    {"source": {...pinned commit...},
     "files": {"0_zap_sample.xml": {"sha256": ..., "bytes": ..., "vendored": true,
                                    "expect": [{"count": 4, "findings": {"0": {"title": ...}}}]}}}

Files over `MAX_VENDORED` are listed (with their digest) but not copied: fetch them with this
script when you want them. The DefectDojo licence travels with every copy (BSD-3-Clause).
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "golden" / "ingest" / "defectdojo"
MAX_VENDORED = 3_000_000  # bytes (git stores them compressed); bigger samples stay out
ATTRS = {
    "title", "severity", "vuln_id_from_tool", "cwe", "cvssv3_score", "component_name", "component_version",
}  # fmt: skip

# tool -> (DefectDojo test file, the scans directory it reads, helper functions that open a file in it)
TOOLS: dict[str, dict[str, Any]] = {
    "zap": {"test": "test_zap_parser.py", "dir": "zap"},
    "nuclei": {"test": "test_nuclei_parser.py", "dir": "nuclei"},
    "grype": {"test": "test_anchore_grype_parser.py", "dir": "anchore_grype"},
    "trivy": {
        "test": "test_trivy_parser.py",
        "dir": "trivy",
        "helpers": {"sample_path": "trivy"},
    },
    "snyk": {"test": "test_snyk_parser.py", "dir": "snyk"},
    "burp": {"test": "test_burp_parser.py", "dir": "burp"},
    "nessus": {"test": "test_tenable_parser.py", "dir": "tenable/nessus"},
    # DefectDojo has two OpenVAS parsers; Bulwark ports the current one ("v2"), so only its tests
    # are expectations. The older layout's sample files are still vendored and parsed.
    "openvas": {
        "test": "test_openvas_parser.py",
        "dir": "openvas",
        "helpers": {"openvas_open": "openvas"},
        "classes": ["TestOpenVASParserV2"],
        "parse_methods": ["setup_openvas_v2_test"],
    },
}


def _const(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return ...


def _index(node: ast.AST) -> int | None:
    value = _const(node)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class _Case(ast.NodeVisitor):
    """Walk one test method in source order, tracking which finding a name currently holds."""

    def __init__(self, helpers: dict[str, str], parsers: frozenset[str]) -> None:
        self.helpers = helpers
        self.parsers = parsers  # method names that parse a file and return findings
        self.files: set[str] = set()
        self.count: int | None = None
        self.per: dict[int, dict[str, Any]] = {}
        self.bound: dict[str, int | None] = {}
        self.parses = 0
        self.results: set[str] = {"findings"}  # names that hold a parse result

    def _finding_index(self, node: ast.AST) -> int | None:
        """The index a `finding` expression refers to: `findings[3]`, or a name bound to one."""
        if isinstance(node, ast.Name):
            return self.bound.get(node.id)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            return _index(node.slice) if node.value.id in self.results else None
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in self.parsers
        ):
            self.results |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self.bound[node.targets[0].id] = self._finding_index(node.value)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        # get_unit_tests_scans_path("zap") / "file.xml"
        if (
            isinstance(node.op, ast.Div)
            and isinstance(node.right, ast.Constant)
            and isinstance(node.right.value, str)
            and isinstance(node.left, ast.Call)
            and getattr(node.left.func, "id", "") == "get_unit_tests_scans_path"
            and node.left.args
        ):
            self.files.add(f"{_const(node.left.args[0])}/{node.right.value}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = getattr(node.func, "id", None)
        if name in self.helpers and node.args and isinstance(node.args[0], ast.Constant):
            self.files.add(f"{self.helpers[name]}/{node.args[0].value}")
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in self.parsers:
                self.parses += 1
            elif node.func.attr == "assertEqual" and len(node.args) == 2:
                self._equal(*node.args)
            elif node.func.attr == "assertIsNone" and len(node.args) == 1:
                self._equal(ast.Constant(None), node.args[0])
        self.generic_visit(node)

    def _equal(self, a: ast.AST, b: ast.AST) -> None:
        expected, actual = (a, b) if _const(a) is not ... else (b, a)
        value = _const(expected)
        if value is ...:
            return
        if isinstance(actual, ast.Call) and getattr(actual.func, "id", "") == "len" and actual.args:
            arg = actual.args[0]
            if isinstance(arg, ast.Name) and arg.id in self.results:
                self.count = value
                return
            # len(self.get_unsaved_locations(finding)) -- how many places a finding applies to
            if (
                isinstance(arg, ast.Call)
                and getattr(arg.func, "attr", "") == "get_unsaved_locations"
            ):
                idx = self._finding_index(arg.args[0]) if arg.args else None
                if idx is not None:
                    self.per.setdefault(idx, {})["locations"] = value
            return
        if (
            isinstance(actual, ast.Attribute)
            and actual.attr in ATTRS
            and (idx := self._finding_index(actual.value)) is not None
        ):
            self.per.setdefault(idx, {})[actual.attr] = value


def extract(
    test_file: Path,
    directory: str,
    helpers: dict[str, str],
    classes: list[str] | None = None,
    parse_methods: tuple[str, ...] = (),
) -> dict[str, list[dict]]:
    """file name (inside `directory`) -> the expectations DefectDojo's tests make about it."""
    tree = ast.parse(test_file.read_text(encoding="utf-8"))
    by_file: dict[str, list[dict]] = {}
    for fn in ast.walk(tree):
        if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_")):
            continue
        if classes is not None and fn.name not in {
            f.name
            for c in ast.walk(tree)
            if isinstance(c, ast.ClassDef) and c.name in classes
            for f in c.body
            if isinstance(f, ast.FunctionDef)
        }:
            continue
        case = _Case(helpers, frozenset({"get_findings", *parse_methods}))
        case.visit(fn)
        # A test that parses two files (xml/csv parity) says nothing about either alone.
        if len(case.files) != 1 or case.parses != 1:
            continue
        (path,) = case.files
        if not path.startswith(directory + "/") or (case.count is None and not case.per):
            continue
        entry: dict[str, Any] = {"test": fn.name}
        if case.count is not None:
            entry["count"] = case.count
        if case.per:
            entry["findings"] = {str(i): case.per[i] for i in sorted(case.per)}
        by_file.setdefault(path[len(directory) + 1 :], []).append(entry)
    return by_file


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--checkout", type=Path, required=True)
    ap.add_argument("tools", nargs="+", choices=sorted(TOOLS))
    args = ap.parse_args()
    dd: Path = args.checkout

    commit = subprocess.run(
        ["git", "-C", str(dd), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copy(dd / "LICENSE.md", OUT / "LICENSE")

    for tool in args.tools:
        cfg = TOOLS[tool]
        scans = dd / "unittests" / "scans" / cfg["dir"]
        expected = extract(
            dd / "unittests" / "tools" / cfg["test"],
            cfg["dir"],
            cfg.get("helpers", {}),
            cfg.get("classes"),
            tuple(cfg.get("parse_methods", ())),
        )
        dest = OUT / tool
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        files: dict[str, Any] = {}
        for src in sorted(p for p in scans.iterdir() if p.is_file()):
            data = src.read_bytes()
            vendored = len(data) <= MAX_VENDORED
            if vendored:
                (dest / src.name).write_bytes(data)
            files[src.name] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "vendored": vendored,
                "expect": expected.get(src.name, []),
            }
        manifest = {
            "tool": tool,
            "source": {
                "repository": "https://github.com/DefectDojo/django-DefectDojo",
                "commit": commit,
                "license": "BSD-3-Clause (see ../LICENSE)",
                "scans": f"unittests/scans/{cfg['dir']}",
                "tests": f"unittests/tools/{cfg['test']}",
            },
            "files": files,
        }
        (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        n_exp = sum(len(f["expect"]) for f in files.values())
        print(f"{tool}: {len(files)} files, {n_exp} expectations read from {cfg['test']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
