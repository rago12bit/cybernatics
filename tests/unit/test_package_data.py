"""Every data file the code reads at runtime must be in the installed package, not only in a source
checkout. The GitHub Action installs Bulwark with a plain `pip install`, and the taint catalogs were
missing from it: every Action scan logged a traceback and silently skipped taint analysis."""

from __future__ import annotations

import ast
import fnmatch
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Read only by the prompt evaluations (promptfoo) and their fixtures, never by the installed code.
NOT_SHIPPED = ["core/llm/prompts/*/fixtures/*", "core/llm/prompts/*/promptfooconfig.yaml"]


def _package_data(pyproject: Path) -> dict[str, list[str]]:
    """[tool.setuptools.package-data], read without setuptools (not installed on Python 3.12+) or
    tomllib (3.11+): every entry there is one `"package" = ["glob", ...]` line."""
    out: dict[str, list[str]] = {}
    in_table = False
    for line in pyproject.read_text().splitlines():
        if line.startswith("["):
            in_table = line.strip() == "[tool.setuptools.package-data]"
        elif in_table and "=" in line:
            key, value = line.split("=", 1)
            out[ast.literal_eval(key.strip())] = ast.literal_eval(value.strip())
    return out


def test_every_data_file_under_the_packages_is_shipped() -> None:
    package_data = _package_data(ROOT / "pyproject.toml")
    shipped = [
        f"{pkg.replace('.', '/')}/{pattern}"
        for pkg, patterns in package_data.items()
        for pattern in patterns
    ]
    tracked = subprocess.run(
        ["git", "ls-files", "core", "cli", "api"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    missing = [
        rel
        for rel in tracked
        if not rel.endswith(".py")
        and not any(fnmatch.fnmatch(rel, p) for p in shipped + NOT_SHIPPED)
    ]
    assert (
        missing == []
    ), f"add these to [tool.setuptools.package-data] in pyproject.toml: {missing}"
