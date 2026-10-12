"""Every data file the code reads at runtime must be in the installed package, not only in a source
checkout. The GitHub Action installs Bulwark with a plain `pip install`, and the taint catalogs were
missing from it: every Action scan logged a traceback and silently skipped taint analysis."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from setuptools.config.pyprojecttoml import read_configuration

ROOT = Path(__file__).resolve().parents[2]

# Read only by the prompt evaluations (promptfoo) and their fixtures, never by the installed code.
NOT_SHIPPED = ["core/llm/prompts/*/fixtures/*", "core/llm/prompts/*/promptfooconfig.yaml"]


def test_every_data_file_under_the_packages_is_shipped() -> None:
    package_data = read_configuration(ROOT / "pyproject.toml")["tool"]["setuptools"]["package-data"]
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
