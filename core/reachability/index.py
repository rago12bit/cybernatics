"""Reachability v1 for dependency findings: is the vulnerable package imported by the code?

This answers a narrow question and says so. It does NOT prove a vulnerable function is called, and
it cannot see use through another package (Flask loads Jinja2 without your code importing it).
Three answers:

    True   an application source file imports it
    False  it is a declared dependency that no application file imports (or only tests do): the
           application's own code does not use it, though another dependency still may
    None   cannot tell (transitive dependency, plugin loaded by name, unsupported ecosystem,
           unparsable files): unknown is never turned into "unreachable"

Because False can be wrong in that indirect case, it only nudges the score (docs/reachability.md),
and every doubt about the analysis itself resolves to None.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from core.models import Finding, Package
from core.reachability.imports import FileImports, js_imports, python_imports
from core.reachability.manifests import norm_py, read_manifest

MAX_FILES = 20_000
SKIP_DIRS = frozenset(
    "node_modules .git .hg .svn .venv venv env __pycache__ site-packages dist build .tox .mypy_cache "
    ".next .nuxt coverage vendor third_party bower_components target".split()
)
TEST_DIRS = frozenset(
    "test tests __tests__ spec specs e2e testing fixtures __mocks__ cypress".split()
)
PY_EXT, JS_EXT, TS_EXT = {".py"}, {".js", ".jsx", ".mjs", ".cjs"}, {".ts", ".tsx", ".mts", ".cts"}

# distribution name (normalised) -> import names, where they differ from the distribution name.
PY_IMPORT_NAMES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"], "python-dateutil": ["dateutil"],
    "pyjwt": ["jwt"], "protobuf": ["google"], "attrs": ["attr", "attrs"], "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"], "psycopg2-binary": ["psycopg2"], "python-dotenv": ["dotenv"],
    "setuptools": ["setuptools", "pkg_resources"], "msgpack-python": ["msgpack"],
    "python-jose": ["jose"], "python-multipart": ["multipart"], "pymongo": ["pymongo", "bson"],
    "pyopenssl": ["OpenSSL"], "python-magic": ["magic"], "pyzmq": ["zmq"], "pycurl": ["pycurl"],
    "ruamel-yaml": ["ruamel"], "typing-extensions": ["typing_extensions"], "markupsafe": ["markupsafe"],
    "jinja2": ["jinja2"], "werkzeug": ["werkzeug"], "flask": ["flask"], "django": ["django"],
    "djangorestframework": ["rest_framework"], "python-ldap": ["ldap"], "pyserial": ["serial"],
    "pywin32": ["win32api", "win32con", "pythoncom"], "mysqlclient": ["MySQLdb"],
    "python-slugify": ["slugify"], "gitpython": ["git"], "pyasn1": ["pyasn1"], "lxml": ["lxml"],
}  # fmt: skip


def py_candidates(dist: str) -> set[str]:
    n = norm_py(dist)
    base = n.replace("-", "_")
    out = {base, *PY_IMPORT_NAMES.get(n, [])}
    for prefix in ("python-", "py-"):
        if n.startswith(prefix):
            out.add(n[len(prefix) :].replace("-", "_"))
    if n.endswith("-python"):
        out.add(n[: -len("-python")].replace("-", "_"))
    if n.startswith("py") and len(n) > 3:
        out.add(n[2:].replace("-", "_"))
    return {c.lower() for c in out}


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Reachability:
    reachable: bool | None
    reason: str


@dataclass
class ReachabilityIndex:
    app_imports: dict[str, dict[str, str]] = field(default_factory=dict)  # eco -> package -> file
    test_imports: dict[str, dict[str, str]] = field(default_factory=dict)
    strings: dict[str, set[str]] = field(default_factory=dict)  # eco -> string literals in source
    direct: dict[str, set[str]] = field(default_factory=dict)  # eco -> declared dependencies
    scripts_text: str = ""
    source_files: dict[str, int] = field(default_factory=dict)
    unparsed: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    def assess(self, f: Finding) -> Reachability | None:
        return None if f.package is None else self.assess_package(f.package)

    def assess_package(self, pkg: Package) -> Reachability:
        """The same answer for a package with no finding: what the component inventory records
        for every package in the SBOM."""
        eco = pkg.ecosystem
        if eco not in ("pypi", "npm"):
            return Reachability(None, f"Reachability is not analysed for {eco or 'this'} packages")
        if eco == "pypi":
            names = {c.lower() for c in py_candidates(pkg.name)}
            match = _py_matcher(names)
            declared = norm_py(pkg.name) in self.direct.get(eco, set())
            known = norm_py(pkg.name) in PY_IMPORT_NAMES or "-" not in norm_py(pkg.name)
            mentioned = bool(names & {s.lower() for s in self.strings.get(eco, ())})
        else:
            match = _js_matcher(pkg.name)
            declared = pkg.name in self.direct.get(eco, set())
            known = True
            mentioned = pkg.name in self.strings.get(eco, set()) or pkg.name in self.scripts_text
        app = match(self.app_imports.get(eco, {}))
        if app:
            return Reachability(True, f"Imported by application code ({app})")
        test = match(self.test_imports.get(eco, {}))
        if test:
            return Reachability(
                False, f"Imported only by test code ({test}), not by the application's own code"
            )
        if not declared:
            return Reachability(
                None,
                "Transitive dependency: reachability through its parent package is not analysed",
            )
        if self.truncated or self.unparsed.get(eco, 0) or not self.source_files.get(eco, 0):
            return Reachability(None, "Source files could not be fully analysed")
        if mentioned:
            return Reachability(
                None, "Not imported, but named in code or scripts (plugin or CLI use)"
            )
        if not known:
            return Reachability(None, "Import name for this package could not be determined")
        return Reachability(
            False,
            "No source file of the application imports it (another dependency may still load it)",
        )


def _py_matcher(names: set[str]) -> Callable[[dict[str, str]], str | None]:
    def match(table: dict[str, str]) -> str | None:
        return next((table[k] for k in table if k.lower() in names), None)

    return match


def _js_matcher(name: str) -> Callable[[dict[str, str]], str | None]:
    def match(table: dict[str, str]) -> str | None:
        return table.get(name)

    return match


def _classify(rel: Path) -> str:
    return (
        "test"
        if any(p.lower() in TEST_DIRS for p in rel.parts[:-1]) or _is_test_name(rel.name)
        else "app"
    )


def _is_test_name(name: str) -> bool:
    n = name.lower()
    return n.startswith("test_") or n.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx", ".test.jsx", ".spec.jsx"))  # fmt: skip


def analyze(root: Path) -> ReachabilityIndex:
    """Walk `root` (never following symlinks or descending into dependency/build dirs)."""
    idx = ReachabilityIndex()
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            path = Path(dirpath, fn)
            if path.is_symlink() or not path.is_file():
                continue
            seen += 1
            if seen > MAX_FILES:
                idx.truncated = True
                return idx
            eco, names, scripts = read_manifest(path)
            if eco:
                idx.direct.setdefault(eco, set()).update(names)
                idx.scripts_text += " " + scripts
                continue
            ext = path.suffix.lower()
            if ext not in PY_EXT | JS_EXT | TS_EXT:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            eco = "pypi" if ext in PY_EXT else "npm"
            res: FileImports = (
                python_imports(data.decode("utf-8", "replace"))
                if eco == "pypi"
                else js_imports(data, typescript=ext in TS_EXT)
            )
            idx.source_files[eco] = idx.source_files.get(eco, 0) + 1
            if not res.parsed:
                idx.unparsed[eco] = idx.unparsed.get(eco, 0) + 1
            rel = path.relative_to(root)
            table = (idx.test_imports if _classify(rel) == "test" else idx.app_imports).setdefault(
                eco, {}
            )
            for p in res.packages:
                table.setdefault(p, rel.as_posix())
            if _classify(rel) == "app":
                idx.strings.setdefault(eco, set()).update(res.strings)
    return idx


def analyze_or_none(root: Path) -> ReachabilityIndex | None:
    """Best effort: a failure here must never fail a scan, it only means no reachability data."""
    try:
        return analyze(root)
    except Exception:  # noqa: BLE001
        log.warning("reachability analysis failed", exc_info=True)
        return None
