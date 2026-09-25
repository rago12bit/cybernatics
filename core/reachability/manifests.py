"""Which dependencies does the project itself declare (as opposed to pull in transitively)?"""

from __future__ import annotations

import json
import re
from pathlib import Path

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ.match(line)
        if m:
            out.add(norm_py(m.group(1)))
    return out


def _pyproject(text: str) -> set[str]:
    try:
        import tomllib  # type: ignore[import-not-found,unused-ignore]  # Python 3.11+
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef,import-not-found,unused-ignore]

    try:
        doc = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return set()
    specs: list[str] = list(doc.get("project", {}).get("dependencies", []))
    for group in doc.get("project", {}).get("optional-dependencies", {}).values():
        specs.extend(group)
    out = _requirements("\n".join(specs))
    poetry = doc.get("tool", {}).get("poetry", {})
    for key in ("dependencies", "dev-dependencies"):
        out.update(norm_py(k) for k in poetry.get(key, {}) if k.lower() != "python")
    return out


def read_manifest(path: Path) -> tuple[str, set[str], str]:
    """(ecosystem, declared names, scripts text) for one manifest file, or ("", set(), "")."""
    name = path.name
    try:
        text = path.read_text("utf-8", errors="replace")
    except OSError:
        return "", set(), ""
    if name == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return "", set(), ""
        if not isinstance(doc, dict):
            return "", set(), ""
        names: set[str] = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            block = doc.get(key)
            if isinstance(block, dict):
                names.update(str(k) for k in block)
        scripts = doc.get("scripts")
        stext = " ".join(str(v) for v in scripts.values()) if isinstance(scripts, dict) else ""
        return "npm", names, stext
    if name == "pyproject.toml":
        return "pypi", _pyproject(text), ""
    if re.fullmatch(r"[\w.-]*requirements[\w.-]*\.txt", name) or (
        name.endswith(".txt") and path.parent.name == "requirements"
    ):
        return "pypi", _requirements(text), ""
    return "", set(), ""
