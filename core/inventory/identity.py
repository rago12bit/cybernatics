"""Which library a package URL names (plan §46.1).

A library is its ecosystem plus its name as that ecosystem compares names: PyPI folds case and
treats `-`, `_` and `.` alike (PEP 503), npm names are lower case (the purl spec says so too), and
Go module paths and Maven coordinates are compared exactly. The name itself is kept in the form
OSV and the rest of Bulwark write it -- Maven as `group:artifact`, npm scopes as `@scope/name` --
so the advisory engine (Week 68) can look a library up by the name an advisory gives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from core.imports.parsers.purl import parse_purl

MAX_NAME = 300


@dataclass(frozen=True)
class Ident:
    ecosystem: str
    name: str
    key: str
    purl: str  # without a version
    version: str  # "" when the purl had none


def name_key(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name


def library_key(ecosystem: str, name: str) -> str:
    return f"{ecosystem}:{name_key(ecosystem, name)}"


def _purl_type(ecosystem: str) -> str:
    return {"go": "golang", "rubygems": "gem", "packagist": "composer"}.get(ecosystem, ecosystem)


def base_purl(ecosystem: str, name: str) -> str:
    """`pkg:maven/org.apache.logging.log4j/log4j-core` for maven `org.apache...:log4j-core`."""
    path = name.replace(":", "/", 1) if ecosystem == "maven" else name
    return f"pkg:{_purl_type(ecosystem)}/" + "/".join(quote(p, safe="") for p in path.split("/"))


def from_purl(purl: str) -> Ident | None:
    """None for anything that is not a usable purl (no `pkg:` prefix, no name, an absurd length)."""
    if len(purl) > 2000:
        return None
    parsed = parse_purl(purl.strip())
    if parsed is None:
        return None
    ecosystem, name, version = parsed
    if not ecosystem or not name or len(name) > MAX_NAME or len(ecosystem) > 32:
        return None
    return Ident(
        ecosystem=ecosystem,
        name=name,
        key=library_key(ecosystem, name),
        purl=base_purl(ecosystem, name),
        version=version[:200],
    )
