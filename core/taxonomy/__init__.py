"""CWE and OWASP Top 10 (2021) mapping tables.

Scanners report weaknesses inconsistently: Bandit gives a CWE, Semgrep sometimes tags OWASP,
Gitleaks and OSV give neither. We complete the picture from one table so a finding can be grouped
by OWASP category. The table is OWASP's own CWE-to-category list (owasp_top10_2021.json).
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

from core.models import Category, Finding

_DATA = Path(__file__).with_name("owasp_top10_2021.json")
_CWE = re.compile(r"^(?:CWE)?[-_ ]?(\d{1,5})$", re.IGNORECASE)
_OWASP = re.compile(r"^(?:OWASP[-_ ]?)?A?(\d{1,2})(?::2021)?$", re.IGNORECASE)

# When a scanner gives no CWE, the finding's kind still implies a category (documented in
# docs/taxonomy.md): a vulnerable dependency is A06, an infrastructure misconfiguration is A05.
CATEGORY_DEFAULTS: dict[Category, str] = {Category.SCA: "A06:2021", Category.IAC: "A05:2021"}


@lru_cache(maxsize=1)
def _load() -> dict[str, dict[str, object]]:
    cats: dict[str, dict[str, object]] = json.loads(_DATA.read_text(encoding="utf-8"))["categories"]
    return cats


@lru_cache(maxsize=1)
def _cwe_to_owasp() -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    for cat, entry in _load().items():
        for cwe in entry["cwes"]:  # type: ignore[attr-defined]
            out.setdefault(f"CWE-{cwe}", []).append(cat)
    return {k: tuple(sorted(v)) for k, v in out.items()}


@lru_cache(maxsize=1)
def _cwe_names() -> dict[str, str]:
    return {
        f"CWE-{cwe}": name
        for entry in _load().values()
        for cwe, name in entry["cwes"].items()  # type: ignore[attr-defined]
    }


def normalize_cwe(raw: object) -> str | None:
    """`79`, `"79"`, `cwe_79`, `CWE-79` -> `CWE-79`; anything else (untrusted input) -> None."""
    m = _CWE.match(str(raw).strip())
    return f"CWE-{int(m.group(1))}" if m and int(m.group(1)) > 0 else None


def normalize_owasp(raw: object) -> str | None:
    """`A03:2021`, `OWASP-A03:2021`, `a3` -> `A03:2021`; only A01..A10 are valid."""
    m = _OWASP.match(str(raw).strip())
    if not m or not 1 <= int(m.group(1)) <= 10:
        return None
    return f"A{int(m.group(1)):02d}:2021"


def owasp_for_cwe(cwe: str) -> tuple[str, ...]:
    return _cwe_to_owasp().get(normalize_cwe(cwe) or "", ())


def owasp_name(category: str) -> str | None:
    entry = _load().get(normalize_owasp(category) or "")
    return str(entry["name"]) if entry else None


def cwe_name(cwe: str) -> str | None:
    """Known only for CWEs that appear in the Top 10 table; None otherwise (never guessed)."""
    return _cwe_names().get(normalize_cwe(cwe) or "")


def enrich(finding: Finding) -> Finding:
    """Normalize CWE ids and fill in OWASP categories. Never removes anything a scanner reported."""
    tax = finding.taxonomy
    cwes = tuple(dict.fromkeys(c for c in map(normalize_cwe, tax.cwe) if c))
    owasp = [c for c in map(normalize_owasp, tax.owasp_top_10_2021) if c]
    for cwe in cwes:
        owasp.extend(owasp_for_cwe(cwe))
    if not owasp and tax.category in CATEGORY_DEFAULTS:
        owasp.append(CATEGORY_DEFAULTS[tax.category])
    new = replace(tax, cwe=cwes, owasp_top_10_2021=tuple(sorted(dict.fromkeys(owasp))))
    return finding if new == tax else replace(finding, taxonomy=new)


def enrich_all(findings: list[Finding]) -> list[Finding]:
    return [enrich(f) for f in findings]
