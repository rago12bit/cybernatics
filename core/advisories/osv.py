"""Reading OSV records (https://ossf.github.io/osv-schema/) and deciding whether a version is
affected (plan §46.2).

OSV is the one format every source arrives in: GitHub's advisories (GHSA), the Python and Go
databases (PYSEC, GO) and malicious-package reports (MAL) are all OSV records in OSV's per-ecosystem
dumps. A record names packages and, for each, version *ranges* -- events (`introduced`, `fixed`,
`last_affected`) in the ecosystem's own version order -- and sometimes an explicit list of affected
versions.

`affects()` is OSV's own evaluation, over `core.versions` keys: sort a range's events, walk them,
and the last one at or below the version decides. Getting this right is the hard part (plan §46.2),
so it is checked against osv-scanner on the same SBOMs (`scripts/osv-crosscheck.py`). A version or
an event the ecosystem cannot read makes the answer "cannot tell" (None), never "not affected".
`GIT` ranges are commit ranges; they are not evaluated against release versions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cvss import CVSS3, CVSS4, CVSSError

from core.inventory.identity import library_key
from core.versions import VersionError, key

# OSV's ecosystem names -> Bulwark's (core.models.Package.normalize_ecosystem).
ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm", "Go": "go", "Maven": "maven"}
MAX_TEXT = 4000


@dataclass(frozen=True)
class Range:
    type: str  # SEMVER | ECOSYSTEM | GIT
    events: tuple[tuple[str, str], ...]  # ("introduced", "1.0"), ("fixed", "1.2"), ...


@dataclass(frozen=True)
class Affected:
    ecosystem: str  # Bulwark's name: pypi | npm | go | maven
    name: str  # as OSV writes it (Maven group:artifact)
    ranges: tuple[Range, ...] = ()
    versions: tuple[str, ...] = ()

    @property
    def library_key(self) -> str:
        return library_key(self.ecosystem, self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ranges": [
                {"type": r.type, "events": [list(e) for e in r.events]} for r in self.ranges
            ],
            "versions": list(self.versions),
        }

    @classmethod
    def from_dict(cls, ecosystem: str, name: str, d: dict[str, Any]) -> Affected:
        return cls(
            ecosystem=ecosystem,
            name=name,
            ranges=tuple(
                Range(str(r["type"]), tuple((str(k), str(v)) for k, v in r["events"]))
                for r in d.get("ranges") or []
            ),
            versions=tuple(str(v) for v in d.get("versions") or []),
        )


@dataclass(frozen=True)
class Advisory:
    id: str
    modified: datetime
    published: datetime | None = None
    withdrawn: datetime | None = None
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    cvss: float | None = None  # the highest CVSS base score among its vectors, like osv-scanner
    cvss_vector: str = ""
    db_severity: str = ""  # GitHub's LOW | MODERATE | HIGH | CRITICAL, when given
    cwe: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    affected: tuple[Affected, ...] = field(default_factory=tuple)

    @property
    def malicious(self) -> bool:
        return self.id.startswith("MAL-") or any(a.startswith("MAL-") for a in self.aliases)

    @property
    def vuln_key(self) -> str:
        """One key for every record of one vulnerability: its lowest CVE alias, else the lowest of
        its id and aliases. OSV aliases are symmetric, so GHSA-x and PYSEC-y that alias each other
        get the same key -- what osv-scanner's "groups" do."""
        cves = sorted(a for a in (self.id, *self.aliases) if a.startswith("CVE-"))
        return cves[0] if cves else min((self.id, *self.aliases))

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(sorted({a for a in (self.id, *self.aliases) if a.startswith("CVE-")}))


_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$")


def parse_time(v: Any) -> datetime | None:
    """RFC 3339, with any number of fractional digits (OSV records use 0 to 9; Python 3.10's
    `fromisoformat` takes only 3 or 6), always timezone-aware."""
    m = _TIME.match(str(v or "").strip())
    if not m:
        return None
    base, frac, tz = m.groups()
    fraction = f".{(frac + '000000')[:6]}" if frac else ""
    text = base + fraction + ("+00:00" if tz in (None, "Z") else tz)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _score(vector: str) -> float | None:
    try:
        if vector.startswith("CVSS:4."):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).base_score)
    except (CVSSError, ValueError, KeyError, IndexError, TypeError):
        return None
    return None


def _links(raw: Any) -> tuple[str, ...]:
    """Reference URLs, shown as links: web addresses only, never `javascript:` and the like."""
    urls = [str(r.get("url") or "") for r in raw or [] if isinstance(r, dict)]
    return tuple(u for u in urls if u.startswith(("https://", "http://")) and len(u) < 2000)[:30]


def parse(raw: bytes | str | dict[str, Any]) -> Advisory | None:
    """One OSV record, keeping only the packages of the supported ecosystems. None for a record that
    is not OSV or affects none of them."""
    try:
        d = raw if isinstance(raw, dict) else json.loads(raw)
        aid = str(d["id"])
        modified = parse_time(d.get("modified"))
    except (ValueError, KeyError, TypeError):
        return None
    if modified is None or not aid or len(aid) > 100:
        return None
    affected: list[Affected] = []
    for a in d.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        eco = ECOSYSTEMS.get(str(pkg.get("ecosystem", "")))
        name = str(pkg.get("name") or "")
        if eco is None or not name or len(name) > 300:
            continue
        ranges = []
        for r in a.get("ranges") or []:
            if not isinstance(r, dict) or not isinstance(r.get("events"), list):
                continue
            events = tuple(
                (k, str(v)) for e in r["events"] if isinstance(e, dict) for k, v in e.items()
                if k in ("introduced", "fixed", "last_affected", "limit")
            )  # fmt: skip
            ranges.append(Range(str(r.get("type", "")), events))
        versions = tuple(str(v) for v in a.get("versions") or [] if isinstance(v, (str, int)))
        affected.append(Affected(eco, name, tuple(ranges), versions))
    if not affected:
        return None
    scores = [
        (s, str(sev.get("score")))
        for sev in d.get("severity") or []
        if isinstance(sev, dict) and (s := _score(str(sev.get("score", "")))) is not None
    ]
    best = max(scores, default=(None, ""))
    raw_db = d.get("database_specific")
    db: dict[str, Any] = raw_db if isinstance(raw_db, dict) else {}
    return Advisory(
        id=aid,
        modified=modified,
        published=parse_time(d.get("published")),
        withdrawn=parse_time(d.get("withdrawn")),
        aliases=tuple(sorted({str(x) for x in d.get("aliases") or [] if str(x) != aid}))[:50],
        summary=str(d.get("summary") or "")[:500],
        details=str(d.get("details") or "")[:MAX_TEXT],
        cvss=best[0],
        cvss_vector=best[1],
        db_severity=str(db.get("severity") or "")[:16].upper(),
        cwe=tuple(str(c) for c in db.get("cwe_ids") or [])[:20],
        references=_links(d.get("references")),
        affected=tuple(affected),
    )


# ---------------------------------------------------------------- does it affect this version?


def _listed(ecosystem: str, version: str, listed: tuple[str, ...]) -> bool:
    """Is `version` one of the listed versions -- as a version, not as text (osv-scanner finds
    `v1.6.5` in a list holding `1.6.5`)?"""
    if version in listed:
        return True
    try:
        k = key(ecosystem, version)
    except VersionError:
        return False
    for v in listed:
        try:
            if key(ecosystem, v) == k:
                return True
        except VersionError:
            continue
    return False


def _sorted_events(ecosystem: str, r: Range) -> list[tuple[str, str, Any]]:
    """Events in version order; `introduced: "0"` is before every version. Raises VersionError
    when an event's version cannot be read."""
    keyed = []
    for kind, v in r.events:
        if kind == "limit":
            continue  # only meaningful for GIT ranges
        keyed.append((kind, v, None if kind == "introduced" and v == "0" else key(ecosystem, v)))
    order = {"introduced": 0, "last_affected": 1, "fixed": 2}

    def sort_key(e: tuple[str, str, Any]) -> tuple[int, Any, int]:
        return (0, 0, order[e[0]]) if e[2] is None else (1, _Cmp(e[2]), order[e[0]])

    return sorted(keyed, key=sort_key)


class _Cmp:
    """Wraps a version key so sort() can compare it (Maven keys order but do not hash usefully)."""

    __slots__ = ("k",)

    def __init__(self, k: Any) -> None:
        self.k = k

    def __lt__(self, other: _Cmp) -> bool:
        return bool(self.k < other.k)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Cmp) and bool(self.k == other.k)

    __hash__ = None  # type: ignore[assignment]


def in_range(ecosystem: str, r: Range, version: str) -> bool:
    """OSV's evaluation of one SEMVER or ECOSYSTEM range. Raises VersionError."""
    k = key(ecosystem, version)
    affected = False
    for kind, _v, ek in _sorted_events(ecosystem, r):
        if kind == "introduced":
            if ek is None or k >= ek:
                affected = True
        elif kind == "fixed":
            if k >= ek:
                affected = False
        elif kind == "last_affected" and k > ek:
            affected = False
    return affected


def affects(a: Affected, version: str) -> bool | None:
    """True, False, or None when it cannot be told (a version or range the ecosystem cannot read).

    An entry with a GIT range is matched by its explicit `versions` list alone, as osv-scanner
    does: there the release ranges were derived from commits, and the list is what the database
    resolved them to (checked: osv-scanner flagged 0 of 40 versions inside such a range but not in
    the list, and 39 of 40 for entries without a GIT range)."""
    if a.versions and _listed(a.ecosystem, version, a.versions):
        return True
    if any(r.type == "GIT" for r in a.ranges):
        return False
    unknown = False
    for r in a.ranges:
        if r.type not in ("SEMVER", "ECOSYSTEM"):
            continue
        try:
            if in_range(a.ecosystem, r, version):
                return True
        except VersionError:
            unknown = True
    return None if unknown else False


def fixed_in(a: Affected, version: str) -> str | None:
    """The lowest `fixed` version above `version` in a range that affects it: the upgrade that
    fixes it. None when no range lists a fix (only `last_affected`, or nothing)."""
    best: tuple[Any, str] | None = None
    for r in a.ranges:
        if r.type not in ("SEMVER", "ECOSYSTEM"):
            continue
        try:
            if not in_range(a.ecosystem, r, version):
                continue
            k = key(a.ecosystem, version)
            for kind, v, ek in _sorted_events(a.ecosystem, r):
                if kind == "fixed" and ek > k and (best is None or ek < best[0]):
                    best = (ek, v)
                    break
        except VersionError:
            continue
    return best[1] if best else None
