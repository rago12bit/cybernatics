"""Ordering package versions the way each ecosystem does (plan §46.1-46.2).

"Is 2.17.0 below 2.17.1?" has a different answer per ecosystem once versions stop being three
plain numbers: PEP 440 puts `1.0rc1` before `1.0` and `1.0.post1` after it; semver puts
`1.0.0-rc.1` before `1.0.0` and ignores `+build`; Maven puts `1.0-alpha` before `1.0`, treats
`1.0`, `1.0.0` and `1.0-ga` as the same version, and sorts unknown qualifiers after `sp`. The
component search (`?version=<2.17.1`) and the advisory engine's range matching both order versions
with `key()` here, so the two can never disagree with each other.

Supported: PyPI (PEP 440 through `packaging`, and versions that are not PEP 440 in setuptools'
legacy order before all of them, as osv-scanner does), npm and Go (semver 2.0.0, read as leniently
as osv-scanner reads it -- see `_semver`) and Maven (the algorithm of Maven's own
`ComparableVersion`). Another ecosystem, or an empty or absurdly long version, raises
`VersionError`, and callers report it as "could not be compared" rather than guessing an order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any

from packaging.version import InvalidVersion, Version

SUPPORTED = ("pypi", "npm", "go", "maven")
MAX_VERSION_LENGTH = 200


class VersionError(ValueError):
    pass


# ---------------------------------------------------------------- semver (npm, Go)


@total_ordering
@dataclass(frozen=True)
class _Pre:
    """One prerelease identifier: numeric ones sort numerically and before alphanumeric ones."""

    num: int | None
    text: str

    def __lt__(self, other: _Pre) -> bool:
        if self.num is not None and other.num is not None:
            return self.num < other.num
        if (self.num is None) != (other.num is None):
            return self.num is not None
        return self.text < other.text


def _semver(v: str) -> tuple[Any, ...]:
    """Semver as osv-scanner reads it (osv-scalibr's semver parser), so the two agree on every
    version OSV's npm and Go data contain -- including the ones that are not strict semver
    (`19.03.0`, `2.62`, `9.6.0b1`), which OSV allows implementations to accept. Leading `v` is
    dropped; numbers up to the first character that is neither a digit nor `.` are the version
    (missing ones are 0, so `1.2` is `1.2.0`); the rest, less `+build` metadata and a leading `-`,
    is the prerelease. For strict semver this is exactly semver 2.0.0's order."""
    s = v.strip().removeprefix("v")
    nums: list[int] = []
    cur = ""
    rest = ""
    for i, c in enumerate(s):
        if c.isdigit():
            cur += c
            continue
        if cur:
            nums.append(int(cur))
            cur = ""
        if c == ".":
            continue
        rest = s[i:]
        break
    else:
        if cur:
            nums.append(int(cur))
    while nums and nums[-1] == 0:
        nums.pop()  # 1.2 == 1.2.0
    pre = rest.split("+", 1)[0].removeprefix("-")
    if not pre:
        return (tuple(nums), 1, ())  # a release sorts after every prerelease of the same version
    ids = tuple(_Pre(int(p), p) if p.isdigit() else _Pre(None, p) for p in pre.split("."))
    return (tuple(nums), 0, ids)


# ---------------------------------------------------------------- PyPI before PEP 440

_LEGACY_PART = re.compile(r"(\d+|[a-z]+|\.|-)")
_LEGACY_MAP = {"pre": "c", "preview": "c", "-": "final-", "rc": "c", "dev": "@"}


def _legacy(v: str) -> tuple[str, ...]:
    """setuptools' LegacyVersion order (removed from `packaging` in 22.0, still what osv-scanner
    applies to a PyPI version that is not PEP 440, such as Debian's `0.8.3ubuntu7.5`): every such
    version sorts before every PEP 440 version, and among themselves by these parts."""
    parts: list[str] = []
    for raw in _LEGACY_PART.split(v.lower()):
        part = _LEGACY_MAP.get(raw, raw)
        if not part or part == ".":
            continue
        part = part.zfill(8) if part[:1].isdigit() else "*" + part
        if part.startswith("*"):
            if part < "*final":
                while parts and parts[-1] == "*final-":
                    parts.pop()
            while parts and parts[-1] == "00000000":
                parts.pop()
        parts.append(part)
    return (*parts, "*final")


# ---------------------------------------------------------------- Maven ComparableVersion

_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_RELEASE = str(_QUALIFIERS.index(""))


def _qualifier(value: str) -> str:
    """A qualifier's sort string: its place in the known list, or after all of them, by name."""
    if value in _QUALIFIERS:
        return str(_QUALIFIERS.index(value))
    return f"{len(_QUALIFIERS)}-{value}"


class _Int:
    def __init__(self, text: str) -> None:
        self.value = int(text or "0")

    def null(self) -> bool:
        return self.value == 0

    def cmp(self, other: Any) -> int:
        if other is None:
            return 0 if self.value == 0 else 1
        if isinstance(other, _Int):
            return (self.value > other.value) - (self.value < other.value)
        return 1  # a number is newer than a qualifier or a sub-list


class _Str:
    def __init__(self, value: str, followed_by_digit: bool) -> None:
        if followed_by_digit and len(value) == 1:
            value = {"a": "alpha", "b": "beta", "m": "milestone"}.get(value, value)
        self.value = _ALIASES.get(value, value)

    def null(self) -> bool:
        return self.value == ""

    def cmp(self, other: Any) -> int:
        mine = _qualifier(self.value)
        if other is None:
            return (mine > _RELEASE) - (mine < _RELEASE)
        if isinstance(other, _Str):
            theirs = _qualifier(other.value)
            return (mine > theirs) - (mine < theirs)
        return -1  # older than a number or a sub-list


class _List(list[Any]):
    def null(self) -> bool:
        return len(self) == 0

    def normalize(self) -> None:
        for i in range(len(self) - 1, -1, -1):
            if self[i].null():
                del self[i]
            elif not isinstance(self[i], _List):
                break

    def cmp(self, other: Any) -> int:
        if other is None:  # every item, not only the first (Maven 3.9, MNG-6964)
            return next((r for i in self if (r := i.cmp(None))), 0)
        if isinstance(other, _Int):
            return -1
        if isinstance(other, _Str):
            return 1
        for i in range(max(len(self), len(other))):
            left = self[i] if i < len(self) else None
            right = other[i] if i < len(other) else None
            if left is None:
                res: int = 0 if right is None else -right.cmp(None)
            else:
                res = left.cmp(right)
            if res:
                return res
        return 0


def _maven_items(v: str) -> _List:
    version = v.strip().lower()
    if not version:
        raise VersionError("an empty version is not a Maven version")
    root = cur = _List()
    stack = [root]
    start, digit = 0, False

    def item(is_digit: bool, text: str, followed_by_digit: bool = False) -> Any:
        return _Int(text) if is_digit else _Str(text, followed_by_digit)

    def sub() -> _List:
        nxt = _List()
        cur.append(nxt)
        stack.append(nxt)
        return nxt

    # Read off Maven 3.9.16's own bytecode, and checked against it on random versions
    # (tests/unit/test_versions.py): a qualifier opens a sub-list unless it starts the list.
    for i, c in enumerate(version):
        if c == ".":
            cur.append(_Int("0") if i == start else item(digit, version[start:i]))
            start = i + 1
        elif c == "-":
            cur.append(_Int("0") if i == start else item(digit, version[start:i]))
            start = i + 1
            cur = sub()
        elif c.isdigit():
            if not digit and i > start:
                if cur:
                    cur = sub()
                cur.append(_Str(version[start:i], True))
                start = i
                cur = sub()
            digit = True
        else:
            if digit and i > start:
                cur.append(item(True, version[start:i]))
                start = i
                cur = sub()
            digit = False
    if len(version) > start:
        if not digit and cur:
            cur = sub()
        cur.append(item(digit, version[start:]))
    while stack:
        stack.pop().normalize()
    return root


@total_ordering
class _MavenKey:
    __slots__ = ("items",)

    def __init__(self, items: _List) -> None:
        self.items = items

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _MavenKey) and self.items.cmp(other.items) == 0

    def __lt__(self, other: _MavenKey) -> bool:
        return self.items.cmp(other.items) < 0

    def __hash__(self) -> int:  # equal keys (1.0, 1.0.0, 1-ga) must hash alike; collide rather
        return 0


# ---------------------------------------------------------------- the interface


def key(ecosystem: str, version: str) -> Any:
    """A sort key for `version` in `ecosystem`: keys of one ecosystem compare with `<` and `==`.
    Raises `VersionError` when the ecosystem is not supported or cannot read the version."""
    if not version or len(version) > MAX_VERSION_LENGTH:
        raise VersionError("no version" if not version else "version is too long")
    if ecosystem == "pypi":
        try:
            return (1, Version(version))
        except InvalidVersion:
            return (
                0,
                _legacy(version),
            )  # before every PEP 440 version, as pip and osv-scanner put it
    if ecosystem in ("npm", "go"):
        return _semver(version)
    if ecosystem == "maven":
        return _MavenKey(_maven_items(version))
    raise VersionError(f"versions are not compared for {ecosystem or 'unknown'} packages")


def compare(ecosystem: str, a: str, b: str) -> int:
    ka, kb = key(ecosystem, a), key(ecosystem, b)
    return 0 if ka == kb else (-1 if ka < kb else 1)


# ---------------------------------------------------------------- constraints ("<2.17.1")

_OPS = ("<=", ">=", "!=", "==", "<", ">", "=")
_CHECK = {
    "<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0,
    ">=": lambda c: c >= 0, "=": lambda c: c == 0, "!=": lambda c: c != 0,
}  # fmt: skip


@dataclass(frozen=True)
class Constraint:
    """All of `terms` must hold: `>=2.0,<2.17.1` is two terms. Written `?version=` in the API."""

    terms: tuple[tuple[str, str], ...]

    def __str__(self) -> str:
        return ",".join(f"{op}{v}" for op, v in self.terms)

    def check(self, ecosystem: str, version: str) -> bool:
        """Raises `VersionError` when `version` (or a bound) cannot be compared."""
        k = key(ecosystem, version)
        for op, bound in self.terms:
            b = key(ecosystem, bound)
            c = 0 if k == b else (-1 if k < b else 1)
            if not _CHECK[op](c):
                return False
        return True


def parse_constraint(text: str) -> Constraint:
    """`<2.17.1`, `>=2.0, <2.17.1`, `=1.2.3` or a bare `1.2.3` (exactly that version)."""
    terms: list[tuple[str, str]] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        op = next((o for o in _OPS if part.startswith(o)), "=")
        bound = part[len(op) :].strip() if part.startswith(op) else part
        if not bound or len(bound) > MAX_VERSION_LENGTH or re.search(r"[\s<>=!,]", bound):
            raise VersionError(f"{part!r} is not a version condition such as <2.17.1")
        terms.append(("=" if op == "==" else op, bound))
    if not terms:
        raise VersionError("no version condition given")
    if len(terms) > 4:
        raise VersionError("at most four version conditions")
    return Constraint(tuple(terms))


__all__ = [
    "SUPPORTED",
    "Constraint",
    "VersionError",
    "compare",
    "key",
    "parse_constraint",
]
