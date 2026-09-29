"""Comparing "fixed version" strings a scanner reported (plan §20.5: "the smallest upgrade that
fixes it").

A scanner's own list of fixed versions is not always sorted, and is not always even a version: OSV
records sometimes list a git commit hash instead of a release when no tagged fix exists yet (see
`tests/golden/osv-scanner/expected.json`'s own flask entry, "Upgrade flask to
70f906c51ce49c485f1d355703e9cc3386b1cc2b or later."). Picking `fixed[0]` -- what
`core.adapters.osv_scanner` and `core.adapters.grype` both did before this -- is not "the
smallest," just "whichever the tool listed first."

This compares dotted-numeric versions only (the one thing semver and PEP 440 agree on), and
refuses to guess otherwise: mixing a real ordering with a git hash would produce a confidently
wrong answer, not a merely imprecise one.
"""

from __future__ import annotations


def _version_key(v: str) -> tuple[int, ...] | None:
    parts = v.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def smallest_safe_upgrade(fixed_versions: list[str]) -> str | None:
    """The lowest of `fixed_versions` when every one parses as dotted integers; `None` when the
    list is empty or any entry does not (a git hash, a prerelease tag) -- never a fabricated order.
    """
    keyed = [(k, v) for v in fixed_versions if (k := _version_key(v)) is not None]
    if len(keyed) != len(fixed_versions) or not keyed:
        return None
    return min(keyed)[1]


__all__ = ["smallest_safe_upgrade"]
