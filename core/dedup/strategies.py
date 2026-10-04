"""What makes two findings from one source the same Issue (plan §42.3).

Pure functions, no database. A strategy turns a Finding into a *key*; findings with equal keys are
one Issue. `fingerprint_v2` is the key every Finding already carries
(`core.correlation.fingerprint`, location-independent for code), so it is the default and applying
it changes nothing; the others trade precision for stability:

- `fingerprint_v2`: the existing fingerprint (CWE, place, snippet, rule); SAST, where code moves.
- `tool_id`: the scanner's rule id and where (file, URL, package); tools with stable ids.
- `hash_fields`: a hash of chosen fields; tools without stable ids.
- `tool_id_or_hash`: `tool_id`, or `hash_fields` for a finding with no rule id; mixed quality.
- `package`: ecosystem, package, version, vulnerability id; SCA and advisories. It is
  `fingerprint_v2` for an SCA finding (its fingerprint already is that key), selectable so a package
  source's setting says what it means.

A non-default key is namespaced (`dd1:<strategy>:<sha256>`): it can never collide with a
fingerprint, and the `1` is the version of this key scheme, so the scheme itself can change later
without silently matching old keys.
"""

from __future__ import annotations

import hashlib
from typing import Final

from core.models import Finding

STRATEGIES: Final = ("fingerprint_v2", "tool_id", "hash_fields", "tool_id_or_hash", "package")
DEFAULT: Final = "fingerprint_v2"
KEY_PREFIX: Final = "dd1:"

# The fields `hash_fields` may use (a closed list: a free-form field name would make a setting a
# way to read anything off a finding, and the dry run could not explain it).
FIELDS: Final = (
    "title", "severity", "cwe", "rule", "path", "line", "host", "route", "package", "version",
    "ecosystem", "cve", "category",
)  # fmt: skip
DEFAULT_HASH_FIELDS: Final = ("title", "path", "cwe")

RECOMMENDED: Final = {
    "sast": "fingerprint_v2", "secrets": "fingerprint_v2", "iac": "fingerprint_v2",
    "sca": "package", "container": "package", "dast": "tool_id",
}  # fmt: skip


def source_of(f: Finding) -> str:
    """The tool a finding came from: the first of `evidence.reported_by` ("zap", "nessus",
    "semgrep"). A finding two tools agreed on is keyed under whichever the correlation put first,
    which is why a strategy is chosen per source and applied to what that source reported."""
    return f.evidence.reported_by[0] if f.evidence.reported_by else "unknown"


def _rules(f: Finding) -> list[str]:
    return sorted({r for rs in f.evidence.rule_ids.values() for r in rs})


def _place(f: Finding) -> str:
    if f.package:
        return f"{f.package.ecosystem}:{f.package.name}"
    if f.location.host or f.location.route:
        return f"{f.location.host}{f.location.route}"
    return f.location.path


def _field(f: Finding, name: str) -> str:
    if name == "title":
        return " ".join(f.title.lower().split())
    values = {
        "severity": f.scoring.normalized_severity.value,
        "cwe": ",".join(sorted(f.taxonomy.cwe)),
        "rule": ",".join(_rules(f)),
        "path": f.location.path,
        "line": str(f.location.start_line),
        "host": f.location.host,
        "route": f.location.route,
        "package": f.package.name if f.package else "",
        "version": f.package.version if f.package else "",
        "ecosystem": f.package.ecosystem if f.package else "",
        "cve": ",".join(sorted(f.taxonomy.cve)),
        "category": f.taxonomy.category.value,
    }
    return values[name]


def _digest(strategy: str, raw: str) -> str:
    return f"{KEY_PREFIX}{strategy}:{hashlib.sha256(raw.encode()).hexdigest()}"


def validate(strategy: str, fields: tuple[str, ...] = ()) -> tuple[str, ...]:
    """The fields a setting will use, or ValueError saying what is wrong with it."""
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy!r}; one of {', '.join(STRATEGIES)}")
    bad = [f for f in fields if f not in FIELDS]
    if bad:
        raise ValueError(f"unknown field(s) {bad}; allowed: {', '.join(FIELDS)}")
    if fields and strategy not in ("hash_fields", "tool_id_or_hash"):
        raise ValueError(f"{strategy} takes no fields")
    if strategy == "hash_fields" and not fields:
        raise ValueError("hash_fields needs at least one field")
    return tuple(dict.fromkeys(fields))


def key_for(strategy: str, f: Finding, fields: tuple[str, ...] = ()) -> str:
    """The key `strategy` gives `f`: its own fingerprint for the default (and for `package` on a
    finding that is not a package), a namespaced digest otherwise."""
    fields = validate(strategy, fields)
    if strategy in ("fingerprint_v2", "package"):
        # An SCA fingerprint already is ecosystem|package|version|vulnerability id (ADR-0004), so
        # `package` names what that default means for a package source -- it changes no key. A
        # finding that is not a package keeps its fingerprint under it too.
        return f.fingerprint
    rules = _rules(f)
    if strategy == "tool_id" or (strategy == "tool_id_or_hash" and rules):
        raw = (
            f"{f.taxonomy.category.value}|{source_of(f)}|{','.join(rules) or 'no-rule'}|{_place(f)}"
        )
        return _digest("tool_id", raw)
    use = fields or DEFAULT_HASH_FIELDS
    return _digest("hash_fields", "|".join(f"{n}={_field(f, n)}" for n in sorted(use)))


def is_namespaced(key: str) -> bool:
    return key.startswith(KEY_PREFIX)


def describe(strategy: str) -> str:
    return {
        "fingerprint_v2": "the location-independent fingerprint (CWE, place, snippet, rule)",
        "tool_id": "the scanner's own rule id, and where it was found",
        "hash_fields": "a hash of the fields you choose",
        "tool_id_or_hash": "the rule id and place, or chosen fields when a finding has no rule id",
        "package": "ecosystem, package, version and vulnerability id",
    }[strategy]


__all__ = ["DEFAULT", "FIELDS", "STRATEGIES", "describe", "key_for", "source_of", "validate"]
