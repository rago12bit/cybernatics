"""Canonical Finding model (design doc §4.2). Every adapter emits these."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    CONTAINER = "container"
    DAST = "dast"


class TriageState(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int
    snippet: str = ""
    snippet_hash: str = ""
    # Set only for a DAST finding (plan §22.4, Week 49 task 3): the URL path the live scanner hit
    # ("/admin/users"), as opposed to `path`'s filesystem meaning everywhere else. Kept as a
    # distinct field rather than overloading `path` so a DAST Finding and the SAST Finding it may
    # correlate against (Week 49 task 4, "same route+CWE") can both be read without a category
    # check first.
    route: str = ""
    # Set only for a DAST or network finding: which target it was found on -- `scheme://host:port`
    # for a web target, the bare host or IP for a network scan -- so the same route on two hosts
    # ("/login" on staging and on production) is two defects, not one. Empty everywhere else.
    host: str = ""

    @staticmethod
    def hash_snippet(snippet: str) -> str:
        return "sha256:" + hashlib.sha256(snippet.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TaintPathStep:
    """One step of a concrete taint path (plan §20.3/§28.3): "the input gets there" one hop at a
    time, source to sink. `is_sink` marks the last step -- the UI's own arrow marker (§28.3's
    mockup: "cursor.execute(q) ◄"). `snippet` is captured from the scanned workspace while it still
    exists (`core.taint.reachability.attach_taint_paths` reads it at scan time), so the UI's code
    view has something real to show for every step, not only the sink's own location."""

    path: str
    line: int
    description: str
    is_sink: bool = False
    snippet: str = ""


@dataclass(frozen=True)
class Taxonomy:
    category: Category
    cwe: tuple[str, ...] = ()
    owasp_top_10_2021: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()  # every vulnerability id seen (CVE, GHSA, PYSEC, ...)


_ECOSYSTEMS = {
    "pypi": "pypi", "pip": "pypi", "poetry": "pypi", "pipenv": "pypi",
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "go": "go", "gomod": "go", "golang": "go",
    "cargo": "cargo", "crates.io": "cargo", "rustcrates": "cargo",
    "rubygems": "rubygems", "bundler": "rubygems", "gem": "rubygems",
    "maven": "maven", "pom": "maven", "jar": "maven", "gradle": "maven",
    "packagist": "packagist", "composer": "packagist",
    "nuget": "nuget",
}  # fmt: skip


@dataclass(frozen=True)
class Package:
    """Affected dependency (SCA). Ecosystem is normalized so tools agree on identity (ADR-004)."""

    name: str
    version: str
    ecosystem: str
    license: str = ""  # "" until a license is resolved (Week 40) -- never a fabricated "unknown"

    @staticmethod
    def normalize_ecosystem(raw: str) -> str:
        return _ECOSYSTEMS.get(raw.strip().lower(), raw.strip().lower())


@dataclass
class Scoring:
    native_severity: dict[str, str] = field(default_factory=dict)
    normalized_severity: Severity = Severity.INFO
    cvss_v3_1: float | None = None
    epss_score: float | None = None
    in_cisa_kev: bool = False
    reachable: bool | None = None
    risk_score: int | None = None
    risk_factors: list[str] = field(default_factory=list)  # why the score is what it is
    confidence: float = 0.5


@dataclass
class Evidence:
    reported_by: list[str] = field(default_factory=list)
    agreement_count: int = 1
    rule_ids: dict[str, list[str]] = field(default_factory=dict)  # tool -> rules that fired


@dataclass
class Remediation:
    summary: str = ""
    suggested_patch: str | None = None
    references: list[str] = field(default_factory=list)
    generated_by: str = "static"  # "static" | "llm"
    is_suggestion: bool = True


@dataclass
class Triage:
    state: TriageState = TriageState.OPEN
    user_marked_false_positive: bool = False
    suppression_reason: str | None = None


@dataclass
class Finding:
    id: str
    title: str
    description: str
    location: Location
    taxonomy: Taxonomy
    scoring: Scoring = field(default_factory=Scoring)
    evidence: Evidence = field(default_factory=Evidence)
    remediation: Remediation = field(default_factory=Remediation)
    triage: Triage = field(default_factory=Triage)
    fingerprint: str = ""
    package: Package | None = None
    taint_path: tuple[TaintPathStep, ...] = ()  # empty: no concrete path found (not "unreachable")

    def to_dict(self) -> dict[str, Any]:
        def default(obj: Any) -> Any:
            return obj.value if isinstance(obj, Enum) else obj

        result: dict[str, Any] = _walk(asdict(self), default)
        return result


def _walk(obj: Any, default: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _walk(v, default) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_walk(v, default) for v in obj]
    return default(obj)


def finding_from_dict(d: dict[str, Any]) -> Finding:
    """Inverse of Finding.to_dict(); used to carry Findings across process boundaries (Celery)."""
    tax = d["taxonomy"]
    sc = d["scoring"]
    pkg = d.get("package")
    return Finding(
        id=d["id"],
        title=d["title"],
        description=d["description"],
        location=Location(**d["location"]),
        taxonomy=Taxonomy(
            Category(tax["category"]),
            cwe=tuple(tax["cwe"]),
            owasp_top_10_2021=tuple(tax["owasp_top_10_2021"]),
            cve=tuple(tax["cve"]),
            aliases=tuple(tax.get("aliases", ())),
        ),
        scoring=Scoring(
            **{**sc, "normalized_severity": Severity(sc["normalized_severity"])},
        ),
        evidence=Evidence(**d["evidence"]),
        remediation=Remediation(**d["remediation"]),
        triage=Triage(**{**d["triage"], "state": TriageState(d["triage"]["state"])}),
        fingerprint=d.get("fingerprint", ""),
        package=Package(**pkg) if pkg else None,
        taint_path=tuple(TaintPathStep(**step) for step in d.get("taint_path", ())),
    )
