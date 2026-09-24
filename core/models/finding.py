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

    @staticmethod
    def hash_snippet(snippet: str) -> str:
        return "sha256:" + hashlib.sha256(snippet.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Taxonomy:
    category: Category
    cwe: tuple[str, ...] = ()
    owasp_top_10_2021: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()


@dataclass
class Scoring:
    native_severity: dict[str, str] = field(default_factory=dict)
    normalized_severity: Severity = Severity.INFO
    cvss_v3_1: float | None = None
    epss_score: float | None = None
    in_cisa_kev: bool = False
    reachable: bool | None = None
    risk_score: int | None = None
    confidence: float = 0.5


@dataclass
class Evidence:
    reported_by: list[str] = field(default_factory=list)
    agreement_count: int = 1
    rule_ids: dict[str, str] = field(default_factory=dict)


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
