"""The priority engine (plan §44.3, Week 63): v2's explainable risk score, made a policy.

Every factor is a multiplier relative to "no effect" (1.0), and a project's weight for it is an
exponent: `multiplier ** weight`. So a weight of 1 is the factor as designed, 0 ignores it, and 2
doubles its pull in either direction -- a damper damps harder, a boost boosts harder. Known
exploitation (CISA KEV) is the exception: it is a floor, `90 x weight` (80 x weight when nothing
imports the package), as v2's was.

    score = 100 x severity^w x likelihood^w x reachability^w x taint^w x runtime^w x path^w
                x internet-facing^w x data sensitivity^w x criticality^w      (rounded)
    score = score x assistant^w                                                (rounded)
    score = max(score, KEV floor);  at most 100

`likelihood` comes from one place per finding, and that place's weight applies: KEV (then 1.0),
else EPSS, else "no exploit data" for a dependency (0.3), else -- code, secrets, IaC -- the merged
confidence from tool agreement. The arithmetic, factor order and rounding are v2's
(`core.risk.score`), so `V2_WEIGHTS` -- the new factors at 0, the business context unset -- gives
the v2 score (a test holds this). A project without a saved policy simply keeps the v2 score stored
on each occurrence; `STARTER` (everything at 1) is offered, not imposed.

The business context is per project, so inside one project it scales every Issue alike: it moves
scores and bands (and so SLA deadlines by priority band), not the order. It matters across
projects: a payments service and an internal wiki should not rank the same issue the same way (plan
C17). It only lowers scores -- unset is the worst case -- so it can never inflate a project into P1.

Pure: no database, no network. `core.priority.service` stores the result on each Issue.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from core.models import Severity
from core.reachability.index import TEST_DIRS, _is_test_name
from core.risk.score import (
    _FALSE_POSITIVE_FACTOR,
    _LIKELY_REAL_FACTOR,
    KEV_FLOOR,
    SEVERITY_IMPACT,
    UNKNOWN_LIKELIHOOD,
    UNREACHED_FACTOR,
    UNREACHED_KEV_FLOOR,
    epss_likelihood,
)

MAX_WEIGHT = 3.0
TAINT_BOOST = 1.1  # a concrete path from a real HTTP entrypoint to the sink
RUNTIME_BOOST = 1.25  # a real request reached it (DAST, plan §22.4)
NON_PRODUCTION_PATH = 0.6  # test, example, documentation or vendored code

# The business context only lowers a score: "not set" assumes the worst (internet-facing, restricted
# data, critical), so a project nobody described is never under-ranked, and describing one can only
# calm it down. Boosts instead would push hundreds of Issues to 100 and P1 at once (measured on a
# 2,500-Issue project in the Week 63 browser run: 770 in P1, the whole top 50 tied at 100).
INTERNET_FACING = {True: 1.0, False: 0.8}
DATA_SENSITIVITY = {"public": 0.65, "internal": 0.8, "confidential": 0.9, "restricted": 1.0}
CRITICALITY = {"low": 0.65, "medium": 0.8, "high": 0.9, "critical": 1.0}

# P1 is "fix first". Fixed thresholds for now; the SLA's priority bands key on them.
BANDS = (("P1", 80), ("P2", 60), ("P3", 30), ("P4", 0))
BAND_NAMES = tuple(b for b, _ in BANDS)

_OTHER_NON_PROD_DIRS = frozenset(
    "example examples sample samples demo demos doc docs vendor vendored third_party "
    "node_modules".split()
)


@dataclass(frozen=True)
class Factor:
    key: str
    label: str
    description: str


FACTORS: tuple[Factor, ...] = (
    Factor("severity", "Severity",
           "How bad it is if exploited: the CVSS score when known, otherwise the severity."),
    Factor("epss", "Chance of exploitation (EPSS)",
           "For dependencies: the EPSS probability of exploitation in the next 30 days, or "
           "'unknown' when there is no exploit data."),
    Factor("kev", "Known exploited (CISA KEV)",
           "Listed in CISA's catalogue of vulnerabilities exploited in the wild: a guaranteed "
           "minimum of 90 x the weight."),
    Factor("reachability", "Not reachable",
           "Nothing in the application imports the vulnerable package (or only tests do)."),
    Factor("taint", "Taint path confirmed",
           "A concrete path from a real HTTP entrypoint to the vulnerable call."),
    Factor("runtime", "Confirmed at runtime",
           "A DAST scan reached the same route and weakness with a real request."),
    Factor("agreement", "Tool agreement",
           "For code, secrets and IaC: how many scanners agree, and how confident they are."),
    Factor("path", "Path context",
           "Test, example, documentation or vendored code counts for less."),
    Factor("assistant", "Triage assistant",
           "The AI triage assistant's verdict: a bounded nudge, never a suppression."),
    Factor("internet_facing", "Internet-facing",
           "Internal-only projects count for less. Not set: treated as internet-facing."),
    Factor("data_sensitivity", "Data sensitivity",
           "Projects handling less sensitive data count for less. Not set: treated as restricted."),
    Factor("criticality", "Business criticality",
           "Less critical projects count for less. Not set: treated as critical."),
)  # fmt: skip
FACTOR_KEYS = tuple(f.key for f in FACTORS)
_LABEL = {f.key: f.label for f in FACTORS}

STARTER: dict[str, float] = dict.fromkeys(FACTOR_KEYS, 1.0)
# v2, exactly: the factors v2 never had are off.
V2_WEIGHTS: dict[str, float] = {**STARTER, "taint": 0.0, "runtime": 0.0, "path": 0.0}


class PolicyError(ValueError):
    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name


@dataclass(frozen=True)
class Context:
    """The project's business context; `None` is "not set", which has no effect."""

    internet_facing: bool | None = None
    data_sensitivity: str | None = None
    criticality: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "internet_facing": self.internet_facing,
            "data_sensitivity": self.data_sensitivity,
            "criticality": self.criticality,
        }


def parse_weights(raw: Any) -> dict[str, float]:
    """Every factor present, each 0 to 3, rounded to two places; missing ones take the starter."""
    if not isinstance(raw, dict):
        raise PolicyError("weights", "weights maps each factor to a number from 0 to 3")
    unknown = sorted(set(map(str, raw)) - set(FACTOR_KEYS))
    if unknown:
        raise PolicyError("weights", f"unknown factor: {', '.join(unknown)}")
    out: dict[str, float] = {}
    for key in FACTOR_KEYS:
        v = raw.get(key, STARTER[key])
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            raise PolicyError(f"weights.{key}", f"{_LABEL[key]}: the weight is a number")
        if not 0 <= v <= MAX_WEIGHT:
            raise PolicyError(f"weights.{key}", f"{_LABEL[key]}: the weight is 0 to {MAX_WEIGHT:g}")
        out[key] = round(float(v), 2)
    return out


def parse_context(raw: Any) -> Context:
    if raw is None:
        return Context()
    if not isinstance(raw, dict):
        raise PolicyError("context", "context has internet_facing, data_sensitivity, criticality")
    unknown = sorted(set(map(str, raw)) - {"internet_facing", "data_sensitivity", "criticality"})
    if unknown:
        raise PolicyError("context", f"unknown context field: {', '.join(unknown)}")
    facing = raw.get("internet_facing")
    if facing is not None and not isinstance(facing, bool):
        raise PolicyError("context.internet_facing", "Internet-facing is yes, no, or not set")
    sens, crit = raw.get("data_sensitivity") or None, raw.get("criticality") or None
    if sens is not None and sens not in DATA_SENSITIVITY:
        raise PolicyError(
            "context.data_sensitivity",
            f"Data sensitivity is one of {', '.join(DATA_SENSITIVITY)}, or not set",
        )
    if crit is not None and crit not in CRITICALITY:
        raise PolicyError(
            "context.criticality", f"Criticality is one of {', '.join(CRITICALITY)}, or not set"
        )
    return Context(facing, sens, crit)


@dataclass(frozen=True)
class Signals:
    """What the engine reads about one Issue: its latest occurrence's stored Finding, plus the
    Issue's own runtime confirmation and assistant verdict. Everything here is stored at scan time,
    so a recomputation needs no scanner, feed download or network."""

    severity: str
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    has_cve: bool = False
    dependency: bool = False
    confidence: float = 0.5
    agreement: int = 1
    reachable: bool | None = None
    reach_reason: str | None = None
    taint: bool = False
    runtime: bool = False
    path: str = ""
    verdict: str | None = None
    verdict_confidence: str | None = None

    @classmethod
    def from_finding(
        cls,
        data: dict[str, Any],
        *,
        runtime: bool = False,
        verdict: str | None = None,
        verdict_confidence: str | None = None,
    ) -> Signals:
        sc = data.get("scoring") or {}
        tax = data.get("taxonomy") or {}
        ids = [str(c).upper() for c in (*tax.get("cve", ()), *tax.get("aliases", ()))]
        reasons = [r for r in sc.get("risk_factors") or () if "reach" in r.lower()]
        return cls(
            severity=str(sc.get("normalized_severity") or "INFO").upper(),
            cvss=sc.get("cvss_v3_1"),
            epss=sc.get("epss_score"),
            kev=bool(sc.get("in_cisa_kev")),
            has_cve=any(c.startswith("CVE-") for c in ids),
            dependency=tax.get("category") == "sca",
            confidence=float(sc.get("confidence", 0.5)),
            agreement=int((data.get("evidence") or {}).get("agreement_count") or 1),
            reachable=sc.get("reachable"),
            reach_reason=reasons[-1] if reasons else None,
            taint=bool(data.get("taint_path")),
            runtime=runtime,
            path=str((data.get("location") or {}).get("path") or ""),
            verdict=verdict,
            verdict_confidence=verdict_confidence,
        )


@dataclass(frozen=True)
class Contribution:
    factor: str
    weight: float
    effect: float  # the multiplier applied, after the weight; for KEV, the floor
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor": self.factor,
            "label": _LABEL[self.factor],
            "weight": self.weight,
            "effect": round(self.effect, 3),
            "text": self.text,
        }


@dataclass(frozen=True)
class Priority:
    score: int
    band: str
    factors: list[Contribution] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "factors": [c.to_dict() for c in self.factors],
        }


def band_of(score: int | None) -> str | None:
    if score is None:
        return None
    return next(name for name, at_least in BANDS if score >= at_least)


def non_production(path: str) -> str | None:
    """'test' or 'other' (examples, docs, vendored code) when the path says so; else None."""
    p = PurePosixPath(path.replace("\\", "/").lstrip("./"))
    dirs = [d.lower() for d in p.parts[:-1]]
    if any(d in TEST_DIRS for d in dirs) or _is_test_name(p.name):
        return "test"
    if any(d in _OTHER_NON_PROD_DIRS for d in dirs):
        return "other"
    return None


def _pow(m: float, w: float) -> float:
    return float(m**w)


def score(sig: Signals, weights: dict[str, float], context: Context | None = None) -> Priority:
    context = context or Context()
    w = weights
    out: list[Contribution] = []

    def add(key: str, effect: float, text: str) -> None:
        out.append(Contribution(key, w[key], effect, text))

    # Impact.
    if sig.cvss is not None:
        impact = min(max(float(sig.cvss), 0.0), 10.0) / 10
        what = f"CVSS {sig.cvss:g}"
    else:
        sev = Severity(sig.severity) if sig.severity in Severity.__members__ else Severity.INFO
        impact = SEVERITY_IMPACT[sev]
        what = f"{sev.value.title()} severity"
    impact_t = _pow(impact, w["severity"])
    add("severity", impact_t, what)

    # Likelihood: one source, and that source's weight.
    kev = sig.kev and w["kev"] > 0
    if kev:
        lik_t = 1.0
        add("kev", 1.0, "In CISA KEV: exploited in the wild")
    elif sig.epss is not None:
        lik_t = _pow(0.5 + 0.5 * epss_likelihood(sig.epss), w["epss"])
        add("epss", lik_t, f"EPSS {sig.epss:.1%}: chance of exploitation in the next 30 days")
    elif sig.has_cve or sig.dependency:
        lik_t = _pow(0.5 + 0.5 * UNKNOWN_LIKELIHOOD, w["epss"])
        why = "No exploit data" if sig.has_cve else "No CVE id to look up exploit data"
        add("epss", lik_t, why)
    else:
        conf = min(max(sig.confidence, 0.0), 1.0)
        lik_t = _pow(0.5 + 0.5 * conf, w["agreement"])
        n = sig.agreement
        add(
            "agreement",
            lik_t,
            f"Flagged by {n} scanner{'s' if n != 1 else ''}, confidence {conf:.0%}",
        )

    unreached = sig.reachable is False
    reach_t = _pow(UNREACHED_FACTOR, w["reachability"]) if unreached else 1.0
    if sig.reachable is not None:
        add(
            "reachability",
            reach_t,
            sig.reach_reason or ("Not reachable" if unreached else "Reachable"),
        )

    raw = 100 * impact_t * lik_t * reach_t
    if sig.taint and w["taint"] > 0:
        m = _pow(TAINT_BOOST, w["taint"])
        raw *= m
        add("taint", m, "A concrete path from an HTTP entrypoint reaches it")
    if sig.runtime and w["runtime"] > 0:
        m = _pow(RUNTIME_BOOST, w["runtime"])
        raw *= m
        add("runtime", m, "Confirmed at runtime by a DAST scan")
    where = non_production(sig.path)
    if where and w["path"] > 0:
        m = _pow(NON_PRODUCTION_PATH, w["path"])
        raw *= m
        add("path", m, "In test code" if where == "test" else "In example, docs or vendored code")
    for key, table, value, text in (
        ("internet_facing", INTERNET_FACING, context.internet_facing, "Internal only"),
        ("data_sensitivity", DATA_SENSITIVITY, context.data_sensitivity,
         f"Handles {context.data_sensitivity} data"),
        ("criticality", CRITICALITY, context.criticality,
         f"{str(context.criticality).title()} business criticality"),
    ):  # fmt: skip
        if value is None or w[key] == 0 or table[value] == 1.0:  # type: ignore[index]
            continue
        m = _pow(table[value], w[key])  # type: ignore[index]
        raw *= m
        add(key, m, text)

    result = round(raw)
    if sig.verdict in ("likely_false_positive", "likely_real") and sig.verdict_confidence:
        fp = sig.verdict == "likely_false_positive"
        table = _FALSE_POSITIVE_FACTOR if fp else _LIKELY_REAL_FACTOR
        base = table.get(sig.verdict_confidence)
        if base is not None and w["assistant"] > 0:
            m = _pow(base, w["assistant"])
            result = round(result * m)
            add(
                "assistant",
                m,
                f"Triage assistant: {sig.verdict.replace('_', ' ')} "
                f"({sig.verdict_confidence} confidence)",
            )
    if kev:
        floor = min(100, round((UNREACHED_KEV_FLOOR if unreached else KEV_FLOOR) * w["kev"]))
        if floor > result:
            out = [
                (
                    Contribution(c.factor, c.weight, float(floor), f"{c.text}: at least {floor}")
                    if c.factor == "kev"
                    else c
                )
                for c in out
            ]
        result = max(result, floor)
    result = min(result, 100)
    band = band_of(result)
    assert band is not None
    return Priority(result, band, out)
