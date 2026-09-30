"""The Hypotheses lane's output contract (plan §21.4): given one deterministic candidate (a route
with no recognized auth marker in a file where a sibling route has one), the model decides whether
the asymmetry is worth a person's time and, if so, writes the evidence and a suggested manual check.

    {"surface": bool, "evidence": str, "suggested_check": str, "confidence": "high"|"medium"|"low"}

`surface=false` is a normal, expected answer -- e.g. the route is a public health check, or the
"protected" siblings turn out to be unrelated -- and is never treated as an error; the caller simply
stores nothing for that candidate. Kept as a separate contract from both `core.llm.contract`
(remediation) and `core.triage_assistant.contract` (triage verdicts) for the same reason those two
are separate from each other: each one enforces a different promise about what a model may and may
not claim, and merging validators would risk one promise leaking into a call site it was never meant
to guard.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

Confidence = Literal["high", "medium", "low"]
FIELDS = ("surface", "evidence", "suggested_check", "confidence")
EVIDENCE_LIMIT = 1200
CHECK_LIMIT = 800
MAX_REPLY_CHARS = 8_000
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")
_FENCE = re.compile(r"\A```(?:json)?\s*\n(.*)\n```\s*\Z", re.S)
_CONFIDENCES: tuple[Confidence, ...] = ("high", "medium", "low")


class ContractError(ValueError):
    """The model's reply broke the contract. The message names the rule, never echoes the reply."""


@dataclass(frozen=True)
class HypothesisResult:
    surface: bool
    evidence: str
    suggested_check: str
    confidence: Confidence


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ContractError("duplicate key in JSON object")
        out[k] = v
    return out


def _reject_constant(name: str) -> object:
    raise ContractError(f"non-standard JSON constant {name}")


def parse_response(raw: str) -> HypothesisResult:
    if not isinstance(raw, str):
        raise ContractError("reply is not text")
    if len(raw) > MAX_REPLY_CHARS:
        raise ContractError("reply is far longer than any valid answer")
    text = raw.strip()
    if fenced := _FENCE.match(text):
        text = fenced.group(1).strip()
    if not text.startswith("{"):
        raise ContractError("reply is not a single JSON object")
    try:
        doc = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except json.JSONDecodeError:
        raise ContractError("reply is not valid JSON") from None
    if not isinstance(doc, dict):
        raise ContractError("reply is not a JSON object")
    extra = sorted(set(doc) - set(FIELDS))
    if extra:
        raise ContractError(f"unexpected field(s): {', '.join(k[:30] for k in extra[:5])}")
    missing = [k for k in FIELDS if k not in doc]
    if missing:
        raise ContractError(f"missing field(s): {', '.join(missing)}")

    surface = doc["surface"]
    if not isinstance(surface, bool):
        raise ContractError("surface must be a boolean")
    confidence = doc["confidence"]
    if confidence not in _CONFIDENCES:
        raise ContractError(f"confidence must be one of {_CONFIDENCES}")
    evidence = doc["evidence"]
    if not isinstance(evidence, str) or not evidence.strip():
        raise ContractError("evidence must be a non-empty string")
    if len(evidence) > EVIDENCE_LIMIT:
        raise ContractError(f"evidence is longer than {EVIDENCE_LIMIT} characters")
    if _CTRL.search(evidence):
        raise ContractError("evidence contains control characters")
    check = doc["suggested_check"]
    if not isinstance(check, str):
        raise ContractError("suggested_check must be a string")
    if len(check) > CHECK_LIMIT:
        raise ContractError(f"suggested_check is longer than {CHECK_LIMIT} characters")
    if _CTRL.search(check):
        raise ContractError("suggested_check contains control characters")
    if surface and not check.strip():
        raise ContractError("suggested_check must be non-empty when surface is true")
    return HypothesisResult(surface, evidence.strip(), check.strip(), confidence)
