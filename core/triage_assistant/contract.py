"""The triage assistant's output contract (plan §21.3): a model reads one finding's taint path and
surrounding code and returns a verdict -- untrusted input until it passes every check here, same
posture as `core.llm.contract` for remediation replies.

    {"verdict": "likely_real" | "likely_false_positive" | "unsure",
     "confidence": "high" | "medium" | "low",
     "rationale": str,
     "supporting_lines": [int, ...]}

Deliberately a SEPARATE contract from `core.llm.contract.parse_response`, not a shared one, even
though both validate a small JSON object from a model: remediation's contract exists specifically
to REJECT dismissal language ("false positive", "safe to ignore") because a fix suggestion must
never suppress a finding. The triage assistant's entire job is to say exactly that when it believes
it, so reusing the same validator would mean punching a hole in the one guarantee it exists to
enforce. Structural separation -- two contracts, two call sites -- is what lets both promises hold
at once: fix suggestions can never dismiss a finding, and triage verdicts always can, because they
live behind different code paths that were never merged.

`supporting_lines` is checked against the code range the model was actually shown
(`parse_response` takes `first_line`/`last_line`): a model citing a line it was never shown is a
hallucinated citation, rejected whole like everything else here, not silently clipped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

Verdict = Literal["likely_real", "likely_false_positive", "unsure"]
Confidence = Literal["high", "medium", "low"]
FIELDS = ("verdict", "confidence", "rationale", "supporting_lines")
RATIONALE_LIMIT = 1000
MAX_SUPPORTING_LINES = 15
MAX_REPLY_CHARS = 8_000
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")  # incl. bidi
_FENCE = re.compile(r"\A```(?:json)?\s*\n(.*)\n```\s*\Z", re.S)
_VERDICTS: tuple[Verdict, ...] = ("likely_real", "likely_false_positive", "unsure")
_CONFIDENCES: tuple[Confidence, ...] = ("high", "medium", "low")


class ContractError(ValueError):
    """The model's reply broke the contract. The message names the rule, never echoes the reply."""


@dataclass(frozen=True)
class TriageVerdict:
    verdict: Verdict
    confidence: Confidence
    rationale: str
    supporting_lines: tuple[int, ...]


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ContractError("duplicate key in JSON object")
        out[k] = v
    return out


def _reject_constant(name: str) -> object:
    raise ContractError(f"non-standard JSON constant {name}")


def parse_response(raw: str, *, first_line: int, last_line: int) -> TriageVerdict:
    """`first_line`/`last_line`: the inclusive range of code the model was actually shown -- any
    `supporting_lines` entry outside it is rejected as a hallucinated citation."""
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

    verdict = doc["verdict"]
    if verdict not in _VERDICTS:
        raise ContractError(f"verdict must be one of {_VERDICTS}")
    confidence = doc["confidence"]
    if confidence not in _CONFIDENCES:
        raise ContractError(f"confidence must be one of {_CONFIDENCES}")
    rationale = doc["rationale"]
    if not isinstance(rationale, str) or not rationale.strip():
        raise ContractError("rationale must be a non-empty string")
    if len(rationale) > RATIONALE_LIMIT:
        raise ContractError(f"rationale is longer than {RATIONALE_LIMIT} characters")
    if _CTRL.search(rationale):
        raise ContractError("rationale contains control characters")

    lines = doc["supporting_lines"]
    if not isinstance(lines, list) or not (1 <= len(lines) <= MAX_SUPPORTING_LINES):
        raise ContractError(f"supporting_lines must be a list of 1-{MAX_SUPPORTING_LINES} integers")
    checked: list[int] = []
    for ln in lines:
        if not isinstance(ln, int) or isinstance(ln, bool):
            raise ContractError("supporting_lines must contain only integers")
        if not (first_line <= ln <= last_line):
            raise ContractError(
                f"supporting_lines cites line {ln}, outside the {first_line}-{last_line} range "
                "shown to the model"
            )
        checked.append(ln)
    return TriageVerdict(verdict, confidence, rationale.strip(), tuple(checked))
