"""The output contract: a model's reply is untrusted input until it passes every check here.

    {"explanation": str, "impact": str, "fix_summary": str, "suggested_patch": str | null,
     "confidence": "high" | "medium" | "low"}

Anything else is rejected whole, never repaired or partially used (the caller then shows the static CWE
text instead). In particular a reply may not carry extra keys, so a model that was talked into adding
`"severity": "LOW"` or `"suppress": true` produces nothing usable, and it may not argue that the finding is
not real: dismissal is a deterministic decision made upstream, not an LLM's (design doc 7.1).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

Confidence = Literal["high", "medium", "low"]
FIELDS = ("explanation", "impact", "fix_summary", "suggested_patch", "confidence")
LIMITS = {"explanation": 1500, "impact": 800, "fix_summary": 1200, "suggested_patch": 6000}
MAX_PATCH_LINES = 120
MAX_REPLY_CHARS = 20_000  # the five fields at their limits fit in well under this
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")  # incl. bidi overrides
_FENCE = re.compile(r"\A```(?:json)?\s*\n(.*)\n```\s*\Z", re.S)
_DISMISS = re.compile(
    r"(?i)\b(?:false[- ]positive|not\s+(?:actually\s+)?(?:a\s+)?(?:real\s+)?(?:vulnerab|security\s+(?:issue|risk|problem))"
    r"|no\s+(?:real\s+)?(?:vulnerabilit|security\s+(?:issue|risk))|safe\s+to\s+(?:ignore|dismiss|suppress)"
    r"|can\s+be\s+(?:safely\s+)?(?:ignored|dismissed|suppressed)|does\s+not\s+(?:need|require)\s+(?:to\s+be\s+)?(?:fix|attention))"
)
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class ContractError(ValueError):
    """The model's reply broke the contract. The message names the rule, never echoes the reply."""


@dataclass(frozen=True)
class Suggestion:
    explanation: str
    impact: str
    fix_summary: str
    suggested_patch: str | None
    confidence: Confidence


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ContractError("duplicate key in JSON object")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise ContractError(f"non-standard JSON constant {name}")


def _norm_path(p: str) -> str:
    p = p.strip().split("\t")[0]
    for prefix in ("a/", "b/"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
    return p


def validate_patch(patch: str, path: str) -> None:
    """A unified diff for exactly one existing file (the finding's), small, with consistent hunks."""
    lines = patch.splitlines()
    if len(lines) > MAX_PATCH_LINES:
        raise ContractError(f"patch longer than {MAX_PATCH_LINES} lines")
    if len(lines) < 4 or not lines[0].startswith("--- ") or not lines[1].startswith("+++ "):
        raise ContractError("patch is not a unified diff (needs ---/+++ headers)")
    old, new = _norm_path(lines[0][4:]), _norm_path(lines[1][4:])
    for p in (old, new):
        if p == "/dev/null":
            raise ContractError("patch may not create or delete files")
        if p.startswith("/") or ".." in p.split("/") or "\\" in p:
            raise ContractError("patch path is not a plain relative path")
    if old != new or old != path:
        raise ContractError("patch must modify only the file the finding is in")
    i, hunks = 2, 0
    while i < len(lines):
        m = _HUNK.match(lines[i])
        if not m:
            raise ContractError("expected a hunk header (@@ -a,b +c,d @@)")
        want_old, want_new = int(m.group(2) or 1), int(m.group(4) or 1)
        got_old = got_new = 0
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            tag = lines[i][:1]
            if tag == " ":
                got_old += 1
                got_new += 1
            elif tag == "-":
                got_old += 1
            elif tag == "+":
                got_new += 1
            elif tag == "\\" or lines[i] == "":
                pass  # "\\ No newline at end of file", or a blank context line stripped of its space
            else:
                raise ContractError("patch line does not start with ' ', '+', '-' or '@@'")
            i += 1
        if (got_old, got_new) != (want_old, want_new):
            raise ContractError("hunk line counts do not match its header")
        hunks += 1
    if hunks == 0:
        raise ContractError("patch has no hunks")


def parse_response(raw: str, *, path: str) -> Suggestion:
    """Validate a model reply for a finding in `path`. Raises ContractError; never returns partial data."""
    if not isinstance(raw, str):
        raise ContractError("reply is not text")
    if len(raw) > MAX_REPLY_CHARS:
        raise ContractError("reply is far longer than any valid answer")
    text = raw.strip()
    if fenced := _FENCE.match(text):  # tolerate exactly one ```json fence around the whole reply
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

    strings: dict[str, str] = {}
    for key in ("explanation", "impact", "fix_summary"):
        v = doc[key]
        if not isinstance(v, str) or not v.strip():
            raise ContractError(f"{key} must be a non-empty string")
        if len(v) > LIMITS[key]:
            raise ContractError(f"{key} is longer than {LIMITS[key]} characters")
        if _CTRL.search(v):
            raise ContractError(f"{key} contains control characters")
        if _DISMISS.search(v):
            raise ContractError(f"{key} tries to dismiss the finding")
        strings[key] = v.strip()
    conf = doc["confidence"]
    if conf not in ("high", "medium", "low"):
        raise ContractError("confidence must be high, medium or low")
    patch = doc["suggested_patch"]
    if patch is not None:
        if not isinstance(patch, str):
            raise ContractError("suggested_patch must be a string or null")
        if not patch.strip():
            patch = None
        else:
            if len(patch) > LIMITS["suggested_patch"]:
                raise ContractError("suggested_patch is too long")
            if _CTRL.search(patch.replace("\t", " ")):
                raise ContractError("suggested_patch contains control characters")
            validate_patch(patch, path)
            patch = patch.rstrip("\n") + "\n"
    return Suggestion(
        strings["explanation"], strings["impact"], strings["fix_summary"], patch, conf
    )
