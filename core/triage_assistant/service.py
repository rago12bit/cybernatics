"""Generate a triage verdict for one finding (plan §21.3). Unlike `core.llm.service.suggest`, there
is no static fallback: a verdict with no model behind it would just be a fabricated opinion, so
`assess()` returns `None` when no model is configured or the call fails, and the caller (the API
endpoint) reports that plainly rather than inventing something to show.

Never touches `Finding.scoring`, `.triage` or `.taxonomy` -- the result is a separate object, same
separation `core.llm.service.suggest`'s docstring establishes for remediation, for the same reason:
whatever this returns must not be able to silently change what the finding already says about
itself.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from core.llm.client import LLMClient
from core.llm.prompt import CodeContext
from core.models import Finding
from core.triage_assistant.contract import ContractError, TriageVerdict, parse_response
from core.triage_assistant.prompt import build_prompt

log = logging.getLogger(__name__)

REPAIR_NOTE = (
    "Your previous reply did not match the required format. Reply again with exactly the single "
    "JSON object described in the system message: no markdown, no code fences, no other text."
)


@dataclass
class TriageAssessment:
    verdict: TriageVerdict
    model: str
    tokens_used: int
    warnings: list[str]


def assess(finding: Finding, client: LLMClient | None, code: CodeContext | None) -> (
    TriageAssessment | None
):  # fmt: skip
    """`None`: no model configured, or the model's reply never passed the contract (even after one
    repair attempt) -- both are reported by the caller as "no verdict available," never a guess."""
    if client is None:
        return None
    prompt = build_prompt(finding, code)
    warnings: list[str] = []
    if prompt.signals:
        warnings.append(
            "The scanned code contained text that looks like instructions to an AI "
            f"({', '.join(prompt.signals)}). It was treated as data."
        )
    if prompt.secrets_scrubbed:
        warnings.append(
            f"{prompt.secrets_scrubbed} possible secret(s) were removed before the code was sent."
        )
    if prompt.pii_redacted:
        warnings.append(
            f"{prompt.pii_redacted} possible personal detail(s) were redacted before sending."
        )
    tokens = 0
    try:
        completion = client.complete(prompt.system, prompt.user)
        tokens += completion.tokens
    except Exception as exc:  # noqa: BLE001 - any failure means "no verdict," never a crash
        log.warning("triage model call failed: %s", type(exc).__name__)
        return None
    try:
        verdict = parse_response(
            completion.text, first_line=prompt.first_line, last_line=prompt.last_line
        )
    except ContractError as exc:
        log.warning("triage reply rejected, attempting one repair: %s", exc)
        try:
            repair = client.complete(prompt.system, prompt.user + "\n\n" + REPAIR_NOTE)
            tokens += repair.tokens
            verdict = parse_response(
                repair.text, first_line=prompt.first_line, last_line=prompt.last_line
            )
        except Exception as exc2:  # noqa: BLE001 - repair failed too: no verdict, not a guess
            log.warning("triage repair attempt also rejected: %s", exc2)
            return None
    return TriageAssessment(verdict, client.model, tokens, warnings)
