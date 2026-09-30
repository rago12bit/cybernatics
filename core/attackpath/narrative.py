"""Generate a plain-text narrative for one attack path (plan §21.6). Same "no fabricated opinion"
posture as `core.triage_assistant.service.assess`: `generate()` returns `None` when no model is
configured or the call (plus one repair attempt) never passes the contract, and the caller reports
that plainly rather than inventing a narrative to show."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from core.attackpath.contract import ContractError, validate_narrative
from core.attackpath.model import AttackPath
from core.attackpath.prompt import build_prompt
from core.llm.client import LLMClient

log = logging.getLogger(__name__)

REPAIR_NOTE = (
    "Your previous reply did not match the required format. Reply again with 2-4 plain sentences "
    "only, mentioning every node listed above by its label at least once: no markdown, no code "
    "fences, no JSON."
)


@dataclass
class Narrative:
    text: str
    model: str
    tokens_used: int
    warnings: list[str]


def generate(path: AttackPath, client: LLMClient | None) -> Narrative | None:
    if client is None:
        return None
    prompt = build_prompt(path)
    warnings: list[str] = []
    if prompt.signals:
        warnings.append(
            "The path's data contained text that looks like instructions to an AI "
            f"({', '.join(prompt.signals)}). It was treated as data."
        )
    if prompt.secrets_scrubbed:
        warnings.append(
            f"{prompt.secrets_scrubbed} possible secret(s) were removed before the path was sent."
        )
    if prompt.pii_redacted:
        warnings.append(
            f"{prompt.pii_redacted} possible personal detail(s) were redacted before sending."
        )
    tokens = 0
    try:
        completion = client.complete(prompt.system, prompt.user)
        tokens += completion.tokens
    except Exception as exc:  # noqa: BLE001 - any failure means "no narrative," never a crash
        log.warning("attack-path narrative model call failed: %s", type(exc).__name__)
        return None
    try:
        text = validate_narrative(completion.text, node_labels=prompt.node_labels)
    except ContractError as exc:
        log.warning("attack-path narrative reply rejected, attempting one repair: %s", exc)
        try:
            repair = client.complete(prompt.system, prompt.user + "\n\n" + REPAIR_NOTE)
            tokens += repair.tokens
            text = validate_narrative(repair.text, node_labels=prompt.node_labels)
        except Exception as exc2:  # noqa: BLE001 - repair failed too: no narrative, not a guess
            log.warning("attack-path narrative repair attempt also rejected: %s", exc2)
            return None
    return Narrative(text, client.model, tokens, warnings)
