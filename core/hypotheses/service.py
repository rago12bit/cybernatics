"""Ask a model to reason over one deterministic candidate (plan §21.4). Like
`core.triage_assistant.service.assess`, there is no static fallback and no repair-then-guess: a
hypothesis with no model behind it would be a fabricated opinion, so `assess_candidate()` returns
`None` when no model is configured or the reply never passes the contract, and the caller simply
generates no hypothesis for that candidate rather than inventing one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from core.hypotheses.contract import ContractError, HypothesisResult, parse_response
from core.hypotheses.facts import Candidate, missing_auth_candidates
from core.hypotheses.prompt import build_prompt
from core.llm.client import LLMClient

log = logging.getLogger(__name__)

MAX_CANDIDATES_PER_RUN = 30  # a generous bound on model calls per "generate" request

REPAIR_NOTE = (
    "Your previous reply did not match the required format. Reply again with exactly the single "
    "JSON object described in the system message: no markdown, no code fences, no other text."
)


@dataclass
class HypothesisAssessment:
    result: HypothesisResult
    snippet: str  # the exact code shown to the model -- persisted so promotion needs no re-clone
    model: str
    tokens_used: int


def assess_candidate(
    candidate: Candidate, raw_code: str, client: LLMClient | None
) -> HypothesisAssessment | None:
    if client is None:
        return None
    prompt = build_prompt(candidate, raw_code)
    tokens = 0
    try:
        completion = client.complete(prompt.system, prompt.user)
        tokens += completion.tokens
    except Exception as exc:  # noqa: BLE001 - any failure means "no hypothesis," never a crash
        log.warning("hypotheses model call failed: %s", type(exc).__name__)
        return None
    try:
        result = parse_response(completion.text)
    except ContractError as exc:
        log.warning("hypothesis reply rejected, attempting one repair: %s", exc)
        try:
            repair = client.complete(prompt.system, prompt.user + "\n\n" + REPAIR_NOTE)
            tokens += repair.tokens
            result = parse_response(repair.text)
        except Exception as exc2:  # noqa: BLE001 - repair failed too: no hypothesis, not a guess
            log.warning("hypothesis repair attempt also rejected: %s", exc2)
            return None
    return HypothesisAssessment(result, prompt.snippet, client.model, tokens)


def _safe_read(root: Path, rel: str) -> str | None:
    """The same path-containment chokepoint `core.fixagent.tools._safe_path` uses, kept as its own
    small copy rather than a cross-feature import: this module's only filesystem access is one
    read-only lookup, not worth coupling two independently-evolving features over."""
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        return None
    candidate = (root / rel).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        return None
    if not candidate.is_file():
        return None
    return candidate.read_text(errors="replace")


def generate_for_checkout(
    checkout: Path, client: LLMClient | None
) -> list[tuple[Candidate, HypothesisAssessment]]:
    """The whole per-asset generation pass (plan §21.4): find every deterministic candidate, ask
    the model about each one (up to `MAX_CANDIDATES_PER_RUN`), and return only the ones it chose to
    surface. `client is None` short-circuits to an empty list rather than calling
    `assess_candidate` once per candidate just to have each one return `None` -- same result, no
    wasted work.
    """
    if client is None:
        return []
    from core.codeintel import analyze

    graph = analyze(checkout)
    out: list[tuple[Candidate, HypothesisAssessment]] = []
    for candidate in missing_auth_candidates(graph)[:MAX_CANDIDATES_PER_RUN]:
        code = _safe_read(checkout, candidate.file)
        if code is None:
            continue
        from core.hypotheses.prompt import extract_snippet

        snippet = extract_snippet(code, candidate.line)
        assessment = assess_candidate(candidate, snippet, client)
        if assessment is not None and assessment.result.surface:
            out.append((candidate, assessment))
    return out
