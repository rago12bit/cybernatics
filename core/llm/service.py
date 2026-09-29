"""Suggest a remediation for one finding. Never raises, never changes the finding, always returns something.

    finding + RAG context + code  ->  prompt  ->  model  ->  contract check  ->  AI suggestion
                                          any failure (or no model configured)  ->  static CWE/cheat-sheet text

The result is a separate object: `Finding.scoring`, `.triage` and `.taxonomy` are never touched, so the model
cannot downgrade, suppress or relabel a finding whatever it returns (design doc 7.1; test_llm proves it).
Prompt and reply text are never logged: they can contain source code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from core.llm.client import LLMClient
from core.llm.contract import ContractError, Suggestion, parse_response
from core.llm.patchcheck import check_patch
from core.llm.prompt import CodeContext, build_prompt
from core.models import Finding
from core.rag.retrieve import RemediationContext, context_for
from core.rag.store import KnowledgeBase

log = logging.getLogger(__name__)
LABEL = "AI suggestion: review before applying"
STATIC_LABEL = "Reference guidance (not AI-generated)"
# Fixed and generic, deliberately: it never echoes the rejected reply or the rejection reason back
# into a new prompt. Both could contain model- or attacker-influenced text (the reply was already
# untrusted enough to fail the contract), and re-feeding either would build exactly the kind of
# feedback channel prompt.py's nonce-fencing exists to prevent (plan §21.1, "one repair attempt").
REPAIR_NOTE = (
    "Your previous reply did not match the required format. Reply again with exactly the single "
    "JSON object described in the system message: no markdown, no code fences, no other text."
)


@dataclass
class RemediationResult:
    source: Literal["ai", "static"]
    label: str
    explanation: str
    impact: str
    fix_summary: str
    suggested_patch: str | None
    confidence: str
    model: str | None = None
    degraded_reason: str | None = None  # why static text was used instead of a model's
    warnings: list[str] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    patch_status: str | None = (
        None  # 'verified' | 'unverified' (never 'rejected': those patches are dropped)
    )
    from_cache: bool = False
    generated_at: str | None = (
        None  # when the model produced it (cache hits keep the original time)
    )
    tokens_used: int = 0  # real model calls only (0 for static/cached); feeds core.llm.budget


def _refs(ctx: RemediationContext) -> list[dict[str, str]]:
    return [{"title": r.title, "url": r.url} for r in [*ctx.cwe_entries, *ctx.guidance]]


def _first_sentences(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(". ", 1)[0]
    return (cut if len(cut) > limit // 3 else text[:limit].rstrip()) + (
        "." if not cut.endswith(".") else ""
    )


def static_suggestion(finding: Finding, ctx: RemediationContext, reason: str) -> RemediationResult:
    """Deterministic fallback built only from the reference corpus: no model, nothing invented."""
    cwe = ctx.cwe_entries[0] if ctx.cwe_entries else None
    explanation = _first_sentences(cwe.text, 700) if cwe else finding.description or finding.title
    impact = "See the CWE entry linked below for the consequences of this weakness."
    fix = ""
    if ctx.guidance:
        fix = _first_sentences(ctx.guidance[0].text, 700)
    elif finding.remediation.summary:
        fix = finding.remediation.summary
    else:
        fix = "No specific guidance is available for this finding. See the linked references."
    return RemediationResult(
        source="static", label=STATIC_LABEL, explanation=explanation, impact=impact, fix_summary=fix,
        suggested_patch=None, confidence="low", degraded_reason=reason, references=_refs(ctx),
    )  # fmt: skip


def suggest(
    finding: Finding,
    kb: KnowledgeBase,
    client: LLMClient | None,
    code: CodeContext | None = None,
) -> RemediationResult:
    ctx = context_for(finding, kb)
    if client is None:
        return static_suggestion(finding, ctx, "no model configured")
    prompt = build_prompt(finding, ctx, code)
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
    except Exception as exc:  # noqa: BLE001 - any failure degrades, none propagates
        log.warning("remediation model call failed: %s", type(exc).__name__)
        res = static_suggestion(finding, ctx, f"model call failed ({type(exc).__name__})")
        res.warnings, res.tokens_used = warnings, tokens
        return res
    try:
        s: Suggestion = parse_response(completion.text, path=finding.location.path)
    except ContractError as exc:
        log.warning("remediation reply rejected, attempting one repair: %s", exc)
        try:
            repair = client.complete(prompt.system, prompt.user + "\n\n" + REPAIR_NOTE)
            tokens += repair.tokens
            s = parse_response(repair.text, path=finding.location.path)
        except (
            Exception
        ) as exc2:  # noqa: BLE001 - repair failed too (contract or transport): degrade
            log.warning("remediation repair attempt also rejected: %s", exc2)
            res = static_suggestion(
                finding, ctx, f"model reply rejected after one repair attempt: {exc2}"
            )
            res.warnings, res.tokens_used = warnings, tokens
            return res
    patch, patch_status = s.suggested_patch, None
    if patch:
        # The contract proved the patch is well formed; this proves it matches the code we showed the model.
        chk = check_patch(patch, code)
        if chk.status == "rejected":
            log.warning("remediation patch discarded: %s", chk.detail)
            warnings.append(f"The suggested patch was discarded because {chk.detail}.")
            patch = None
        else:
            patch, patch_status = chk.patch, chk.status
            if chk.status == "unverified":
                warnings.append(f"The suggested patch could not be fully checked: {chk.detail}.")
    return RemediationResult(
        source="ai", label=LABEL, explanation=s.explanation, impact=s.impact, fix_summary=s.fix_summary,
        suggested_patch=patch, confidence=s.confidence, model=client.model,
        warnings=warnings, references=_refs(ctx), patch_status=patch_status, tokens_used=tokens,
    )  # fmt: skip
