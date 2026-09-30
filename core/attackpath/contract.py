"""The attack-path narrative's output contract (plan §21.6): a model reads one AttackPath's nodes
and edges and returns a short plain-text narrative -- untrusted input until it passes every check
here, same posture as `core.triage_assistant.contract` for verdicts.

Unlike the JSON contracts elsewhere in this codebase (fix/triage/hypotheses), the narrative is free
text, so there is no schema to parse -- the enforcement instead is that the narrative must actually
be grounded in the path it was given: every node's label must appear in it (plan §21.6: "the graph
is the source of truth; the narrative only describes it"). A reply that mentions every labeled node
and adds nothing the graph didn't already say is accepted; a reply that omits a node, or reads like
markdown/JSON instead of prose, is rejected.
"""

from __future__ import annotations

import re

MAX_REPLY_CHARS = 2_000
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")  # incl. bidi
_FENCE = re.compile(r"```")
_MARKDOWN_HEADING = re.compile(r"^\s{0,3}#{1,6}\s", re.M)
_BULLET = re.compile(r"^\s*[-*]\s", re.M)


class ContractError(ValueError):
    """The model's reply broke the contract. The message names the rule, never echoes the reply."""


def validate_narrative(raw: str, *, node_labels: tuple[str, ...]) -> str:
    if not isinstance(raw, str):
        raise ContractError("reply is not text")
    text = raw.strip()
    if not text:
        raise ContractError("reply is empty")
    if len(text) > MAX_REPLY_CHARS:
        raise ContractError(f"reply is longer than {MAX_REPLY_CHARS} characters")
    if _CTRL.search(text):
        raise ContractError("reply contains control characters")
    if _FENCE.search(text):
        raise ContractError("reply must be plain prose, not a code fence")
    if _MARKDOWN_HEADING.search(text) or _BULLET.search(text):
        raise ContractError("reply must be plain prose, not markdown headings or bullet points")
    if text.lstrip().startswith("{") or text.lstrip().startswith("["):
        raise ContractError("reply must be plain prose, not JSON")
    missing = [label for label in node_labels if label and label.lower() not in text.lower()]
    if missing:
        raise ContractError(f"reply omits {len(missing)} node label(s) from the path")
    return text
