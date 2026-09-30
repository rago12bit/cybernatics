"""Prompt construction for the attack-path narrative (plan §21.6). Same defensive shape as
`core.triage_assistant.prompt` (design doc 7.1, threat T8): instructions only in the system
message, node/edge data nonce-fenced as untrusted data, secrets scrubbed and PII redacted before
anything is sent -- rewritten here rather than imported, same reason triage_assistant's prompt.py
gives for not sharing fencing code with core.llm.prompt: it would tempt sharing the *contract* too.
The model is shown only the AttackPath's own nodes and edges, in the order the chaining rules
produced them -- never asked to invent additional structure (plan §21.6: "the graph is the source
of truth; the narrative only describes it")."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from core.attackpath.model import AttackPath
from core.llm.pii import redact_pii
from core.llm.scrub import injection_signals, scrub_secrets

PROMPTS_DIR = Path(__file__).parent.parent / "llm" / "prompts"
CURRENT_PROMPT_VERSION = "v1"


def load_prompt(version: str) -> str:
    return (PROMPTS_DIR / "attackpath" / f"{version}.md").read_text().rstrip("\n")


SYSTEM = load_prompt(CURRENT_PROMPT_VERSION)
PROMPT_VERSION = hashlib.sha256(SYSTEM.encode()).hexdigest()[:12]

USER_TASK = "Write the narrative for the attack path described in the data block above."
USER_TAIL = (
    "Reply with 2-4 plain sentences only: no markdown, no headings, no bullet points, and mention "
    "every node listed above by its label at least once."
)


@dataclass
class Prompt:
    system: str
    user: str
    node_labels: tuple[str, ...]
    secrets_scrubbed: int = 0
    pii_redacted: int = 0
    signals: list[str] = field(default_factory=list)


def _clean(text: str) -> tuple[str, int, int]:
    label, pii = redact_pii(text)
    label, scrubbed = scrub_secrets(label)
    return label, scrubbed, pii


def build_prompt(path: AttackPath) -> Prompt:
    scrubbed_total = 0
    pii_total = 0
    labels: list[str] = []
    raw_text: list[str] = []
    clean_by_id: dict[str, str] = {}

    lines = [f"Likelihood: {path.likelihood.value}", f"Impact: {path.impact.value}", "", "Nodes:"]
    for n in path.nodes:
        label, s1, p1 = _clean(n.label)
        detail, s2, p2 = _clean(n.detail)
        scrubbed_total += s1 + s2
        pii_total += p1 + p2
        labels.append(label)
        clean_by_id[n.id] = label
        raw_text.extend([label, detail])
        lines.append(f"- [{n.kind.value}] {label}" + (f" ({detail})" if detail else ""))

    lines.append("")
    lines.append("Edges:")
    for e in path.edges:
        src_label = clean_by_id.get(e.source, e.source)
        dst_label = clean_by_id.get(e.target, e.target)
        lines.append(f"- {src_label} --[{e.kind.value}]--> {dst_label} (rule: {e.rule_id})")

    signals = injection_signals("\n".join(raw_text))

    while True:
        nonce = secrets.token_hex(16)
        if not any(nonce in t for t in raw_text):
            break

    body = "\n".join(lines)
    fenced = (
        f"=====BEGIN UNTRUSTED DATA [{nonce}] kind=attack_path=====\n{body}\n"
        f"=====END UNTRUSTED DATA [{nonce}]====="
    )
    user = "\n\n".join([fenced, USER_TASK, USER_TAIL])
    return Prompt(SYSTEM, user, tuple(labels), scrubbed_total, pii_total, signals)
