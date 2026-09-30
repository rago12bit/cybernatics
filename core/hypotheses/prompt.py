"""Prompt construction for the Hypotheses lane (plan §21.4). Same defensive shape as
`core.llm.prompt`/`core.triage_assistant.prompt`: instructions only in the system message,
repository content nonce-fenced as data. Unlike those two, the model is shown STRUCTURED FACTS
about a candidate (the plan's own framing: "the model reasons over facts rather than guessing from
raw text") plus one route's code -- never a raw repository dump, and never another route's code
beyond its own path and marker names.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from core.hypotheses.facts import Candidate
from core.llm.pii import redact_pii
from core.llm.scrub import injection_signals, scrub_secrets

MAX_CODE_CHARS = 3000
CODE_RADIUS = 15  # lines of context either side of the route's own definition

PROMPTS_DIR = Path(__file__).parent.parent / "llm" / "prompts"
CURRENT_PROMPT_VERSION = "v1"


def load_prompt(version: str) -> str:
    return (PROMPTS_DIR / "hypotheses" / f"{version}.md").read_text().rstrip("\n")


SYSTEM = load_prompt(CURRENT_PROMPT_VERSION)
PROMPT_VERSION = hashlib.sha256(SYSTEM.encode()).hexdigest()[:12]

USER_TASK = "Decide whether this candidate is worth a person's time, per the rules above."
USER_TAIL = "Reply with the single JSON object described in the system message, and nothing else."


@dataclass
class Prompt:
    system: str
    user: str
    nonce: str
    snippet: str  # the exact code shown -- HypothesisRow.snippet stores this for promotion later
    secrets_scrubbed: int = 0
    pii_redacted: int = 0
    signals: list[str] = field(default_factory=list)


def _block(kind: str, nonce: str, body: str) -> str:
    return (
        f"=====BEGIN UNTRUSTED DATA [{nonce}] kind={kind}=====\n{body}\n"
        f"=====END UNTRUSTED DATA [{nonce}]====="
    )


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + " [truncated]"


def extract_snippet(source: str, line: int, radius: int = CODE_RADIUS) -> str:
    lines = source.splitlines()
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    numbered = [f"{lo + i:>5} | {ln}" for i, ln in enumerate(lines[lo - 1 : hi])]
    return "\n".join(numbered)


def build_prompt(candidate: Candidate, raw_code: str) -> Prompt:
    code, scrubbed = scrub_secrets(raw_code)
    code, pii = redact_pii(code)
    code = _clip(code, MAX_CODE_CHARS)

    sibling_lines = [
        f"- {s.method or '(any method)'} {s.path or '(no path)'}, markers: "
        f"{', '.join(s.auth_markers) or 'none'}"
        for s in candidate.protected_siblings
    ]

    repo_text = [candidate.route.path or "", candidate.file, code, "\n".join(sibling_lines)]
    signals = injection_signals("\n".join(repo_text))

    while True:
        nonce = secrets.token_hex(16)
        if not any(nonce in t for t in repo_text):
            break

    facts = "\n".join(
        [
            f"File: {candidate.file}",
            f"Candidate route: {candidate.route.method or '(any method)'} "
            f"{candidate.route.path or '(no path)'}",
            f"Candidate's own auth-looking markers: "
            f"{', '.join(candidate.route.auth_markers) or 'none'}",
            "Sibling routes in the same file that DO have a recognized auth-looking marker:",
            *sibling_lines,
        ]
    )
    parts = [_block("facts", nonce, facts), _block("code", nonce, code)]
    user = "\n\n".join([*parts, USER_TASK, USER_TAIL])
    return Prompt(SYSTEM, user, nonce, code, scrubbed, pii, signals)
