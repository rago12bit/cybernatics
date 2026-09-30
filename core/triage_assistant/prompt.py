"""Prompt construction for the triage assistant (plan §21.3). Same defensive shape as
`core.llm.prompt` (design doc 7.1, threat T8) -- instructions only in the system message, repository
content nonce-fenced as data, secrets scrubbed and PII redacted before anything is sent -- rewritten
here rather than imported because the two prompts show the model structurally different things (a
taint path and a request for a verdict, not a request for a patch) and, more importantly, because
sharing fencing code between the two would tempt sharing the *contract* too, which is exactly the
coupling `core.triage_assistant.contract`'s docstring explains must never happen.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from core.llm.pathguard import is_denylisted
from core.llm.pii import redact_pii
from core.llm.prompt import CodeContext
from core.llm.scrub import injection_signals, scrub_secrets
from core.models import Category, Finding

MAX_CODE_CHARS = 6000
MAX_TEXT_CHARS = 1200
MAX_TAINT_STEPS = 12

PROMPTS_DIR = Path(__file__).parent.parent / "llm" / "prompts"
CURRENT_PROMPT_VERSION = "v1"


def load_prompt(version: str) -> str:
    return (PROMPTS_DIR / "triage" / f"{version}.md").read_text().rstrip("\n")


SYSTEM = load_prompt(CURRENT_PROMPT_VERSION)
PROMPT_VERSION = hashlib.sha256(SYSTEM.encode()).hexdigest()[:12]

USER_TASK = "Give your verdict on the finding described in the data blocks above."
USER_TAIL = "Reply with the single JSON object described in the system message, and nothing else."


@dataclass
class Prompt:
    system: str
    user: str
    nonce: str
    first_line: int  # the code range actually shown -- parse_response rejects citations outside it
    last_line: int
    code_included: bool
    secrets_scrubbed: int = 0
    pii_redacted: int = 0
    signals: list[str] = field(default_factory=list)
    truncated: bool = False


def _clip(s: str, n: int) -> tuple[str, bool]:
    return (s, False) if len(s) <= n else (s[:n] + " [truncated]", True)


def _block(kind: str, nonce: str, body: str, **attrs: str) -> str:
    meta = " ".join(f'{k}="{v}"' for k, v in attrs.items())
    head = f"=====BEGIN UNTRUSTED DATA [{nonce}] kind={kind}{' ' + meta if meta else ''}====="
    return f"{head}\n{body}\n=====END UNTRUSTED DATA [{nonce}]====="


def _safe_attr(v: str) -> str:
    return "".join(c for c in v if c.isalnum() or c in "._/-+@:#")[:200]


def build_prompt(finding: Finding, code: CodeContext | None) -> Prompt:
    truncated = False
    loc = finding.location
    title, pii_title = redact_pii(finding.title)
    description, pii_desc = redact_pii(finding.description)
    pii_found = pii_title + pii_desc
    # A scanner's own title/description text can incidentally contain a secret-shaped string (e.g.
    # a rule that quotes the offending literal) -- scrubbed here the same way `code` already is,
    # found by the red-team corpus (plan §21.9) via a SECRETS finding whose title embedded a raw
    # AWS key that this function was otherwise sending straight to a model.
    title, title_scrubbed = scrub_secrets(title)
    description, desc_scrubbed = scrub_secrets(description)
    scrubbed = title_scrubbed + desc_scrubbed
    repo_text: list[str] = [title, description, loc.path]

    code_body = ""
    first_line, last_line = loc.start_line, loc.end_line
    if finding.taxonomy.category is Category.SECRETS:
        code_body = "[code withheld: this finding is a leaked secret; no source is sent to a model]"
        code = None
    elif is_denylisted(loc.path):
        code_body = f"[code withheld: {loc.path} matches the path denylist]"
        code = None
    elif code is not None:
        clean, code_scrubbed = scrub_secrets(code.text)
        scrubbed += code_scrubbed
        clean, pii_code = redact_pii(clean)
        pii_found += pii_code
        clean, cut = _clip(clean, MAX_CODE_CHARS)
        truncated |= cut
        first_line = code.first_line
        last_line = code.first_line + len(clean.splitlines()) - 1
        numbered = [f"{first_line + i:>5} | {ln}" for i, ln in enumerate(clean.splitlines())]
        code_body = "\n".join(numbered)
        repo_text.append(clean)

    taint_lines = []
    for step in finding.taint_path[:MAX_TAINT_STEPS]:
        marker = " <-- sink" if step.is_sink else ""
        taint_lines.append(f"{step.path}:{step.line}: {step.description}{marker}")
    taint_body = "\n".join(taint_lines) if taint_lines else "[no concrete taint path was recorded]"
    repo_text.append(taint_body)

    signals = injection_signals("\n".join(repo_text))

    while True:
        nonce = secrets.token_hex(16)
        if not any(nonce in t for t in repo_text):
            break

    title, c1 = _clip(title, MAX_TEXT_CHARS)
    desc, c2 = _clip(description, MAX_TEXT_CHARS)
    truncated |= c1 or c2
    lines = [
        f"Title: {title}",
        f"Description: {desc}",
        f"Category: {finding.taxonomy.category.value}",
        f"CWE: {', '.join(finding.taxonomy.cwe) or 'none given'}",
        f"File: {loc.path}",
        f"Lines: {loc.start_line}-{loc.end_line}",
        f"Reported by {finding.evidence.agreement_count} scanner(s): "
        f"{', '.join(finding.evidence.reported_by) or 'unknown'}",
    ]
    parts = [_block("finding", nonce, "\n".join(lines), path=_safe_attr(loc.path))]
    if code_body:
        parts.append(_block("code", nonce, code_body, path=_safe_attr(loc.path)))
    parts.append(_block("taint_path", nonce, taint_body))

    user = "\n\n".join([*parts, USER_TASK, USER_TAIL])
    return Prompt(
        SYSTEM, user, nonce, first_line, last_line,
        code_body != "" and code is not None, scrubbed, pii_found, signals, truncated,
    )  # fmt: skip
