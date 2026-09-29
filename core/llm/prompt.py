"""Prompt construction for remediation suggestions (design doc 7.1, threat T8).

Defences, all structural (none depends on the model behaving):

1. Instructions live ONLY in the system message. Everything from the scanned repository or a scanner sits in
   the user message inside a block fenced with a random per-request nonce, so repository text cannot forge
   the closing fence (it would have to guess 128 random bits; we also check the nonce is absent).
2. The system message says, in plain words, that block content is data and never instructions.
3. The task reminder comes AFTER the data blocks, outside them.
4. Secrets are scrubbed from code before it is included; a finding whose category is `secrets` gets no code.
5. The reply is validated by `contract.parse_response`; an obedient-to-the-attacker reply fails validation.
6. Prompt injection signals in the repository text are reported (informational), never silently ignored.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from core.llm.pathguard import is_denylisted
from core.llm.pii import redact_pii
from core.llm.scrub import injection_signals, scrub_secrets
from core.models import Category, Finding
from core.rag.retrieve import RemediationContext

CODE_RADIUS = 20  # lines of context on each side of the finding
MAX_CODE_CHARS = 6000
MAX_TEXT_CHARS = 1200  # per scanner-supplied string (title, description)

# The prompt registry (plan §21.1): "prompts are versioned files, each paired with an evaluation
# set; changing a prompt requires its evaluation to pass" (promptfoo/prompts/fix/, ADR-0026). Lives
# under `core/llm/prompts/`, not a repo-root `prompts/` as the plan's own example path shows, because
# `pyproject.toml` only packages `core*`/`cli*`/`api*` for a real `pip install` -- a repo-root
# directory would silently vanish outside a git checkout, exactly the kind of packaging surprise
# `core.rag`'s own bundled corpus (`core/rag/corpus/`) already avoids for the same reason.
PROMPTS_DIR = Path(__file__).parent / "prompts"
CURRENT_PROMPT_VERSION = "v1"  # bump (and add prompts/fix/v2.md) when the rules change materially


def load_prompt(task: str, version: str) -> str:
    return (PROMPTS_DIR / task / f"{version}.md").read_text().rstrip("\n")


SYSTEM = load_prompt("fix", CURRENT_PROMPT_VERSION)

# The cache key (core/llm/cache.py) still hashes the loaded content rather than trusting the "v1"
# label by itself: it is what actually invalidates old cache entries the instant a byte of the file
# changes, whether or not whoever edited it remembered to bump the filename too.
PROMPT_VERSION = hashlib.sha256(SYSTEM.encode()).hexdigest()[
    :12
]  # cache entries die when the rules change

USER_TASK = "Annotate the finding described in the data blocks above."
USER_TAIL = "Reply with the single JSON object described in the system message, and nothing else."


@dataclass(frozen=True)
class CodeContext:
    text: str  # the lines, without numbering
    first_line: int  # 1-based number of the first line in `text`


def extract_context(source: str, start: int, end: int, radius: int = CODE_RADIUS) -> CodeContext:
    """The finding's lines plus `radius` lines either side."""
    lines = source.splitlines()
    lo = max(1, start - radius)
    hi = min(len(lines), max(end, start) + radius)
    return CodeContext("\n".join(lines[lo - 1 : hi]), lo)


@dataclass
class Prompt:
    system: str
    user: str
    nonce: str
    code_included: bool
    secrets_scrubbed: int = 0
    pii_redacted: int = 0
    signals: list[str] = field(
        default_factory=list
    )  # injection-like text found in repository content
    truncated: bool = False


def _clip(s: str, n: int) -> tuple[str, bool]:
    return (s, False) if len(s) <= n else (s[:n] + " [truncated]", True)


def _block(kind: str, nonce: str, body: str, **attrs: str) -> str:
    meta = " ".join(f'{k}="{v}"' for k, v in attrs.items())
    head = f"=====BEGIN UNTRUSTED DATA [{nonce}] kind={kind}{' ' + meta if meta else ''}====="
    return f"{head}\n{body}\n=====END UNTRUSTED DATA [{nonce}]====="


def _safe_attr(v: str) -> str:
    return "".join(c for c in v if c.isalnum() or c in "._/-+@:#")[:200]


def build_prompt(finding: Finding, ctx: RemediationContext, code: CodeContext | None) -> Prompt:
    truncated = False
    loc = finding.location
    title, pii_title = redact_pii(finding.title)
    description, pii_desc = redact_pii(finding.description)
    pii_found = pii_title + pii_desc
    repo_text: list[str] = [title, description, loc.path]

    code_body = ""
    scrubbed = 0
    if finding.taxonomy.category is Category.SECRETS:
        code_body = "[code withheld: this finding is a leaked secret; no source is sent to a model]"
        code = None
    elif is_denylisted(loc.path):
        code_body = f"[code withheld: {loc.path} matches the path denylist]"
        code = None
    elif code is not None:
        clean, scrubbed = scrub_secrets(code.text)
        clean, pii_code = redact_pii(clean)
        pii_found += pii_code
        clean, cut = _clip(clean, MAX_CODE_CHARS)
        truncated |= cut
        numbered = [f"{code.first_line + i:>5} | {ln}" for i, ln in enumerate(clean.splitlines())]
        code_body = "\n".join(numbered)
        repo_text.append(clean)

    signals = injection_signals("\n".join(repo_text))

    while True:
        nonce = secrets.token_hex(16)
        # A block cannot be closed from inside unless its text already contains the nonce. Practically
        # impossible; checked anyway so the guarantee does not rest on probability alone.
        if not any(nonce in t for t in repo_text) and not any(
            nonce in r.text for r in [*ctx.cwe_entries, *ctx.guidance]
        ):
            break

    title, c1 = _clip(title, MAX_TEXT_CHARS)
    desc, c2 = _clip(description, MAX_TEXT_CHARS)
    truncated |= c1 or c2
    lines = [
        f"Title: {title}",
        f"Description: {desc}",
        f"Category: {finding.taxonomy.category.value}",
        f"CWE: {', '.join(finding.taxonomy.cwe) or 'none given'}",
        f"OWASP Top 10: {', '.join(finding.taxonomy.owasp_top_10_2021) or 'none given'}",
        f"File: {loc.path}",
        f"Lines: {loc.start_line}-{loc.end_line}",
    ]
    if finding.package:
        p = finding.package
        lines.append(f"Package: {p.name} {p.version} ({p.ecosystem})")
    parts = [_block("finding", nonce, "\n".join(lines), path=_safe_attr(loc.path))]
    if code_body:
        parts.append(_block("code", nonce, code_body, path=_safe_attr(loc.path)))

    refs: list[str] = []
    for r in ctx.cwe_entries:
        refs.append(f"[{r.title}] ({r.url})\n{r.text}")
    for r in ctx.guidance:
        refs.append(f"[{r.title} > {r.section}] ({r.url})\n{r.text}")
    if refs:
        parts.append(_block("reference", nonce, "\n\n".join(refs)))

    user = "\n\n".join([*parts, USER_TASK, USER_TAIL])
    return Prompt(
        SYSTEM,
        user,
        nonce,
        code_body != "" and code is not None,
        scrubbed,
        pii_found,
        signals,
        truncated,
    )
