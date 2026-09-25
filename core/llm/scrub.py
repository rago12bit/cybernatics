"""Text-level secret scrubbing and prompt-injection signals for anything that will reach a model.

Two separate jobs, both conservative:

* `scrub_secrets` removes credentials from free text (source code context) BEFORE it leaves the machine.
  Threat T7 says: redact before sending anything to an LLM. It errs on the side of removing too much.
* `injection_signals` notices text that looks like instructions aimed at an AI. It never blocks or edits
  anything: the defence is structural (delimited data, validated output). The signals only tell the user
  that the repository contained such text.
"""

from __future__ import annotations

import math
import re

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S
        ),
    ),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "api-key",
        re.compile(
            r"\b(?:sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[0-9A-Za-z]{16,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35})\b"
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("url-credentials", re.compile(r"(?<=://)[^\s/:@]+:[^\s/@]+(?=@)")),
]
# password = "hunter2", "api_key": 'abc...', TOKEN: xyz  -> keep the name, drop the value
_ASSIGN = re.compile(r"""(?ix)
    (\b[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|auth(?:orization)?|credential|private[_-]?key)[\w.-]*\b
     ["']?\s*[:=]\s*)
    (?:(["'`])(?:(?!\2).){4,}\2|[^\s"'`,;)]{8,})
    """)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")

_INJECTION: list[tuple[str, re.Pattern[str]]] = [
    ("ignore-instructions", re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any)\b[^.\n]{0,30}\b(?:instruction|prompt|rule|direction)s?")),
    ("role-change", re.compile(r"(?i)\byou\s+are\s+(?:now\s+)?(?:an?|the)\s+\w+")),
    ("system-prompt", re.compile(r"(?i)\b(?:system|developer)\s+(?:prompt|message|instruction)s?\b")),
    ("new-instructions", re.compile(r"(?i)\b(?:new|updated|real)\s+instructions?\b")),
    ("suppress-finding", re.compile(r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:report|mention|flag|list)\b|\breport\s+no\s+(?:vulnerabilit|issue|finding)|\b(?:mark|treat|classify)\b[^.\n]{0,25}\bfalse\s+positive|\bno\s+vulnerabilit")),
    ("fake-delimiter", re.compile(r"(?i)(?:</?\s*(?:system|assistant|user|instructions?|untrusted[_ ]data)\b|={3,}\s*(?:BEGIN|END)\b|\[/?INST\]|<\|(?:im_start|im_end|system)\|>)")),
    ("output-hijack", re.compile(r"(?i)\brespond\s+(?:only\s+)?with\b|\boutput\s+(?:only\s+)?(?:the\s+)?(?:json|following)\b|\bset\s+(?:the\s+)?(?:severity|confidence)\b")),
]  # fmt: skip


def _entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def scrub_secrets(text: str) -> tuple[str, int]:
    """Return `text` with credentials replaced by [REDACTED], and how many replacements were made."""
    n = 0
    for _name, pat in _PATTERNS:
        text, k = pat.subn(REDACTED, text)
        n += k
    text, k = _ASSIGN.subn(lambda m: f"{m.group(1)}{REDACTED}", text)
    n += k
    long_hits = 0

    def long_token(m: re.Match[str]) -> str:
        nonlocal long_hits
        tok = m.group(0)
        if _entropy(tok) > 4.0:  # random-looking, not a long identifier or file path
            long_hits += 1
            return REDACTED
        return tok

    text = _LONG_TOKEN.sub(long_token, text)
    return text, n + long_hits


def injection_signals(text: str) -> list[str]:
    """Names of injection-like patterns present in `text` (informational only)."""
    return sorted({name for name, pat in _INJECTION if pat.search(text)})
