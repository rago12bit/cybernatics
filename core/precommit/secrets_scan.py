"""Fast, native secret detection for the pre-commit hook (Week 51 task 4, plan §23).

`bulwark scan`'s own secret detection is Gitleaks, run in Docker (core/adapters/gitleaks.py) --
accurate, but a container start plus a full Gitleaks pass is nowhere near the hook's two-second
budget (ADR TBD). This module is a deliberately narrower, pure-Python complement: a short list of
high-confidence, distinctively-prefixed credential formats checked with compiled regexes and no
subprocess at all. It is NOT a replacement for `bulwark scan --tools gitleaks` in CI -- it exists
only to catch the common, obvious case before a commit is even made.

Every pattern here keys off a vendor-specific prefix (`AKIA`, `ghp_`, `sk_live_`, ...) rather than
generic entropy, trading recall for a false-positive rate low enough to block a commit on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.adapters.helpers import make_finding
from core.models import Category, Finding


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    cwe: str = "CWE-798"  # Use of Hard-coded Credentials


RULES: tuple[SecretRule, ...] = (
    SecretRule("PCS001", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretRule(
        "PCS002",
        "AWS secret access key",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    ),
    SecretRule("PCS003", "GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    SecretRule(
        "PCS004",
        "GitHub fine-grained personal access token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    SecretRule("PCS005", "GitHub OAuth/App token", re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36}\b")),
    SecretRule("PCS006", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b")),
    SecretRule(
        "PCS007",
        "Slack incoming webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ),
    SecretRule("PCS008", "Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    SecretRule("PCS009", "Stripe live restricted key", re.compile(r"\brk_live_[A-Za-z0-9]{24,}\b")),
    SecretRule("PCS010", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    SecretRule(
        "PCS011",
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    SecretRule("PCS012", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    SecretRule("PCS013", "OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    SecretRule("PCS014", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    SecretRule(
        "PCS015",
        "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"),
    ),
)


def scan_secrets(path: str, text: str) -> list[Finding]:
    """Every match is reported, regardless of how many rules fire on the same line -- a line with
    two different-looking secrets is two findings, not one, because there is no reliable way to
    know they're the same credential."""
    out: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for rule in RULES:
            if not rule.pattern.search(line):
                continue
            out.append(
                make_finding(
                    "precommit-secrets",
                    Category.SECRETS,
                    rule=rule.rule_id,
                    title=f"{rule.name} detected in staged file",
                    path=path,
                    start=lineno,
                    end=lineno,
                    # T7: never copy the matched text into a Finding (title, description or
                    # snippet) -- only that *a* match of this rule occurred, and where.
                    snippet="[snippet withheld: detected secret]",
                    native="HIGH",
                    description=(
                        f"A value matching the shape of a {rule.name} was found staged for "
                        f"commit at {path}:{lineno}. If this is real, rotate the credential -- "
                        "it is already in git history once committed -- then remove it from the "
                        "file before committing again."
                    ),
                    confidence=0.8,
                    cwe=[rule.cwe],
                )
            )
    return out
