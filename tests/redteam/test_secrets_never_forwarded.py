"""Red-team scenario (plan §21.9): a real-looking credential planted in scanned code (the corpus's
"secret-bait" payload, an AWS access key in the exact AKIA-prefixed format core.llm.scrub._PATTERNS
matches) must never reach a model call, at two independent layers: core.llm.scrub.scrub_secrets
itself, and the SECRETS-category special case in core.triage_assistant.prompt.build_prompt that
withholds code entirely rather than relying on scrubbing alone for a finding that IS a secret.
"""

from __future__ import annotations

import re

from core.llm.prompt import CodeContext
from core.llm.scrub import scrub_secrets
from core.models import Category, Finding, Location, Taxonomy
from core.triage_assistant.prompt import build_prompt
from tests.redteam.payloads import load_payloads

PAYLOADS = load_payloads()
SECRET_BAIT = PAYLOADS["secret-bait"]
# Extracted at runtime, not hardcoded a second time here -- this environment's own secret masking
# (correctly) redacts an AWS-key-shaped literal the moment it appears in a file, even AWS's own
# publicly documented EXAMPLE key, which is all this fixture ever contained.
_RAW_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")


def test_scrub_secrets_redacts_the_planted_aws_key() -> None:
    m = _RAW_KEY_PATTERN.search(SECRET_BAIT)
    assert m, "sanity: the corpus payload still contains an AWS-key-shaped string"
    raw_key = m.group()
    cleaned, count = scrub_secrets(SECRET_BAIT)
    assert raw_key not in cleaned
    assert count >= 1


def test_triage_prompt_withholds_code_entirely_for_a_secrets_finding() -> None:
    finding = Finding(
        "f1", f"Hardcoded credential ({SECRET_BAIT})", "d",
        Location("config.py", 5, 5, "snippet"), Taxonomy(Category.SECRETS, cwe=("CWE-798",)),
    )  # fmt: skip
    prompt = build_prompt(finding, CodeContext(SECRET_BAIT, 1))
    raw_key = _RAW_KEY_PATTERN.search(SECRET_BAIT).group()  # type: ignore[union-attr]
    assert raw_key not in prompt.user
    assert prompt.code_included is False
    assert "withheld" in prompt.user
