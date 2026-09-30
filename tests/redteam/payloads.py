"""Loads the adversarial-repo corpus (plan §21.9): 20 named prompt-injection / format-breaking
payloads at tests/fixtures/injection_payloads.json, curated in an earlier week but never wired into
a test suite until now. Shared by every test module in this package so the corpus is defined once.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "injection_payloads.json"


def load_payloads() -> dict[str, str]:
    data: dict[str, Any] = json.loads(_PATH.read_text())
    return {k: str(v) for k, v in data.items()}
