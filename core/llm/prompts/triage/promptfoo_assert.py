"""The deterministic half of the triage eval: runs a reply through the REAL
`core.triage_assistant.contract.parse_response`, the exact validator `core.triage_assistant.service
.assess` uses -- not a second, divergence-prone reimplementation of the same rules.

`config.first_line`/`config.last_line` name the code range this reply's fixture actually showed the
model, so the line-citation check validates against the truth for that fixture (see
`fixtures/meta.json`, generated alongside the fixtures themselves).
"""

from __future__ import annotations

from typing import Any

from core.triage_assistant.contract import ContractError, parse_response


def get_assert(output: str, context: dict[str, Any]) -> dict[str, Any]:
    v = context.get("vars") or {}
    first_line, last_line = int(v.get("first_line", 1)), int(v.get("last_line", 1))
    try:
        r = parse_response(output, first_line=first_line, last_line=last_line)
    except ContractError as exc:
        return {"pass": False, "score": 0.0, "reason": f"contract rejected the reply: {exc}"}
    return {
        "pass": True,
        "score": 1.0,
        "reason": f"valid: verdict={r.verdict}, confidence={r.confidence}",
    }
