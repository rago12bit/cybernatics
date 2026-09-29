"""The deterministic half of the eval (plan §21.1: "correctness is always decided by deterministic
checks"): runs a reply through the REAL `core.llm.contract.parse_response`, the exact validator
production uses, rather than a second, divergence-prone reimplementation of the same rules.

`config.path` in the test case names which finding fixture this reply is for, so the patch-path
check validates against the right file.
"""

from __future__ import annotations

from typing import Any

from core.llm.contract import ContractError, parse_response


def get_assert(output: str, context: dict[str, Any]) -> dict[str, Any]:
    path = (context.get("vars") or {}).get("path", "app/example.py")
    try:
        s = parse_response(output, path=path)
    except ContractError as exc:
        return {"pass": False, "score": 0.0, "reason": f"contract rejected the reply: {exc}"}
    return {
        "pass": True,
        "score": 1.0,
        "reason": f"valid: confidence={s.confidence}, patch={'yes' if s.suggested_patch else 'no'}",
    }
