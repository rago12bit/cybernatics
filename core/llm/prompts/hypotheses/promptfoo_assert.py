"""The deterministic half of the Hypotheses-lane eval: runs a reply through the REAL
`core.hypotheses.contract.parse_response`, the exact validator `core.hypotheses.service
.assess_candidate` uses.
"""

from __future__ import annotations

from typing import Any

from core.hypotheses.contract import ContractError, parse_response


def get_assert(output: str, context: dict[str, Any]) -> dict[str, Any]:
    try:
        r = parse_response(output)
    except ContractError as exc:
        return {"pass": False, "score": 0.0, "reason": f"contract rejected the reply: {exc}"}
    return {
        "pass": True,
        "score": 1.0,
        "reason": f"valid: surface={r.surface}, confidence={r.confidence}",
    }
