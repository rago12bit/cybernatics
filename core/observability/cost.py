"""Cost per scan: compute seconds plus model tokens (plan §23, Week 50). Two real numbers this
project already tracks -- `ToolRun.duration_seconds` (every scanner's own wall-clock time, summed per
scan) and `Scan.llm_tokens_used` (every real LLM call's token count, accumulated by
`core.llm.budget.record`) -- turned into an estimated USD figure, computed on demand rather than
stored: a scan's LLM spend keeps growing after it "finishes" (remediation suggestions, hypotheses,
and copilot messages are all requested later, independently of the scan job itself), so a cost
written once at scan-completion time would be wrong the moment someone asks for a suggestion. Nothing
here is exact billing -- it is estimated cost for visibility on an internal dashboard, not an invoice.

Known, disclosed imprecision (see docs/v2-week50-verification.md for the full accounting):
- `Scan.llm_tokens_used` is a combined input+output count (`core.llm.client.Completion.tokens` sums
  them before this project ever sees the split), so pricing below is one blended $/token figure per
  model, not real provider pricing's separate (and usually very different) input/output rates.
- A token count carries no record of which model it was spent against if `BULWARK_LLM_MODEL` changes
  mid-month; this always prices every token at whatever model is configured *now*.
- `COMPUTE_USD_PER_SECOND` is a placeholder or an explicit override, not a real cloud bill -- see its
  own docstring.
"""

from __future__ import annotations

from dataclasses import dataclass

# $ per 1K tokens, blended (input+output averaged), for whichever model BULWARK_LLM_MODEL names.
# Anthropic's own published pricing changes over time and varies by input vs. output -- these are
# deliberately rounded, order-of-magnitude placeholders for a *relative* cost comparison across scans
# and orgs, not a source of truth for billing. Override per deployment via `BULWARK_LLM_COST_PER_1K_TOKENS_USD`
# (a single blended rate covering every model) when a more accurate figure for your actual provider
# contract is available.
MODEL_PRICING_USD_PER_1K_TOKENS: dict[str, float] = {
    "claude-sonnet-5": 0.006,
    "claude-opus-5": 0.03,
    "claude-haiku-4-5": 0.002,
}
_DEFAULT_MODEL_PRICE = 0.006  # an unrecognized model falls back to the sonnet-tier estimate

# $ per second of scanner wall-clock time. This is NOT derived from any real cloud bill -- it is a
# placeholder (roughly a small-VM's per-second compute cost) explicitly meant to be overridden via
# `BULWARK_COMPUTE_COST_PER_SECOND_USD` once a deployment knows its own real per-second compute cost
# (reserved capacity, spot pricing, a Kubernetes node's amortized hourly rate divided by 3600 -- all
# legitimate, all different, none of them knowable from inside this codebase).
DEFAULT_COMPUTE_USD_PER_SECOND = 0.0003


@dataclass(frozen=True)
class CostBreakdown:
    compute_seconds: float
    compute_usd: float
    llm_tokens: int
    llm_usd: float

    @property
    def total_usd(self) -> float:
        return self.compute_usd + self.llm_usd


def model_price_per_1k_tokens(model: str) -> float:
    return MODEL_PRICING_USD_PER_1K_TOKENS.get(model, _DEFAULT_MODEL_PRICE)


def estimate_cost(
    *,
    compute_seconds: float,
    llm_tokens: int,
    model: str,
    compute_usd_per_second: float = DEFAULT_COMPUTE_USD_PER_SECOND,
    llm_usd_per_1k_tokens: float | None = None,
) -> CostBreakdown:
    """`llm_usd_per_1k_tokens`, when given, overrides the per-model table entirely (a deployment's
    own negotiated rate, via `Settings.llm_cost_per_1k_tokens_usd`) -- otherwise priced per `model`.
    """
    compute_usd = max(compute_seconds, 0.0) * compute_usd_per_second
    rate = (
        llm_usd_per_1k_tokens
        if llm_usd_per_1k_tokens is not None
        else model_price_per_1k_tokens(model)
    )
    llm_usd = max(llm_tokens, 0) / 1000.0 * rate
    return CostBreakdown(
        compute_seconds=max(compute_seconds, 0.0),
        compute_usd=compute_usd,
        llm_tokens=max(llm_tokens, 0),
        llm_usd=llm_usd,
    )
