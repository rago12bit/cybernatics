"""core.observability.cost's estimate_cost (Week 50, plan §23)."""

from __future__ import annotations

from core.observability.cost import (
    DEFAULT_COMPUTE_USD_PER_SECOND,
    estimate_cost,
    model_price_per_1k_tokens,
)


def test_compute_only_cost_scales_with_seconds() -> None:
    c = estimate_cost(compute_seconds=100.0, llm_tokens=0, model="claude-sonnet-5")
    assert c.compute_seconds == 100.0
    assert c.compute_usd == 100.0 * DEFAULT_COMPUTE_USD_PER_SECOND
    assert c.llm_usd == 0.0
    assert c.total_usd == c.compute_usd


def test_llm_only_cost_uses_the_models_own_rate() -> None:
    c = estimate_cost(compute_seconds=0.0, llm_tokens=5000, model="claude-opus-5")
    assert c.llm_tokens == 5000
    assert c.llm_usd == 5.0 * model_price_per_1k_tokens("claude-opus-5")
    assert c.compute_usd == 0.0


def test_unknown_model_falls_back_to_the_default_rate() -> None:
    c = estimate_cost(compute_seconds=0.0, llm_tokens=1000, model="some-future-model")
    assert c.llm_usd == model_price_per_1k_tokens("claude-sonnet-5")  # the documented fallback tier


def test_an_explicit_override_rate_replaces_the_per_model_table() -> None:
    c = estimate_cost(
        compute_seconds=0.0, llm_tokens=1000, model="claude-opus-5", llm_usd_per_1k_tokens=1.23
    )
    assert c.llm_usd == 1.23


def test_negative_inputs_are_clamped_to_zero() -> None:
    c = estimate_cost(compute_seconds=-5.0, llm_tokens=-10, model="claude-sonnet-5")
    assert c.compute_seconds == 0.0
    assert c.compute_usd == 0.0
    assert c.llm_tokens == 0
    assert c.llm_usd == 0.0


def test_total_usd_is_the_sum_of_both_components() -> None:
    c = estimate_cost(compute_seconds=50.0, llm_tokens=2000, model="claude-haiku-4-5")
    assert c.total_usd == c.compute_usd + c.llm_usd
