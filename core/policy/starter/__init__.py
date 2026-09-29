"""The starter policy library (plan §20.4): file locations, so `core.policy.gate` and its tests
share one source of truth instead of each hard-coding the path."""

from __future__ import annotations

from pathlib import Path

STARTER_DIR = Path(__file__).parent
GATE_POLICY_PATH = STARTER_DIR / "gate.rego"

__all__ = ["STARTER_DIR", "GATE_POLICY_PATH"]
