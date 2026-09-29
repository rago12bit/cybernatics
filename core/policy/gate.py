"""High-level policy gate (plan §20.4): what both `bulwark ci compare` and the policy editor's
live evaluation call -- build the OPA input from findings, evaluate the gate, return denials.
"""

from __future__ import annotations

from typing import Any

from core.policy.input import build_input
from core.policy.models import PolicyResult
from core.policy.opa import eval_deny
from core.policy.starter import GATE_POLICY_PATH

DEFAULT_PACKAGE = "gate.pull_request"


def evaluate_gate(
    findings: list[dict[str, Any]],
    policy_rego: str,
    package: str = DEFAULT_PACKAGE,
    issues_by_fingerprint: dict[str, dict[str, Any]] | None = None,
) -> PolicyResult:
    input_doc = build_input(findings, issues_by_fingerprint)
    return eval_deny(policy_rego, package, input_doc)


def load_starter_policy() -> str:
    return GATE_POLICY_PATH.read_text()


__all__ = ["DEFAULT_PACKAGE", "evaluate_gate", "load_starter_policy"]
