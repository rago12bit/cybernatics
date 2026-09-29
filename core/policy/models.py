"""Shared data model for policy-as-code (plan §20.4)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PolicyResult:
    """The outcome of evaluating one policy's `deny` rule against one input document."""

    package: str
    deny: tuple[str, ...] = ()
    error: str | None = None  # a real evaluation failure (bad Rego, opa missing, timeout)

    @property
    def failed(self) -> bool:
        return bool(self.deny) or self.error is not None


@dataclass(frozen=True)
class PolicyTestResult:
    passed: int
    failed: int
    failures: tuple[str, ...] = field(default_factory=tuple)  # "package.test_name: reason"

    @property
    def ok(self) -> bool:
        return self.failed == 0
