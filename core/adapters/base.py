"""ToolAdapter interface (design doc §4.1).

Adding a scanner = one subclass of ToolAdapter + one golden-file test.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from core.models import Finding


@dataclass(frozen=True)
class ToolSpec:
    name: str  # "semgrep"
    image: str  # pinned by digest in prod
    categories: frozenset[str]  # {"sast"}
    languages: frozenset[str]  # {"python", "javascript", ...}
    timeout_seconds: int = 900
    memory_limit: str = "2g"
    native_sarif: bool = False


@dataclass(frozen=True)
class RepoContext:
    """What we know about the target repo; drives ToolAdapter.applies_to()."""

    root: Path
    languages: frozenset[str] = field(default_factory=frozenset)
    has_dockerfile: bool = False
    has_iac: bool = False
    lockfiles: tuple[str, ...] = ()


class ToolAdapter(ABC):
    spec: ToolSpec

    @abstractmethod
    def build_command(self, target: Path, output: Path) -> list[str]:
        """Argv executed inside the container. Must write results to `output`."""

    @abstractmethod
    def parse(self, raw: bytes) -> list[Finding]:
        """Raw tool output -> canonical Findings.

        Must never raise on malformed input; return [] and log instead.
        """

    def applies_to(self, ctx: RepoContext) -> bool:
        """Skip this tool when the repo has no relevant files."""
        return bool(ctx.languages & self.spec.languages)
