"""ToolAdapter interface (design doc §4.1).

Adding a scanner = one subclass of ToolAdapter + one golden-file test.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from core.models import Finding

TARGET_PREFIX = "/target/"  # where the runner mounts the scan target inside containers


@dataclass(frozen=True)
class ToolSpec:
    name: str  # "semgrep"
    image: str  # pinned by digest in prod
    categories: frozenset[str]  # {"sast"}
    languages: frozenset[str]  # {"python", "javascript", ...}
    timeout_seconds: int = 900
    memory_limit: str = "2g"
    native_sarif: bool = False
    writable_volumes: tuple[str, ...] = ()  # container paths needing a throwaway rw volume
    output_name: str = "result.json"  # the file the tool writes inside the output directory
    tmp_size: str = "64m"  # size of the throwaway /tmp (Go's build cache needs more)


@dataclass(frozen=True)
class RepoContext:
    """What we know about the target repo; drives ToolAdapter.applies_to()."""

    root: Path
    languages: frozenset[str] = field(default_factory=frozenset)
    has_dockerfile: bool = False
    has_iac: bool = False
    lockfiles: tuple[str, ...] = ()
    has_image_archive: bool = False  # a `docker save` archive named bulwark-image.tar is present


class ToolAdapter(ABC):
    spec: ToolSpec

    @abstractmethod
    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        """Argv executed inside the container. Must write results to `output`.

        `ctx` (optional) lets a tool narrow its work to what the repo actually contains.
        """

    @abstractmethod
    def parse(self, raw: bytes) -> list[Finding]:
        """Raw tool output -> canonical Findings.

        Must never raise on malformed input; return [] and log instead.
        """

    def applies_to(self, ctx: RepoContext) -> bool:
        """Skip this tool when the repo has no relevant files."""
        return bool(ctx.languages & self.spec.languages)
