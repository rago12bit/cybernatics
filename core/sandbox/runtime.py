"""The SandboxRuntime interface (Week 46 task 1, plan §22.1, ADR-0031).

One shape, multiple backends, so switching which kernel enforces a scanner container's isolation is
configuration (which SandboxRuntime instance core.runner.run_tool is given) rather than a change to
any call site. Every backend produces the SAME container contract -- same image, same mounts, same
resource limits, same no-network/read-only/cap-drop=ALL/non-root flags from
core.sandbox.docker_runtime.build_docker_argv -- and differs only in which OCI runtime actually
executes it. Backends never loosen that contract; they only add a deeper enforcement boundary
underneath it (see core.sandbox.gvisor_runtime's module docstring).

Execution mechanics (subprocess.run, wall-clock timeout, `docker kill` on timeout, reading the
output file) stay shared in core.runner.run_tool rather than duplicated per backend: every backend
here is still launched through the host's `docker` CLI (gVisor integrates via `docker run
--runtime=runsc`, not a separate tool), so only argv construction actually varies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from core.adapters.base import RepoContext, ToolAdapter


class SandboxRuntime(Protocol):
    """Builds the argv for one scanner container run. Stateless and side-effect-free: callers are
    responsible for actually running it (core.runner.run_tool does this uniformly for every
    backend)."""

    @property
    def name(self) -> str: ...  # read-only, so a frozen dataclass field satisfies it

    def build_argv(
        self,
        adapter: ToolAdapter,
        target: Path,
        out_dir: Path,
        container_name: str,
        ctx: RepoContext | None = None,
    ) -> list[str]: ...
