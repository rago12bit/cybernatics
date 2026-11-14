"""Runs one scanner adapter in a SandboxRuntime and returns its result (ADR-002, threats T1/T2/T6).

Refactored in Week 46 task 1 (plan §22.1, ADR-0031) to take a core.sandbox.runtime.SandboxRuntime
instead of always building a Docker argv itself -- defaults to
core.sandbox.docker_runtime.DockerRuntime so every existing caller (core.scan, core.sbom.syft) and
every existing test keeps its exact prior behavior. build_docker_argv, CONTAINER_TARGET, and
CONTAINER_OUT are re-exported from core.sandbox.docker_runtime unchanged so
`from core.runner import build_docker_argv` keeps working.
"""

from __future__ import annotations

import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter
from core.config import scratch_dir
from core.sandbox.docker_runtime import (
    CONTAINER_OUT,
    CONTAINER_TARGET,
    DockerRuntime,
    build_docker_argv,
)
from core.sandbox.output import OutputRefused, read_output
from core.sandbox.runtime import SandboxRuntime

__all__ = [
    "CONTAINER_OUT",
    "CONTAINER_TARGET",
    "OUTPUT_NAME",
    "RunnerError",
    "RunResult",
    "build_docker_argv",
    "run_tool",
]

OUTPUT_NAME = "result.json"

_DEFAULT_RUNTIME: SandboxRuntime = DockerRuntime()


class RunnerError(Exception):
    pass


@dataclass(frozen=True)
class RunResult:
    tool: str
    status: str  # "ok" | "timeout" | "error"
    exit_code: int | None
    raw: bytes
    stderr: str


def run_tool(
    adapter: ToolAdapter,
    target: Path,
    ctx: RepoContext | None = None,
    *,
    runtime: SandboxRuntime | None = None,
) -> RunResult:
    """Run one adapter in a sandbox. Never raises for tool failure; reports status instead.

    `runtime` selects the isolation backend (core.sandbox.docker_runtime.DockerRuntime,
    core.sandbox.gvisor_runtime.GvisorRuntime, ...) and defaults to Docker -- the only backend
    available on macOS and the one Bulwark has always used. Every backend is still launched
    through the host `docker` CLI (gVisor integrates via `docker run --runtime=runsc`), so the
    timeout/kill/output-reading logic below is shared and backend-agnostic.
    """
    active_runtime: SandboxRuntime = runtime if runtime is not None else _DEFAULT_RUNTIME
    spec = adapter.spec
    name = f"bulwark-{spec.name}-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="bulwark-out-", dir=scratch_dir()) as tmp:
        out_dir = Path(tmp)
        out_dir.chmod(0o777)  # container runs as a non-root uid
        argv = active_runtime.build_argv(adapter, target, out_dir, name, ctx)
        try:
            proc = subprocess.run(
                argv, capture_output=True, timeout=spec.timeout_seconds, check=False
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            return RunResult(spec.name, "timeout", None, b"", "wall-clock timeout")
        except FileNotFoundError as exc:
            raise RunnerError(f"{active_runtime.name} is not installed or not on PATH") from exc

        try:
            raw = read_output(out_dir / spec.output_name) or b""
        except OutputRefused as exc:
            # Not a file the scanner should have left (a link, a FIFO, something huge): the
            # tool failed, and nothing of it is read (core.sandbox.output says why).
            return RunResult(spec.name, "error", proc.returncode, b"", f"scanner output: {exc}")
        stderr = proc.stderr.decode("utf-8", errors="replace")[-2000:]
        # Scanners commonly exit non-zero when findings exist; output presence is the signal.
        status = "ok" if raw else "error"
        return RunResult(spec.name, status, proc.returncode, raw, stderr)
