"""Sandboxed Docker runner (ADR-002, threats T1/T2/T6).

One ephemeral container per tool: no network, read-only rootfs, all caps dropped,
non-root, resource caps, wall-clock timeout. The target is mounted read-only; the
only writable path is the output directory.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter
from core.config import scratch_dir

CONTAINER_TARGET = "/target"
CONTAINER_OUT = "/out"
OUTPUT_NAME = "result.json"


class RunnerError(Exception):
    pass


@dataclass(frozen=True)
class RunResult:
    tool: str
    status: str  # "ok" | "timeout" | "error"
    exit_code: int | None
    raw: bytes
    stderr: str


def build_docker_argv(
    adapter: ToolAdapter,
    target: Path,
    out_dir: Path,
    container_name: str,
    ctx: RepoContext | None = None,
) -> list[str]:
    spec = adapter.spec
    tool_cmd = adapter.build_command(
        Path(CONTAINER_TARGET), Path(CONTAINER_OUT) / spec.output_name, ctx
    )
    # Docker refuses `--cpus` above the host's actual CPU count outright ("range of CPUs is
    # from 0.01 to N.NN, as there are only N CPUs available") -- it's not a soft cap. A tool
    # tuned against a beefier dev machine (e.g. trivy/semgrep at cpus=4) then fails every single
    # run, deterministically, on a smaller host such as a GitHub Actions runner's 2 CPUs. This
    # isn't the flakiness `pytest-rerunfailures` (tests/integration/test_tools_docker.py) was
    # added for -- retrying the identical argv against the identical host fails the same way
    # every time -- so it has to be fixed at the source: clamp to what the host actually has.
    effective_cpus = min(spec.cpus, os.cpu_count() or spec.cpus)
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--user=10001:10001",
        "--security-opt=no-new-privileges",
        f"--memory={spec.memory_limit}",
        f"--cpus={effective_cpus:g}",
        "--pids-limit=256",
        "--label=bulwark.managed=1",
        f"--tmpfs=/tmp:rw,noexec,nosuid,size={spec.tmp_size}",
        *[a for vol in spec.writable_volumes for a in ("-v", vol)],
        "-v",
        f"{target.resolve()}:{CONTAINER_TARGET}:ro",
        "-v",
        f"{out_dir.resolve()}:{CONTAINER_OUT}",
        spec.image,
        *tool_cmd,
    ]


def run_tool(adapter: ToolAdapter, target: Path, ctx: RepoContext | None = None) -> RunResult:
    """Run one adapter in a sandbox. Never raises for tool failure; reports status instead."""
    spec = adapter.spec
    name = f"bulwark-{spec.name}-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="bulwark-out-", dir=scratch_dir()) as tmp:
        out_dir = Path(tmp)
        out_dir.chmod(0o777)  # container runs as a non-root uid
        argv = build_docker_argv(adapter, target, out_dir, name, ctx)
        try:
            proc = subprocess.run(
                argv, capture_output=True, timeout=spec.timeout_seconds, check=False
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            return RunResult(spec.name, "timeout", None, b"", "wall-clock timeout")
        except FileNotFoundError as exc:
            raise RunnerError("docker is not installed or not on PATH") from exc

        out_file = out_dir / spec.output_name
        raw = out_file.read_bytes() if out_file.exists() else b""
        stderr = proc.stderr.decode("utf-8", errors="replace")[-2000:]
        # Scanners commonly exit non-zero when findings exist; output presence is the signal.
        status = "ok" if raw else "error"
        return RunResult(spec.name, status, proc.returncode, raw, stderr)
