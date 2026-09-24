"""Sandboxed Docker runner (ADR-002, threats T1/T2/T6).

One ephemeral container per tool: no network, read-only rootfs, all caps dropped,
non-root, resource caps, wall-clock timeout. The target is mounted read-only; the
only writable path is the output directory.
"""

from __future__ import annotations

import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.adapters.base import ToolAdapter

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
    adapter: ToolAdapter, target: Path, out_dir: Path, container_name: str
) -> list[str]:
    spec = adapter.spec
    tool_cmd = adapter.build_command(Path(CONTAINER_TARGET), Path(CONTAINER_OUT) / OUTPUT_NAME)
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
        "--cpus=1.0",
        "--pids-limit=256",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
        "-v",
        f"{target.resolve()}:{CONTAINER_TARGET}:ro",
        "-v",
        f"{out_dir.resolve()}:{CONTAINER_OUT}",
        spec.image,
        *tool_cmd,
    ]


def run_tool(adapter: ToolAdapter, target: Path) -> RunResult:
    """Run one adapter in a sandbox. Never raises for tool failure; reports status instead."""
    spec = adapter.spec
    name = f"bulwark-{spec.name}-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="bulwark-out-") as tmp:
        out_dir = Path(tmp)
        out_dir.chmod(0o777)  # container runs as a non-root uid
        argv = build_docker_argv(adapter, target, out_dir, name)
        try:
            proc = subprocess.run(
                argv, capture_output=True, timeout=spec.timeout_seconds, check=False
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            return RunResult(spec.name, "timeout", None, b"", "wall-clock timeout")
        except FileNotFoundError as exc:
            raise RunnerError("docker is not installed or not on PATH") from exc

        out_file = out_dir / OUTPUT_NAME
        raw = out_file.read_bytes() if out_file.exists() else b""
        stderr = proc.stderr.decode("utf-8", errors="replace")[-2000:]
        # Scanners commonly exit non-zero when findings exist; output presence is the signal.
        status = "ok" if raw else "error"
        return RunResult(spec.name, status, proc.returncode, raw, stderr)
