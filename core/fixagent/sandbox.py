"""A test-execution sandbox for the verified-fix agent's opt-in "run project tests" step (plan
§21.2) -- deliberately separate from `core/runner.py`'s scanner sandbox, not a mode of it.

`core.runner.build_docker_argv` is `--network=none` and read-only by design: a scanner reads code,
it never needs to fetch a dependency or write anywhere but its own output directory. Running a
project's own test suite is the opposite shape -- it typically needs `pip install`/`npm install`
(network) and a writable tree (caches, `__pycache__`, node_modules) -- so bolting that onto the
scanner runner's contract would either weaken every scanner's isolation to accommodate it, or need a
runtime branch inside one function serving two very different trust levels. A second, explicitly
more permissive function is safer to reason about than one function with a "but not for scanners"
exception.

Still hardened where it doesn't conflict with the above: resource limits, `--pids-limit`,
`--security-opt=no-new-privileges`, an ephemeral `--rm` container, and the same wall-clock timeout +
`docker kill` pattern `core.runner.run_tool` already uses. `core/adapters/base.py`'s per-scanner
`--cap-drop=ALL`/non-root user are deliberately NOT carried over here: installing a project's own
dependencies needs capabilities (arbitrary filesystem writes as whatever user the base image
defaults to, at minimum) a locked-down scanner never does, and picking the exact minimal capability
set for arbitrary language ecosystems' build tooling is real, ecosystem-specific work this pass
doesn't attempt -- default Docker capabilities (not `--privileged`, still namespaced, still not
`--cap-drop=ALL`'s opposite) is the honest, disclosed floor here, not a guessed-at middle ground.
This is exactly the gap ADR-0015/ADR-0027 point at Firecracker (Phase 11, not yet built) to close
properly; this function is the plan's own "hardened Docker runner, for now."
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.fixagent.verify import VerificationStep

DEFAULT_MEMORY = "2g"
DEFAULT_CPUS = 2.0
DEFAULT_PIDS_LIMIT = 512
DEFAULT_TIMEOUT_S = 300  # 5 minutes: a slice of the per-attempt budget (core/fixagent/limits.py)


class SandboxError(Exception):
    pass


@dataclass(frozen=True)
class TestRunSpec:
    __test__ = False  # pytest: not a test class, despite the name (it configures a test *run*)

    image: str  # e.g. "python:3.12-slim", "node:20-slim" -- language-specific, caller's choice
    command: str  # run through `sh -c`, e.g. "pip install -r requirements.txt && pytest -q"
    memory: str = DEFAULT_MEMORY
    cpus: float = DEFAULT_CPUS
    timeout_s: int = DEFAULT_TIMEOUT_S


def _argv(spec: TestRunSpec, checkout: Path, container_name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--name", container_name,
        "--security-opt=no-new-privileges",
        f"--memory={spec.memory}", f"--cpus={spec.cpus:g}", f"--pids-limit={DEFAULT_PIDS_LIMIT}",
        "--label=bulwark.managed=1", "--label=bulwark.fixagent=1",
        "-v", f"{checkout.resolve()}:/work",
        "-w", "/work",
        spec.image, "sh", "-c", spec.command,
    ]  # fmt: skip


def run_tests(checkout: Path, spec: TestRunSpec) -> VerificationStep:
    """Never raises for a failing or timed-out test run -- both are ordinary verification outcomes
    (`VerificationStep(passed=False, ...)`), the same contract `core.runner.run_tool` already has
    for scanners. Only raises `SandboxError` for an environment problem (no `docker` binary)."""
    name = f"bulwark-fixagent-{uuid.uuid4().hex[:8]}"
    argv = _argv(spec, checkout, name)
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=spec.timeout_s, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True, check=False)
        return VerificationStep("run_tests", False, f"timed out after {spec.timeout_s}s")
    except FileNotFoundError as exc:
        raise SandboxError("docker is not installed or not on PATH") from exc
    if proc.returncode == 0:
        return VerificationStep("run_tests", True, "tests passed")
    tail = proc.stdout.decode("utf-8", errors="replace")[-2000:]
    return VerificationStep("run_tests", False, f"exit code {proc.returncode}: {tail}")
