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
`--security-opt=no-new-privileges`, an ephemeral container, and the same wall-clock timeout +
`docker kill` pattern `core.runner.run_tool` already uses. `core/adapters/base.py`'s per-scanner
`--cap-drop=ALL`/non-root user are deliberately NOT carried over here: installing a project's own
dependencies needs capabilities (arbitrary filesystem writes as whatever user the base image
defaults to, at minimum) a locked-down scanner never does, and picking the exact minimal capability
set for arbitrary language ecosystems' build tooling is real, ecosystem-specific work this pass
doesn't attempt -- default Docker capabilities (not `--privileged`, still namespaced, still not
`--cap-drop=ALL`'s opposite) is the honest, disclosed floor here, not a guessed-at middle ground.
This is exactly the gap ADR-0015/ADR-0027 point at Firecracker (Phase 11, not yet built) to close
properly; this function is the plan's own "hardened Docker runner, for now."

Week 46 task 3 (plan §22.1) adds network-layer egress denial, on by default
(`TestRunSpec.deny_internal_egress`): the target container is started detached and held behind a
startup barrier -- a file it polls for on a read-only bind mount -- until
`core.fixagent.egress.apply_egress_policy` has loaded a default-drop-plus-allowlist ruleset into its
network namespace from the outside, via a sidecar container. See that module's docstring for why a
sidecar rather than the target's own (arbitrary, caller-supplied) image, and for the live-verified
ordering details. `deny_internal_egress=False` reproduces the exact original, fully-open-network
behavior for a caller that genuinely needs it (e.g. a private registry on a non-standard port); this
project's own default posture is deny, not that fallback.
"""

from __future__ import annotations

import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.config import scratch_dir
from core.fixagent.egress import EgressPolicyError, apply_egress_policy
from core.fixagent.verify import VerificationStep

DEFAULT_MEMORY = "2g"
DEFAULT_CPUS = 2.0
DEFAULT_PIDS_LIMIT = 512
DEFAULT_TIMEOUT_S = 300  # 5 minutes: a slice of the per-attempt budget (core/fixagent/limits.py)
_BARRIER_MOUNT = "/bulwark-egress"
_BARRIER_FILE = "ready"


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
    deny_internal_egress: bool = True  # Week 46 task 3: metadata + RFC1918 blocked by default


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


def _argv_with_egress_barrier(
    spec: TestRunSpec, checkout: Path, container_name: str, barrier_dir: Path
) -> list[str]:
    """Like _argv, but detached (`-d`, no `--rm` -- the caller reads `docker logs` and removes it
    explicitly, since `--rm` racing the caller's own post-exit `docker logs` call could lose the
    output) and held behind a startup barrier until the caller applies the egress policy."""
    wait_and_run = (
        f"while [ ! -e {_BARRIER_MOUNT}/{_BARRIER_FILE} ]; do sleep 0.05; done; {spec.command}"
    )
    return [
        "docker", "run", "-d", "--name", container_name,
        "--security-opt=no-new-privileges",
        f"--memory={spec.memory}", f"--cpus={spec.cpus:g}", f"--pids-limit={DEFAULT_PIDS_LIMIT}",
        "--label=bulwark.managed=1", "--label=bulwark.fixagent=1",
        "-v", f"{checkout.resolve()}:/work",
        "-v", f"{barrier_dir.resolve()}:{_BARRIER_MOUNT}:ro",
        "-w", "/work",
        spec.image, "sh", "-c", wait_and_run,
    ]  # fmt: skip


def run_tests(checkout: Path, spec: TestRunSpec) -> VerificationStep:
    """Never raises for a failing or timed-out test run -- both are ordinary verification outcomes
    (`VerificationStep(passed=False, ...)`), the same contract `core.runner.run_tool` already has
    for scanners. Raises `SandboxError` for an environment problem: no `docker` binary, or --
    when `spec.deny_internal_egress` is True -- a failure to apply the egress policy itself, which
    must never be silently skipped in favor of running the target unprotected."""
    if not spec.deny_internal_egress:
        return _run_tests_without_egress_policy(checkout, spec)
    return _run_tests_with_egress_policy(checkout, spec)


def _run_tests_without_egress_policy(checkout: Path, spec: TestRunSpec) -> VerificationStep:
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


def _run_tests_with_egress_policy(checkout: Path, spec: TestRunSpec) -> VerificationStep:
    name = f"bulwark-fixagent-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="bulwark-egress-", dir=scratch_dir()) as tmp:
        barrier_dir = Path(tmp)
        start_argv = _argv_with_egress_barrier(spec, checkout, name, barrier_dir)
        try:
            start = subprocess.run(
                start_argv, capture_output=True, timeout=spec.timeout_s, check=False
            )
        except FileNotFoundError as exc:
            raise SandboxError("docker is not installed or not on PATH") from exc
        if start.returncode != 0:
            stderr = start.stderr.decode("utf-8", errors="replace")
            raise SandboxError(f"failed to start sandbox container: {stderr}")

        try:
            apply_egress_policy(name)
        except EgressPolicyError as exc:
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            raise SandboxError(f"failed to apply egress policy, aborting: {exc}") from exc
        (barrier_dir / _BARRIER_FILE).touch()

        try:
            wait = subprocess.run(
                ["docker", "wait", name], capture_output=True, timeout=spec.timeout_s, check=False
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            return VerificationStep("run_tests", False, f"timed out after {spec.timeout_s}s")

        logs = subprocess.run(["docker", "logs", name], capture_output=True, check=False)
        exit_code_raw = wait.stdout.decode("utf-8", errors="replace").strip()
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)

        exit_code = int(exit_code_raw) if exit_code_raw.isdigit() else -1
        if exit_code == 0:
            return VerificationStep("run_tests", True, "tests passed")
        tail = logs.stdout.decode("utf-8", errors="replace")[-2000:]
        return VerificationStep("run_tests", False, f"exit code {exit_code}: {tail}")
