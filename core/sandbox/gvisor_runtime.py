"""The gvisor SandboxRuntime backend: runsc via Docker's --runtime flag (Week 46 task 2, plan
§22.1, ADR-0031).

Linux only. `runsc` has no macOS build, so this backend cannot be exercised on a Mac dev machine --
only written and reviewed here, then smoke-tested on a real Linux host once one exists (Week 46
task 4). Until then it is unused in production; core.runner.run_tool still defaults to
core.sandbox.docker_runtime.DockerRuntime everywhere. This gap is disclosed, not hidden, in
docs/v2-week46-verification.md once that doc exists.

What gVisor actually buys over plain Docker (runc): runc's container boundary is namespaces +
cgroups enforced by the host's REAL kernel -- every syscall the contained process makes still
executes in the host kernel. gVisor replaces that with `runsc`, a userspace kernel (written in Go)
that intercepts every syscall a container makes and re-implements the ones it allows, entirely in
userspace. A scanner parser exploit that escapes the scanner process still has to escape runsc's own
attack surface before it ever reaches a real host syscall. This is a deeper backstop for the exact
threat this project has always cared about (a scanner parses attacker-controlled source, ADR-002 T1)
-- not a new policy: the argv itself (mounts, resource limits, no-new-privileges, cap-drop=ALL) is
untouched, reused verbatim from core.sandbox.docker_runtime.build_docker_argv.

gVisor's own documented, standard integration point IS `docker run --runtime=runsc` -- there is no
separate CLI or API for the common case, which is why this backend still goes through
core.runner.run_tool's existing subprocess/timeout/`docker kill` handling unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter
from core.sandbox.docker_runtime import build_docker_argv
from core.sandbox.seccomp import seccomp_profile_path

RUNTIME_FLAG = "--runtime=runsc"


@dataclass(frozen=True)
class GvisorRuntime:
    """Same container as DockerRuntime, run under `runsc` instead of `runc`, plus this scanner's
    seccomp profile if one exists (core.sandbox.seccomp -- currently always None; see that
    module's docstring for why a profile isn't authored yet)."""

    name: str = "gvisor"

    def build_argv(
        self,
        adapter: ToolAdapter,
        target: Path,
        out_dir: Path,
        container_name: str,
        ctx: RepoContext | None = None,
    ) -> list[str]:
        argv = build_docker_argv(adapter, target, out_dir, container_name, ctx)
        # Inserted right after "run" so it reads next to --rm/--name, matching how the rest of
        # build_docker_argv's flags are grouped.
        run_index = argv.index("run")
        extra = [RUNTIME_FLAG]
        profile = seccomp_profile_path(adapter.spec.name)
        if profile is not None:
            extra.append(f"--security-opt=seccomp={profile}")
        return argv[: run_index + 1] + extra + argv[run_index + 1 :]
