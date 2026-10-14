"""The default SandboxRuntime backend: runc via the host Docker daemon (ADR-002, threats T1/T2/T6).

Moved here from core.runner unchanged in Week 46 task 1 (plan §22.1) when the SandboxRuntime
interface was introduced -- core.runner re-exports build_docker_argv, CONTAINER_TARGET, and
CONTAINER_OUT from this module so every existing import (`from core.runner import
build_docker_argv`, used by tests/unit/test_runner.py and tests/unit/test_tier2_adapters.py) and
every existing call site keeps working with no behavior change: this is a pure refactor.

One ephemeral container per tool: no network, read-only rootfs, all caps dropped, non-root,
resource caps, wall-clock timeout. The target is mounted read-only; the only writable path is the
output directory. This is the boundary Bulwark has run on since v1 and the only one available on
macOS -- runc enforces it via the host's real kernel (namespaces + cgroups), unlike the gvisor
backend (core.sandbox.gvisor_runtime), which interposes a userspace kernel in front of it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter

CONTAINER_TARGET = "/target"
CONTAINER_OUT = "/out"

#: Images Bulwark builds from this repository (docker/<tool>/Dockerfile) and never publishes.
LOCAL_NAMESPACE = "bulwark/"


def image_tag(image: str) -> str:
    """The tag, also of an image pinned by digest: "repo:v8.21.0@sha256:..." -> "v8.21.0"."""
    return image.split("@", 1)[0].rsplit(":", 1)[-1]


def pull_policy(image: str) -> list[str]:
    """`--pull=never` for an image Bulwark builds itself: with Docker's default (`missing`), an
    image not built here is fetched as `docker.io/bulwark/<tool>` -- a Docker Hub namespace
    Bulwark does not own, so whoever registers it would have their image run as a scanner. Never
    pulling makes it a "No such image" error instead. Other images keep the default: those pinned
    by digest (cosign, the PDF renderer) cannot change, and a plugin's image is pulled after its
    publisher's signature is checked (core.plugins.signing)."""
    return ["--pull=never"] if image.startswith(LOCAL_NAMESPACE) else []


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
        *pull_policy(spec.image),
        spec.image,
        *tool_cmd,
    ]


@dataclass(frozen=True)
class DockerRuntime:
    """The runc backend. Default for core.runner.run_tool; the only backend available on macOS."""

    name: str = "docker"

    def build_argv(
        self,
        adapter: ToolAdapter,
        target: Path,
        out_dir: Path,
        container_name: str,
        ctx: RepoContext | None = None,
    ) -> list[str]:
        return build_docker_argv(adapter, target, out_dir, container_name, ctx)
