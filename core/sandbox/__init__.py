"""Sandbox backends for running scanner containers (Week 46, plan §22.1, ADR-0031).

core.sandbox.runtime.SandboxRuntime is the interface; core.sandbox.docker_runtime.DockerRuntime
(the default, all platforms) and core.sandbox.gvisor_runtime.GvisorRuntime (Linux only) are its two
implementations so far. core.runner.run_tool takes a runtime instance and defaults to DockerRuntime,
so choosing a backend is configuration, not a code change at any call site.
"""

from __future__ import annotations
