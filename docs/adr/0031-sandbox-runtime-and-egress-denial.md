# ADR-0031: SandboxRuntime interface, the gvisor backend, and egress denial for fix verification

Status: Partially implemented (2026-10-01), Week 46 (plan §22.1, "Isolation v2"). Tasks 1-3 of 4
shipped; task 4 (a real Linux host to exercise gvisor/Firecracker on, and Firecracker itself) is
explicitly deferred -- see "What is NOT done" below. This is not the full Phase 11 target state
(milestone M10's "scanners run under gvisor and code runs in Firecracker on the Linux host"); it is
the architecture that state will be built on, plus the one piece of it (egress denial) that didn't
need a Linux host to ship for real.

## Context

Every scanner container has run under plain Docker (`runc`) since v1: namespaces and cgroups
enforced by the host's real kernel. That boundary is solid but not layered -- if a scanner's parser
has a real exploit (ADR-002's threats T1/T2), the contained process still executes every syscall in
the host kernel itself. gVisor (`runsc`) interposes a userspace kernel in front of that: it
intercepts and re-implements the syscalls it allows, so an escape from the scanner process still has
to escape `runsc` before reaching a real host syscall. Firecracker goes further still (a microVM,
hardware-virtualization boundary) for the fix-verification agent's "run this project's own tests"
step, which is a fundamentally more permissive posture (network access, a writable tree) than
scanning ever needs.

Both `runsc` and Firecracker are Linux-only. Development on this project happens on macOS. The plan
is explicit about the consequence: keep developing with the existing Docker setup locally, run the
hardened runtimes on a Linux host. Week 46 is the first pass at that architecture.

## Decisions

### One interface, chosen by configuration, not by branching call sites

`core.sandbox.runtime.SandboxRuntime` is a `Protocol` with a single method,
`build_argv(adapter, target, out_dir, container_name, ctx) -> list[str]`. `core.runner.run_tool`
takes an optional instance of it and defaults to `DockerRuntime`, so every existing call site
(`core.scan`, `core.sbom.syft`) and every existing test keeps its exact prior behavior -- Week 46
task 1 is a pure refactor, not a new feature, verified by running the full existing suite unchanged
before and after (1399 tests, byte-identical `build_docker_argv` output).

### gvisor is `docker run --runtime=runsc`, nothing more exotic

`core.sandbox.gvisor_runtime.GvisorRuntime` reuses `build_docker_argv` verbatim and inserts one flag.
This was a deliberate choice over building a separate execution path: gVisor's own documented,
standard integration point for the common case *is* `docker run --runtime=runsc` -- there is no
separate CLI most deployments need. Reusing the argv verbatim also means the gvisor backend can never
accidentally loosen the container contract (mounts, resource limits, `no-new-privileges`,
`cap-drop=ALL`); it can only add a deeper enforcement layer underneath it. This cannot be executed on
this dev machine (no macOS build of `runsc`), so verification here is argv-shape tests only,
disclosed as such rather than claimed as a real run.

### No custom seccomp profile ships yet -- a naive one would be a regression, not hardening

`--security-opt=seccomp=<file>` *replaces* Docker's own default seccomp profile; it does not layer
on top of it. Docker's real default is a deny-by-default allowlist of roughly 300 syscalls, curated
and battle-tested upstream. The only custom profile safe to author without a Linux host to verify it
against is the "mostly allow, deny a few dangerous syscalls" shape -- which is strictly *weaker* than
Docker's real default, not stronger. Shipping that as "hardening" would be a real security regression
dressed up as one. `core.sandbox.seccomp.seccomp_profile_path` is fully wired into `GvisorRuntime`
but returns `None` for every scanner today: Docker's real default stays in effect, unmodified.
Building a genuinely tighter profile needs either a vendored-and-trimmed copy of Docker's actual
default.json or syscalls observed via `strace` on a real run -- both real, disclosed, deferred work,
matching the precedent `core/fixagent/sandbox.py` already set for capability sets in Week 42.

### Egress denial is applied from outside the target container, by a purpose-built sidecar

The fix-verification sandbox's target image (`TestRunSpec.image`) is caller-supplied and arbitrary --
`python:3.12-slim`, `node:20-slim`, anything. Nothing guarantees it has `nftables` installed, and
installing it at runtime would need network access before any restriction exists: a chicken-and-egg
problem for the very thing being restricted. `docker/egress-sidecar` is a small, purpose-built image
(Debian slim + `nftables`, pinned) that joins the target's network namespace via
`docker run --network=container:<name>` and loads a ruleset into it from the outside. nftables rules
are a property of the network namespace, not of any one container's filesystem, so this works
regardless of what the target image contains -- verified live against a real `python:3.12-slim`
target with no nftables of its own.

To close the window between the target container starting and the policy landing, the target is
started detached, behind a startup barrier (`while [ ! -e /bulwark-egress/ready ]; do sleep 0.05;
done; <command>`, backed by a bind-mounted file the orchestrator touches only after the sidecar
confirms the ruleset loaded). A caller that genuinely needs the old, fully-open-network behavior
(e.g. a private registry on a non-standard port) can set `deny_internal_egress=False`, which
reproduces the original single-container code path exactly; the project's own default posture is
deny.

### The egress ruleset's exact shape came from live testing, not from writing it once and trusting it

Two real bugs were found and fixed before this shipped, both by running the ruleset against a real
container rather than reviewing it by eye:
- Denying all of RFC1918 before allowing DNS broke every package install, because Docker Desktop's
  own embedded DNS resolver lives in RFC1918 space (`192.168.65.x` on the machine this was verified
  on). Fixed by moving the DNS-allow rules before the denied-range check.
- An `inet`-family table's `tcp dport {80,443} accept` rule applies to both IPv4 and IPv6, but the
  deny rule was IPv4-only (`ip daddr {...}`) -- so `curl -6` reached a host the IPv4 rule fully
  blocked. Fixed by dropping IPv6 outright (`meta nfproto ipv6 drop`) rather than trying to keep two
  rule sets in sync for a protocol this sandbox has no real need for.

See `docs/v2-week46-verification.md` for the full verification record.

### Firecracker is explicitly descoped this pass, not silently dropped

Firecracker needs a kernel image, a rootfs image, and a resolved architectural choice for getting a
project's checkout into a microVM at all -- bake it into the rootfs per run (simple, slow), pass it
via virtiofs (needs a vhost-user-fs daemon), or fetch it over network inside the guest (reintroduces
exactly the network exposure this ADR's egress-denial decision exists to close). None of these can be
chosen and then verified without a Linux host with KVM, which this pass does not have. The plan's own
risk register (R12, R13) and its "drop in this order if time runs short" list both name Firecracker
as the first thing to cut, in favor of exactly what task 3 did instead: harden the existing Docker
sandbox. This is tracked as real, open, Linux-host-blocked work -- not something this ADR claims to
have solved.

## What is NOT done

- **No gvisor run has ever actually executed.** Every gvisor-path assertion in this codebase is an
  argv-shape test. The backend is not selected by anything in production; `core.runner.run_tool`
  still defaults to `DockerRuntime` everywhere.
- **No seccomp profile is applied.** The hook exists; it always returns `None`.
- **Firecracker does not exist in this codebase at all** -- not even as an unused stub. Building one
  without being able to verify it was judged worse than not building it.

  *Amended 2026-10-12:* built (`core.sandbox.firecracker`), for the fix agent's test runs only,
  because most of it could be verified after all. The checkout is baked in per run, as a second ext4
  disk; the guest has no network; init reports the exit code on the serial console after killing
  every other process. The guest side was booted for real -- under QEMU's software emulation, with
  disks this module built from a real image -- and behaved as designed. Firecracker itself still
  needs a KVM host: `tests/integration/test_firecracker_live.py` runs there and skips here.
- **No Linux host exists yet.** Nothing here was run anywhere but this macOS dev machine's Docker
  Desktop (a real Linux VM under the hood, which is what makes the egress-denial live testing
  meaningful -- but it is not a host this project controls, has gvisor installed, or can be wired
  into CI as a runner).
- **Egress denial only covers the fix-verification sandbox.** Scanner containers already have
  `--network=none` and don't need it; nothing else in this codebase runs untrusted code with network
  access.

Closing these needs a real Linux host: install Docker + `runsc` + (eventually) Firecracker, smoke-test
`GvisorRuntime` for real, resolve and build the Firecracker checkout-delivery mechanism, then wire
the host into CI so this doesn't regress silently. That work is described, not performed, in
`docs/sandbox-runtimes.md`.
