# Sandbox runtimes

Which kernel enforces a scanner container's isolation, and what network a fix-verification test run
can reach, are both now a matter of configuration rather than a code change. Design reasoning is in
[ADR-0031](adr/0031-sandbox-runtime-and-egress-denial.md); the honest verification record, including
two real bugs this caught before shipping, is in
[v2-week46-verification.md](v2-week46-verification.md).

## The SandboxRuntime interface

`core/sandbox/runtime.py` defines one small interface every backend implements: given a tool adapter
and a target, produce the argv to run it. `core/runner.py`'s `run_tool` takes an optional instance of
it and defaults to `DockerRuntime` -- the boundary Bulwark has always run on, and the only one
available on macOS.

| Backend | Where it runs | Status |
|---|---|---|
| `DockerRuntime` (default) | Anywhere Docker runs | In production since v1 |
| `GvisorRuntime` | Linux only, needs `runsc` installed | Written and argv-tested; never actually executed (no Linux dev host) |
| Firecracker | Linux only, needs KVM | Not built -- see ADR-0031 |

`GvisorRuntime` reuses the exact same argv `DockerRuntime` produces and adds one flag
(`--runtime=runsc`): it can only add a deeper enforcement layer, never loosen the existing contract.
A seccomp-profile hook is wired into it but currently always returns `None` -- see ADR-0031 for why
shipping a hand-written profile now would be a regression, not hardening.

## Egress denial for fix verification

`core/fixagent/sandbox.py`'s test-execution sandbox denies egress to the cloud metadata range
(169.254.0.0/16 -- the same SSRF target `core.attackpath` already flags for scanned code) and to
RFC1918 networks, by default. DNS and HTTP(S) to the rest of the internet stay open, so `pip
install`/`npm install` keep working. A purpose-built sidecar (`docker/egress-sidecar`, built as
`bulwark/egress-sidecar:1`) loads the policy into the target's network namespace from the outside, so
it works no matter what's inside the target's own (arbitrary, caller-supplied) image.

```python
from core.fixagent.sandbox import TestRunSpec, run_tests

# Default posture: metadata and internal networks blocked.
run_tests(checkout, TestRunSpec(image="python:3.12-slim", command="pytest -q"))

# Opt out for a case that genuinely needs the old, fully-open network (e.g. a private
# registry on a non-standard port). Reproduces the exact original behavior.
run_tests(checkout, TestRunSpec(image="python:3.12-slim", command="pytest -q",
                                 deny_internal_egress=False))
```

This part is real, live-verified, and running today -- unlike gvisor and Firecracker below.

## Running gvisor for real (not yet done -- a runbook for when it is)

Nothing in this repository has ever executed under `runsc`. This is what closing that gap needs, so
it's an explicit plan rather than an implied "someday":

1. **A Linux host with KVM/nested virtualization**, not a container -- `runsc` needs to run
   alongside the real Docker daemon, not inside another container. A cloud VM (any provider) with
   nested virtualization enabled works; Docker Desktop's own Linux VM on macOS does not expose this
   to an inner `runsc` install.
2. **Install Docker + gVisor's `runsc`** on that host, then register it as a Docker runtime
   (gVisor's own install docs cover the `/etc/docker/daemon.json` `runtimes` entry --
   `docker run --runtime=runsc hello-world` should print gVisor's own banner, not just Docker's).
3. **Smoke-test one real scanner** through `GvisorRuntime` end to end: `run_tool(BanditAdapter(),
   target, runtime=GvisorRuntime())` against a real checkout, confirming the scan still produces the
   same findings a `DockerRuntime` run would -- gVisor's syscall emulation is not 100% coverage of
   every syscall every tool might use, so this has to be checked per scanner, not assumed.
4. **Only then** does authoring a real seccomp profile become possible: either vendor Docker's actual
   default seccomp profile and trim entries a scanner family provably never uses, or `strace` a real
   run of each scanner image and derive a true minimal allowlist. Neither is guessable from a Mac.
5. **Wire the host into CI** (a self-hosted GitHub Actions runner on that box, or an equivalent) so a
   future change to `GvisorRuntime` gets checked automatically instead of silently regressing.

## Running Firecracker for real (not yet started)

Firecracker needs, beyond the Linux+KVM host above: a kernel image, a rootfs image with the target
language runtime baked in, and a resolved answer to "how does the project's checkout get into the
microVM" -- baked into the rootfs per run, passed via virtiofs, or fetched over a controlled network
connection inside the guest. ADR-0031 explains why none of these were chosen blind. This is real,
open design work for whoever picks it up next, not a small follow-up to the gvisor runbook above.
