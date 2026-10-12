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
| Firecracker (`core.sandbox.firecracker`) | Linux only, needs KVM | The fix agent's test runs only (`BULWARK_TEST_SANDBOX=firecracker`). Built 2026-10-12; its guest side booted under QEMU, Firecracker itself never run (no KVM here) |

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

## Firecracker for the fix agent's test runs

`core/sandbox/firecracker.py` runs the fix agent's "run this project's own tests" step in a microVM
when `BULWARK_TEST_SANDBOX=firecracker`: the project's code runs under its own guest kernel, behind
KVM, instead of sharing the host's. Scanners do not use it (they stay on Docker or gVisor).

**How a run works** -- every step without root on the host:

1. The root filesystem is the same image the Docker sandbox would use (`TestRunSpec.image`),
   exported with Docker, unpacked without device nodes, ownership or setuid bits, plus an init
   script and the command, then made into an ext4 image with `mkfs.ext4 -d`.
2. The checkout becomes a second, writable ext4 disk, thrown away afterwards.
3. **No network interface at all**, so a command that installs dependencies fails: use an image
   that already has them.
4. The guest's init runs the command in `/work`, kills every other process, prints the exit code
   on the serial console and reboots, which ends the VM.

A host that cannot run a microVM is an error, never a silent fall-back to Docker.

**Setting up a host** (Linux, x86_64 or arm64, with KVM):

1. Check `/dev/kvm` exists and your user can read and write it (`sudo usermod -aG kvm $USER`, then
   log in again).
2. Install Docker, `e2fsprogs` (for `mkfs.ext4`) and the `firecracker` binary from a Firecracker
   release on GitHub, on your `PATH`.
3. Get an uncompressed guest kernel (`vmlinux`) -- Firecracker's getting-started guide points at
   the ones its own CI uses -- and set `BULWARK_FIRECRACKER_KERNEL` to it.
4. Run `pytest tests/integration/test_firecracker_live.py`: it boots real microVMs (a passing and a
   failing command, and one that tries to reach the network) and skips, saying what is missing,
   anywhere it cannot.

**What has been checked, and what has not.** The unit tests cover the VM document, the init
script, reading the result, the image unpacking (nothing written outside its directory through a
link, `..` or a hard link; setuid bits dropped) and the orchestration. The guest side was booted
for real on 2026-10-12: disks built by this module's own code from a real `python:3.12-slim`, under
QEMU's software emulation in a container (a stock Alpine kernel; no KVM on the Mac). The image's
Python ran, the checkout was at `/work`, a command that printed a fake success marker and exited 3
read as 3, and a leftover background process did not keep the VM up. **Firecracker itself has not
run**: that needs the host above. For production, launch it through Firecracker's `jailer` (chroot,
cgroups, a dedicated uid), as Firecracker recommends; this module runs `firecracker` directly,
which still applies its built-in seccomp filters.
