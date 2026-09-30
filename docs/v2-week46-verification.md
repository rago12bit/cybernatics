# Week 46 verification -- SandboxRuntime interface, gvisor backend, egress denial (plan §22.1)

Honest record of what was built, run, and measured. See
[ADR-0031](adr/0031-sandbox-runtime-and-egress-denial.md) for the design decisions, including which
parts of the plan's "Isolation v2" this deliberately does not attempt yet.

## What was built

- `core/sandbox/` (task 1): `runtime.py` (the `SandboxRuntime` protocol), `docker_runtime.py`
  (`build_docker_argv` moved here unchanged, `DockerRuntime`). `core/runner.py` refactored to take an
  optional `runtime`, defaulting to `DockerRuntime` -- a pure refactor, not a behavior change.
- `core/sandbox/gvisor_runtime.py` + `seccomp.py` (task 2): `GvisorRuntime` reuses
  `build_docker_argv` verbatim and inserts `--runtime=runsc`. A seccomp-profile hook is wired in but
  returns `None` for every scanner today -- see ADR-0031 for why.
- `core/fixagent/egress.py`, `docker/egress-sidecar/` (task 3): a default-drop nftables ruleset
  (DNS + HTTP/S allowed, cloud-metadata range and RFC1918 denied, IPv6 dropped outright) applied to
  the fix-verification sandbox's target container via a sidecar joined to its network namespace.
  `core/fixagent/sandbox.py`'s `run_tests` now starts the target detached behind a startup barrier,
  applies the policy, then releases it -- on by default (`TestRunSpec.deny_internal_egress=True`),
  with an explicit opt-out that reproduces the original behavior exactly.
- `docs/adr/0031-*.md`, `docs/sandbox-runtimes.md` (task 4, this document).

## Validated against real, live things -- not mocks

- **`DockerRuntime`'s argv, against the pre-refactor `build_docker_argv`.** Byte-for-byte equality
  asserted directly (`test_docker_runtime_build_argv_matches_the_free_function`), not just "the tests
  still pass" -- the two code paths are proven identical, not just similarly-behaved.
- **The full existing test suite, unchanged, before and after the task 1 refactor.** 1399 tests
  passed both times; `core.scan` and `core.sbom.syft`'s calls into `run_tool` were never touched.
- **The egress ruleset's actual packet-filtering behavior, against a real container** (Docker
  Desktop on macOS -- a real Linux VM under the hood). Not a syntax check: a `python:3.12-slim`
  container with `nftables`/`curl` installed for the exercise confirmed, with real network calls,
  that HTTPS to pypi.org succeeds, that the metadata IP and an RFC1918 address both time out (a real
  `DROP`, not merely "nothing was listening"), and that DNS resolution keeps working. This caught two
  real bugs before either shipped:
  - **RFC1918-before-DNS ordering broke every package install.** Docker Desktop's own embedded DNS
    resolver is `192.168.65.x` -- inside the RFC1918 ranges the ruleset denies. The very first version
    of the ruleset denied that range before allowing DNS, so `getent hosts pypi.org` failed outright.
    Fixed by moving the DNS-allow rules earlier in the chain; DNS now resolves regardless.
  - **An unmirrored IPv6 allow bypassed every IPv4 deny rule.** The ruleset's `tcp dport {80,443}
    accept` rule, written in an `inet`-family table, applies to both protocol families, but the deny
    rule (`ip daddr {...}`) is IPv4-only. `curl -6 https://pypi.org` succeeded even with the "blocking"
    ruleset loaded. Fixed by dropping IPv6 outright (`meta nfproto ipv6 drop`) rather than trying to
    author and keep in sync a second, IPv6-specific deny list for a protocol this sandbox has no real
    need for.
- **The full `run_tests` orchestration, against real Docker, not mocked `subprocess.run`.** Three
  separate real runs: (1) the default egress-enforced path with a `python:3.12-slim` target proving
  both "pypi reachable" and "metadata blocked" in one process, exit code 0, `VerificationStep(passed=
  True)`; (2) the same target with a deliberately failing script, confirming the real exit code and
  log tail surface correctly through `docker wait`/`docker logs`; (3) `deny_internal_egress=False`
  against a script that asserts the metadata IP is reachable, confirming the fallback path is not
  merely present in code but actually skips the sidecar and its restriction.
- **The `docker/egress-sidecar` image, built and run for real**, including confirming its pinned
  `nftables=1.0.6-2+deb12u2` package version is the one Debian 12's own repository actually serves
  (checked via `apt-cache policy` before pinning it, not assumed), and reading its installed
  package's own `copyright` file to confirm the real license (`GPL-2`) before adding the
  `scripts/gen-licenses.py` `TOOLS` entry, rather than guessing.

## Verified

- `test_sandbox_runtime.py` (4 tests), `test_sandbox_gvisor.py` (5 tests), `test_sandbox_seccomp.py`
  (2 tests), `test_fixagent_sandbox.py` (rewritten: 13 tests covering both the egress-enforced default
  and the legacy fallback), `test_fixagent_egress.py` (8 tests). Full suite re-run clean after every
  task: 1420 passed. `black --check .`, `ruff check .`, `mypy` all clean.
  `scripts/gen-licenses.py --check` passes with the new `egress-sidecar` entry.
- Live Docker runs, above -- both the standalone sidecar mechanism and the full `run_tests` path
  through the real Python code, not just the shell commands used to first work out the ruleset.

## What this does NOT prove (read before relying on it)

- **`GvisorRuntime` has never actually executed.** `runsc` has no macOS build. Every assertion about
  it is an argv-shape unit test (it produces `--runtime=runsc` in the right place, preserves every
  Docker flag, adds the seccomp flag when a profile is given). Whether a real scanner actually runs
  correctly under gVisor's syscall emulation -- and gVisor's syscall coverage is not 100% of Linux's,
  so this is a real open question, not a formality -- is untested. `core.runner.run_tool` does not use
  this backend anywhere in production.
- **No seccomp profile exists.** `seccomp_profile_path` always returns `None`. The plumbing is real;
  the content is not, and shipping a guessed one would have been a security regression (see
  ADR-0031 for exactly why).
- **Firecracker does not exist in this codebase.** Not a stub, not a partial implementation --
  nothing. The architectural question of how a checkout gets into a microVM was identified but not
  resolved.
- **Egress denial adds real latency and a real failure mode per test run**: a sidecar container start
  plus an `nft -f -` invocation (typically well under a second in this project's own testing, but
  unmeasured under real production load), and `EgressPolicyError` is a hard stop, by design -- a
  fix-verification run that can't get its policy applied does not silently fall back to running the
  target unprotected, but it does mean a sidecar-image pull failure or Docker daemon hiccup now fails
  a verification attempt that would previously have succeeded.
- **No Linux host exists for this project.** Every "verified live" claim above ran on Docker Desktop
  on a macOS development machine -- a real Linux VM, which is what makes the egress-denial testing
  meaningful, but not a host this project controls, has `gvisor` installed on, or has wired into CI.
  `docs/sandbox-runtimes.md`'s runbook describes, but does not perform, that setup.
- **The egress policy is IPv4-only and covers exactly one sandbox.** IPv6 is dropped entirely rather
  than policed (a deliberate scope reduction, not an oversight -- see ADR-0031). Scanner containers
  (`core/runner.py`) are unaffected and unchanged: they already run with `--network=none` and have no
  egress to police in the first place.
