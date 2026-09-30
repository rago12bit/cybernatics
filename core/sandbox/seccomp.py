"""Per-scanner seccomp profiles for the gvisor SandboxRuntime backend (Week 46 task 2, plan §22.1).

Disclosed scope, honestly: this module has the real, wired-up plumbing (GvisorRuntime already calls
seccomp_profile_path and passes the result to Docker's `--security-opt=seccomp=`), but
`seccomp_profile_path` returns `None` for every scanner today, so no run currently overrides
Docker's own default seccomp profile.

Why not ship a custom profile now: `--security-opt=seccomp=<file>` REPLACES Docker's default
profile, it does not layer on top of it. Docker's real default is deny-by-default with an allowlist
of roughly 300 syscalls, curated and battle-tested upstream. A hand-written "mostly allow, deny a
few dangerous syscalls" profile -- the shape that's actually safe to author without Linux access to
verify it -- would therefore be *weaker* than doing nothing, not stronger: it would open up every
syscall Docker's default already blocks except the handful named here. Shipping that as
"hardening" would be a real regression, not a disclosed heuristic.

The two honest ways to build a genuinely tighter profile are (a) vendor Docker's actual default.json
and trim entries a scanner family provably never uses, or (b) strace a real run of each scanner
image and derive a true minimal allowlist from what it actually calls. Both require a Linux host
this pass doesn't have (see core.sandbox.gvisor_runtime's module docstring) and neither has been
done here -- so, matching the precedent already set by core.fixagent.sandbox's own capability-set
disclosure, the honest floor is "Docker's real default applies, unmodified," not a guessed-at custom
profile. SCANNER_FAMILY below is left in place as the intended shape for when (a) or (b) is done.
"""

from __future__ import annotations

from pathlib import Path

# Not yet used to build a profile (see module docstring) -- kept as the intended grouping so a
# future profile-authoring pass (vendor-and-trim, or strace-derived) has somewhere to start from
# without re-deriving which scanners share a runtime shape.
SCANNER_FAMILY = {
    "bandit": "static-python",
    "semgrep": "static-multi-lang",
    "trivy": "sbom",
    "osv-scanner": "sbom",
    "syft": "sbom",
}


def seccomp_profile_path(scanner_name: str) -> Path | None:
    """The seccomp profile file for this scanner, or None to leave Docker's own default profile in
    effect (today, always None -- see module docstring for why). Never returns a path to a profile
    that would be weaker than Docker's default.
    """
    return None
