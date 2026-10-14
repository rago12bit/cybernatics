"""Network-layer egress policy for the fix-verification sandbox (Week 46 task 3, plan §22.1).

Applied via a sidecar container joined to the target's own network namespace (`docker run
--network=container:<name>`), never from inside the target's own image: `TestRunSpec.image` is
caller-supplied and arbitrary (`python:3.12-slim`, `node:20-slim`, ...), so nothing guarantees the
target image has `nft` installed, and installing it at runtime would need network access before any
restriction is in place -- a chicken-and-egg problem for the very thing being restricted. A sidecar
with nftables pre-baked (docker/egress-sidecar, built as `bulwark/egress-sidecar:1` the same way the
scanner images are, see .github/workflows/ci.yml and docker-compose.yml) sidesteps this: nftables
rules are a property of the network namespace, not of any one container's filesystem, so a rule the
sidecar loads applies to the target regardless of what's inside it. Verified live end-to-end against
a real `python:3.12-slim` target with no nftables of its own (docs/v2-week46-verification.md).

Ordering and scope were both corrected after live testing against a real container (Docker Desktop
on macOS), not designed blind:
  - DNS is allowed BEFORE the denied-CIDR check, not after. Docker's own embedded DNS resolver
    commonly lives in RFC1918 space (192.168.65.x on the machine this was verified on); denying
    RFC1918 first broke every package install, not just internal-network access.
  - IPv6 is dropped outright rather than mirrored rule-for-rule. An unmirrored IPv6 allow silently
    bypassed every IPv4 deny rule in this exact ruleset during that same live test (`curl -6` reached
    pypi.org while the IPv4 path was fully policed). This sandbox only needs IPv4 egress to public
    package registries, so removing the whole IPv6 path is simpler and safer than keeping two rule
    sets in sync.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

from core.sandbox.docker_runtime import pull_policy

EGRESS_SIDECAR_IMAGE = "bulwark/egress-sidecar:1"

# Every major cloud's metadata service lives in link-local space (169.254.169.254) -- the same SSRF
# target core.attackpath.rules.ssrf_reachable_from_entrypoint flags -- and test code run by the
# fix-verification agent has no legitimate reason to reach it, or any other host on an internal
# network (RFC1918).
DEFAULT_DENIED_CIDRS: tuple[str, ...] = (
    "169.254.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)


class EgressPolicyError(Exception):
    pass


def build_egress_nft_ruleset(denied_cidrs: Sequence[str] = DEFAULT_DENIED_CIDRS) -> str:
    """An nftables ruleset for the target container's own OUTPUT chain: default-drop, DNS and
    HTTP(S) allowed, `denied_cidrs` and all of IPv6 dropped. See the module docstring for why the
    ordering and the IPv6 drop are load-bearing, not arbitrary."""
    denylist = ", ".join(denied_cidrs)
    return (
        "table inet bulwark_egress {\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy drop;\n"
        '    oif "lo" accept\n'
        "    ct state established,related accept\n"
        "    meta nfproto ipv6 drop\n"
        "    udp dport 53 accept\n"
        "    tcp dport 53 accept\n"
        f"    ip daddr {{ {denylist} }} drop\n"
        "    tcp dport { 80, 443 } accept\n"
        "  }\n"
        "}\n"
    )


def apply_egress_policy(
    container_name: str,
    *,
    denied_cidrs: Sequence[str] = DEFAULT_DENIED_CIDRS,
    timeout_s: float = 15,
) -> None:
    """Loads the egress ruleset into `container_name`'s network namespace via the sidecar image.

    Raises EgressPolicyError if the sidecar fails, times out, or `docker`/the sidecar image is
    unavailable -- callers must treat that as a hard stop (kill the target container) rather than
    letting it run with no policy in place.
    """
    argv = [
        "docker",
        "run",
        "--rm",
        "-i",
        f"--network=container:{container_name}",
        "--cap-add=NET_ADMIN",
        "--label=bulwark.managed=1",
        *pull_policy(EGRESS_SIDECAR_IMAGE),
        EGRESS_SIDECAR_IMAGE,
        "-f",
        "-",
    ]
    try:
        proc = subprocess.run(
            argv,
            input=build_egress_nft_ruleset(denied_cidrs).encode(),
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise EgressPolicyError(f"could not apply egress policy: {exc}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise EgressPolicyError(f"egress sidecar exited {proc.returncode}: {stderr}")
