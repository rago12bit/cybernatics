"""Network-layer enforcement that a DAST campaign runner cannot bypass `core.dast.proxy` by simply
not using it (plan §22.4, Week 49 task 2) -- the other half of the scope-enforcing egress control,
alongside the proxy itself.

Same sidecar-container mechanism as `core.fixagent.egress` (Week 46 task 3): nftables rules loaded
into the runner's own network namespace via `bulwark/egress-sidecar:1`, since rules are a property
of the namespace, not of any one container's filesystem -- the runner's image (ZAP's, Nuclei's, ...)
is caller-supplied and need not have `nft` installed itself.

Unlike the fix-verification sandbox's ruleset (which allows direct 80/443 to anywhere not on a
denylist), this one is an allow-list in the opposite direction: ALL direct 80/443 is denied, and the
only thing allowed through is the proxy's own address -- DNS is still permitted (the runner's tools
need to resolve names even though they can't connect to what they resolve), matching the DNS-before-
deny ordering Week 46 found necessary against Docker's own embedded resolver.
"""

from __future__ import annotations

import subprocess

from core.fixagent.egress import EGRESS_SIDECAR_IMAGE, EgressPolicyError

__all__ = ["EgressPolicyError", "build_dast_egress_nft_ruleset", "apply_dast_egress_policy"]


def build_dast_egress_nft_ruleset(proxy_host: str, proxy_port: int) -> str:
    """`proxy_host` must be an IP address, not a hostname -- nftables rules match packets, which
    carry addresses, not DNS names. DNS itself is allowed through unconditionally (both to let the
    runner resolve the proxy's own name if it was given one, and because `core.dast.proxy` relies on
    the runner's own OS-level resolution never succeeding for direct connections to be meaningfully
    blocked at all)."""
    return (
        "table inet bulwark_dast_egress {\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy drop;\n"
        '    oif "lo" accept\n'
        "    ct state established,related accept\n"
        "    meta nfproto ipv6 drop\n"
        "    udp dport 53 accept\n"
        "    tcp dport 53 accept\n"
        f"    ip daddr {proxy_host} tcp dport {proxy_port} accept\n"
        "  }\n"
        "}\n"
    )


def apply_dast_egress_policy(
    container_name: str, *, proxy_host: str, proxy_port: int, timeout_s: float = 15
) -> None:
    """Loads the ruleset into `container_name`'s network namespace. Raises EgressPolicyError on any
    failure -- callers must treat that as a hard stop (kill the runner) rather than letting a DAST
    scanner run with unrestricted egress, exactly the same posture `core.fixagent.egress.
    apply_egress_policy` already takes for the fix-verification sandbox."""
    argv = [
        "docker",
        "run",
        "--rm",
        "-i",
        f"--network=container:{container_name}",
        "--cap-add=NET_ADMIN",
        "--label=bulwark.managed=1",
        EGRESS_SIDECAR_IMAGE,
        "-f",
        "-",
    ]
    try:
        proc = subprocess.run(
            argv,
            input=build_dast_egress_nft_ruleset(proxy_host, proxy_port).encode(),
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise EgressPolicyError(f"could not apply DAST egress policy: {exc}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise EgressPolicyError(f"egress sidecar exited {proc.returncode}: {stderr}")
