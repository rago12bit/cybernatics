"""Nuclei with a curated, excluded-tags template set: the active tier, opt-in per campaign (Week 49
task 3, plan §22.4). Nuclei's own template library includes templates explicitly designed to crash,
flood, or otherwise degrade a target (`dos`), fuzz it with large payload volumes (`fuzz`), or run
intrusive checks with real side effects (`intrusive`) -- these are excluded unconditionally, not
offered as an opt-in, because an "active scan" opt-in authorizes probing the target more thoroughly
than a passive scan, not authorizing a denial-of-service against it.

`-pt http` is the same kind of unconditional restriction, added when the egress proxy was wired in
(Week 49b, plan §22.4 follow-up): a real live run found that Nuclei's default template set reaches
third parties that are NOT the verified target by design, not by bug -- `dns`-type templates query
whatever DNS resolver the container uses, and several `http`-type templates (`rdap-whois`) call a
domain registry's own API to look up WHOIS data about the target. Excluded tags alone don't stop
this, since those templates aren't `dos`/`fuzz`/`intrusive`/`bruteforce`. A campaign's egress proxy
is scoped to exactly one allowed host (the verified Asset); letting Nuclei also need DNS resolvers
and `rdap.verisign.com` would mean either breaking those templates outright or widening the allow-
list past the one host the ownership check actually verified -- the latter is a bigger hole than the
feature these templates provide. Restricting to `http`-protocol templates keeps every request inside
the one relationship DAST is actually authorized for: an HTTP(S) request to the verified target.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from core.dast.mapping import nuclei_finding
from core.dast.proxy import ProxyConfig
from core.models import Finding

NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"

# Never run, regardless of what the caller asks for -- see the module docstring.
EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce")

# Never run anything but an HTTP(S) request to the target itself -- see the module docstring.
ALLOWED_PROTOCOL_TYPES = ("http",)


class NucleiError(Exception):
    pass


def run_nuclei(
    target_url: str,
    *,
    timeout_s: int = 300,
    proxy: ProxyConfig | None = None,
    template_ids: tuple[str, ...] = (),
) -> list[Finding]:
    """`template_ids`: only these templates (a targeted retest, plan §43.3). The excluded tags and
    allowed protocol types still apply, so naming a template cannot bring in an excluded one."""
    argv = ["docker", "run", "--rm"]
    if proxy is not None:
        # host.docker.internal needs this explicit mapping on Linux too (Docker Engine >= 20.10);
        # macOS Docker Desktop already resolves it without the flag, but passing it unconditionally
        # here means the same argv works on both, which is what a worker actually needs.
        argv += ["--add-host", "host.docker.internal:host-gateway"]
    argv += [
        NUCLEI_IMAGE,
        "-u", target_url,
        "-etags", ",".join(EXCLUDED_TAGS),
        "-pt", ",".join(ALLOWED_PROTOCOL_TYPES),
        "-jsonl",
        "-silent",
    ]  # fmt: skip
    if proxy is not None:
        argv += ["-proxy", f"http://{proxy.host}:{proxy.port}"]
    if template_ids:
        argv += ["-id", ",".join(template_ids)]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired as exc:
        raise NucleiError(f"nuclei timed out after {timeout_s}s") from exc
    except FileNotFoundError as exc:
        raise NucleiError("docker is not available") from exc
    return _parse_jsonl(proc.stdout.decode("utf-8", errors="replace"))


def _parse_jsonl(output: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue  # nuclei occasionally interleaves a non-JSON progress line even with -silent
        # The whole raw line is hashed into the id: a real live scan found nuclei reporting the SAME
        # template against the SAME matched-at more than once (one match per extracted value, or
        # per matcher), so neither of those alone is unique.
        finding = nuclei_finding(rec, line) if isinstance(rec, dict) else None
        if finding is not None:
            findings.append(finding)
    return findings
