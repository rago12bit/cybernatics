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

`-ni` and `-duc` follow from the same rule (2026-10-08, measured on Juice Shop v17.3.0). By default
Nuclei registers with a public interactsh server (`oast.me` and friends) and plants its URLs in
payloads, so the target is asked to call a third party -- and the registration went straight out of
the container, around the proxy. The OAST templates are excluded with it; blind, out-of-band issues
are not found. And the upstream image ships no templates: every run downloaded ~86 MB from GitHub,
also around the proxy. `bulwark/nuclei` (docker/nuclei) bakes in a pinned template release, and
`-duc` stops the update check.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import uuid
from typing import IO, Any

from core.dast.mapping import nuclei_finding
from core.dast.proxy import ProxyConfig
from core.models import Finding

NUCLEI_IMAGE = "bulwark/nuclei:3.11.1"  # docker/nuclei: engine v3.11.1, templates v10.5.0 baked in

# Never run, regardless of what the caller asks for -- see the module docstring.
EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce")

# Never run anything but an HTTP(S) request to the target itself -- see the module docstring.
ALLOWED_PROTOCOL_TYPES = ("http",)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")  # Nuclei colours its log lines, even into a pipe


class NucleiError(Exception):
    pass


class NucleiTimeout(NucleiError):
    """The run hit its deadline. `findings` is what Nuclei reported before then: real results, but
    not everything it would have checked, so a campaign that keeps them is partial and closes
    nothing (core.dast.pipeline)."""

    def __init__(self, message: str, findings: list[Finding]) -> None:
        super().__init__(message)
        self.findings = findings


def run_nuclei(
    target_url: str,
    *,
    timeout_s: int = 300,
    proxy: ProxyConfig | None = None,
    template_ids: tuple[str, ...] = (),
) -> list[Finding]:
    """`template_ids`: only these templates (a targeted retest, plan §43.3). The excluded tags and
    allowed protocol types still apply, so naming a template cannot bring in an excluded one.

    Output is read as Nuclei prints it, so a run that hits `timeout_s` still returns what it found
    (as `NucleiTimeout.findings`) instead of nothing, and its container is killed rather than left
    running: stopping the `docker` client alone does not stop the container.

    A run that exits non-zero raises `NucleiError` with the reason it gave: Nuclei's own errors exit
    1 ("no templates provided for scan" for a template id that no longer exists), Docker's 125 (an
    image that is not there). Until 2026-10-14 the exit code was ignored and stderr discarded, so a
    failed run read as a clean one: a campaign "with no findings", and a targeted retest that
    concluded the Issue was fixed. A target that does not answer is not an error to Nuclei (it exits
    0 with no results); the campaign's egress proxy tells that apart instead
    (`BackgroundProxy.target_unreached`)."""
    name = f"bulwark-nuclei-{uuid.uuid4().hex[:8]}"
    argv = ["docker", "run", "--rm", "--name", name]
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
        "-duc",  # no update check: nothing is downloaded during a campaign
        "-ni",  # no interactsh: no third-party callback server
    ]  # fmt: skip
    if proxy is not None:
        argv += ["-proxy", f"http://{proxy.host}:{proxy.port}"]
    if template_ids:
        argv += ["-id", ",".join(template_ids)]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise NucleiError("docker is not available") from exc
    assert proc.stdout is not None and proc.stderr is not None
    lines: list[str] = []
    errors: list[str] = []  # -silent leaves only real errors here
    reader = threading.Thread(target=_read_lines, args=(proc.stdout, lines), daemon=True)
    err_reader = threading.Thread(target=_read_lines, args=(proc.stderr, errors), daemon=True)
    reader.start()
    err_reader.start()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True, check=False)
        proc.kill()
        proc.wait()
        reader.join(timeout=10)
        found = _parse_jsonl("".join(lines))  # a line cut by the kill is not valid JSON: dropped
        raise NucleiTimeout(
            f"nuclei timed out after {timeout_s}s; kept the {len(found)} finding(s) it reported "
            "before then",
            found,
        ) from None
    reader.join()
    err_reader.join(timeout=10)
    if proc.returncode != 0:
        reason = _ANSI.sub("", "".join(errors)).strip().splitlines()[-3:]
        raise NucleiError(
            f"nuclei exited with code {proc.returncode}: "
            + (" / ".join(reason)[-500:] or "no error output")
        )
    return _parse_jsonl("".join(lines))


def _read_lines(stream: IO[bytes], into: list[str]) -> None:
    for raw in iter(stream.readline, b""):
        into.append(raw.decode("utf-8", errors="replace"))


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
