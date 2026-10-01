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

import hashlib
import json
import subprocess
from typing import Any
from urllib.parse import urlsplit

from core.dast.proxy import ProxyConfig
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)

NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"

# Never run, regardless of what the caller asks for -- see the module docstring.
EXCLUDED_TAGS = ("dos", "fuzz", "intrusive", "bruteforce")

# Never run anything but an HTTP(S) request to the target itself -- see the module docstring.
ALLOWED_PROTOCOL_TYPES = ("http",)

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiError(Exception):
    pass


def run_nuclei(
    target_url: str, *, timeout_s: int = 300, proxy: ProxyConfig | None = None
) -> list[Finding]:
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
        info = rec.get("info") or {}
        template_id = str(rec.get("template-id", "unknown"))
        severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        raw_cwe = (info.get("classification") or {}).get("cwe-id")
        if isinstance(raw_cwe, list):
            cwe = tuple(c.upper() for c in raw_cwe)
        elif raw_cwe:
            cwe = (str(raw_cwe).upper(),)
        else:
            cwe = ()
        matched_at = rec.get("matched-at") or rec.get("host") or ""
        route = urlsplit(matched_at).path or "/"
        # A real live scan found this: nuclei can report the SAME template-id against the SAME
        # matched-at more than once (e.g. one match per extracted value, or per matcher within a
        # template) -- keying the digest on matched_at alone collided repeatedly. Hashing the whole
        # raw record is unique unless two records are genuinely byte-for-byte identical, in which
        # case they really are the same finding.
        digest = hashlib.sha256(line.encode()).hexdigest()[:12]
        references = info.get("reference")
        if isinstance(references, str):
            references = [references]
        findings.append(
            Finding(
                id=f"nuclei-{template_id}-{digest}",
                title=info.get("name", template_id),
                description=info.get("description", "") or "",
                location=Location(path="", start_line=0, end_line=0, route=route),
                taxonomy=Taxonomy(category=Category.DAST, cwe=cwe),
                scoring=Scoring(
                    normalized_severity=severity,
                    native_severity={"nuclei": info.get("severity", "")},
                ),
                evidence=Evidence(reported_by=["nuclei"], rule_ids={"nuclei": [template_id]}),
                remediation=Remediation(
                    summary="", references=references or [], generated_by="static"
                ),
            )
        )
    return findings
