"""Public Git URL ingestion with SSRF guards (threat T5).

Layers: strict URL grammar -> host allowlist -> resolve DNS and require every address to be
globally routable (blocks RFC 1918, loopback, link-local/cloud metadata, CGNAT, ...) -> pin the
validated IP into git so DNS cannot change between check and use -> disable redirects, submodules,
hooks, credential helpers and non-https protocols -> hard size watchdog and timeout.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from core.ingest import IngestError, Limits

ALLOWED_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
_PATH_RE = re.compile(r"^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){1,4}(\.git)?/?$")

Resolver = Callable[[str], list[str]]
#: Deliberately narrow (Week 30, ADR-0017): the only ref this codebase ever passes today is one
#: parsed straight out of a GitHub webhook payload for the App integration. Restricting the shape
#: this tightly, rather than accepting any ref-like string, keeps a malformed or hostile webhook
#: payload from ever reaching `git fetch` as anything but this one well-understood form.
_SAFE_REF = re.compile(r"^refs/pull/[0-9]+/(head|merge)$")


class GitUrlError(IngestError):
    """URL rejected by validation (bad scheme/host/path or unsafe resolved address)."""


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({str(i[4][0]) for i in infos})


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address):
        # Unwrap addresses that embed an IPv4 target, a classic SSRF filter bypass.
        embedded = addr.ipv4_mapped or addr.sixtofour or (addr.teredo[1] if addr.teredo else None)
        if embedded is not None:
            return _is_public(str(embedded))
        if addr in ipaddress.ip_network("64:ff9b::/96"):  # NAT64
            return False
    return addr.is_global and not addr.is_multicast


@dataclass(frozen=True)
class ValidatedRepo:
    url: str
    host: str
    ip: str


def validate_git_url(url: str, resolver: Resolver = default_resolver) -> ValidatedRepo:
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise GitUrlError("only https:// URLs are allowed")
    if parts.username or parts.password or "@" in parts.netloc:
        raise GitUrlError("credentials in URL are not allowed")
    if parts.query or parts.fragment:
        raise GitUrlError("query strings and fragments are not allowed")
    host = (parts.hostname or "").lower()
    if parts.port not in (None, 443):
        raise GitUrlError("non-standard ports are not allowed")
    if host not in ALLOWED_HOSTS:
        raise GitUrlError(f"host {host!r} is not in the allowlist ({sorted(ALLOWED_HOSTS)})")
    segments = parts.path.strip("/").split("/")
    if not _PATH_RE.match(parts.path) or any(seg.strip(".") == "" for seg in segments):
        raise GitUrlError("URL path is not a valid owner/repo path")
    try:
        ips = resolver(host)
    except OSError as exc:
        raise GitUrlError(f"could not resolve {host}: {exc}") from exc
    if not ips:
        raise GitUrlError(f"{host} did not resolve")
    bad = [ip for ip in ips if not _is_public(ip)]
    if bad:
        raise GitUrlError(f"{host} resolves to non-public address(es): {bad}")
    return ValidatedRepo(url=f"https://{host}{parts.path}", host=host, ip=ips[0])


def _dir_size(path: Path) -> int:
    total = 0
    for dirpath, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return total


def _friendly_clone_error(stderr: str) -> str:
    """Plain-word summary of git's own stderr, in front of it (plan §30.3: "say what happened and
    what to do next", never a raw tool error as the whole message). Falls back to a generic summary
    for anything not recognized -- the raw stderr always stays attached, so nothing is hidden."""
    low = stderr.lower()
    auth_failure = (
        "could not read username", "terminal prompts disabled", "authentication failed",
        "invalid username or password", "access denied", "permission denied",
    )  # fmt: skip
    if "not found" in low:
        return "Couldn't find this repository. Check the URL is correct."
    if any(s in low for s in auth_failure):
        return (
            "Couldn't clone this repository. Bulwark can only scan public repositories right "
            "now -- make sure this one is public."
        )
    if "could not resolve host" in low:
        return "Couldn't reach that host. Check the URL is correct."
    return "Couldn't clone this repository."


def _run_git(
    argv: list[str], env: dict[str, str], dest: Path, deadline: float, limits: Limits
) -> None:
    """Run one git subprocess, enforcing the same wall-clock and size watchdog every step needs."""
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline:
                raise IngestError("git operation timed out")
            if dest.exists() and _dir_size(dest) > limits.max_uncompressed_bytes:
                raise IngestError("repository exceeds max size")
            time.sleep(0.25)
    except IngestError:
        proc.kill()
        proc.wait()
        raise
    if proc.returncode != 0:
        err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")[-500:].strip()
        msg = f"{_friendly_clone_error(err)} ({err})" if err else "git operation failed"
        raise IngestError(msg)


def clone_repo(
    url: str,
    dest: Path,
    limits: Limits | None = None,
    timeout: float = 120.0,
    resolver: Resolver = default_resolver,
    ref: str | None = None,
) -> Path:
    """Shallow-clone a validated public repo into dest (without .git). Returns dest.

    `ref` (Week 30, ADR-0017): when given, checks out that exact ref instead of the default branch
    -- specifically `refs/pull/<n>/head`, GitHub's own stable name for a pull request's current
    head commit, used by the GitHub App integration so a PR-triggered scan looks at the PR's
    actual code rather than whatever the default branch happens to be. Restricted to that one
    shape (`_SAFE_REF`) since nothing else constructs this value from anything less trusted than
    a webhook payload today.
    """
    limits = limits or Limits()
    repo = validate_git_url(url, resolver)
    if ref is not None and not _SAFE_REF.match(ref):
        raise GitUrlError(f"unsupported ref: {ref!r}")
    cfg = [
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", f"http.curloptResolve={repo.host}:443:{repo.ip}",
        "-c", "core.symlinks=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
    ]  # fmt: skip
    with tempfile.TemporaryDirectory(prefix="bulwark-git-home-") as home:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": home,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
        }
        deadline = time.monotonic() + timeout
        try:
            if ref is None:
                argv = ["git", *cfg, "clone", "--depth=1", "--single-branch", "--no-tags",
                        "--no-recurse-submodules", "--", repo.url, str(dest)]  # fmt: skip
                _run_git(argv, env, dest, deadline, limits)
            else:
                # A shallow clone can't target an arbitrary ref directly (`clone --branch` only
                # resolves refs/heads or refs/tags); init + a scoped fetch is the standard way to
                # shallow-fetch one specific ref like a PR head instead.
                dest.mkdir(parents=True, exist_ok=True)
                _run_git(["git", *cfg, "init", "--quiet", str(dest)], env, dest, deadline, limits)
                _run_git(
                    ["git", *cfg, "-C", str(dest), "remote", "add", "origin", repo.url],
                    env, dest, deadline, limits,
                )  # fmt: skip
                _run_git(
                    ["git", *cfg, "-C", str(dest), "fetch", "--depth=1", "--no-tags",
                     "origin", ref],
                    env, dest, deadline, limits,
                )  # fmt: skip
                _run_git(
                    ["git", *cfg, "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"],
                    env, dest, deadline, limits,
                )  # fmt: skip
        except IngestError:
            shutil.rmtree(dest, ignore_errors=True)
            raise
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return dest
