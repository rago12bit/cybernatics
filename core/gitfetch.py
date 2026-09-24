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


def clone_repo(
    url: str,
    dest: Path,
    limits: Limits | None = None,
    timeout: float = 120.0,
    resolver: Resolver = default_resolver,
) -> Path:
    """Shallow-clone a validated public repo into dest (without .git). Returns dest."""
    limits = limits or Limits()
    repo = validate_git_url(url, resolver)
    argv = [
        "git",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", f"http.curloptResolve={repo.host}:443:{repo.ip}",
        "-c", "core.symlinks=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "clone", "--depth=1", "--single-branch", "--no-tags", "--no-recurse-submodules",
        "--", repo.url, str(dest),
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
        proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    raise IngestError("git clone timed out")
                if dest.exists() and _dir_size(dest) > limits.max_uncompressed_bytes:
                    raise IngestError("repository exceeds max size")
                time.sleep(0.25)
        except IngestError:
            proc.kill()
            proc.wait()
            shutil.rmtree(dest, ignore_errors=True)
            raise
        if proc.returncode != 0:
            err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")[-500:]
            shutil.rmtree(dest, ignore_errors=True)
            raise IngestError(f"git clone failed: {err.strip()}")
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return dest
