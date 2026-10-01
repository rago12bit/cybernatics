"""Keyless (Fulcio/Rekor) Sigstore verification for third-party plugin images (Week 51 task 1).

`core/attest/cosign.py` already wraps cosign for Bulwark's own artifacts, but entirely offline and
key-based: Bulwark holds a private key, and `--network=none` is correct there because nothing about
verifying your own signature needs the internet. A plugin publisher is a stranger, not a key Bulwark
holds -- there is nothing to hand them, and nothing to pin in advance. Keyless signing proves
identity through a short-lived certificate Fulcio issues after an OIDC login (e.g. a GitHub Actions
job's own ambient token) and records in the public Rekor transparency log; verifying it genuinely
needs the network, to fetch Sigstore's root of trust and query that log. This is the one place in
the codebase a cosign container runs with network access, which is why it is kept in its own module
rather than folded into core/attest/cosign.py's otherwise-offline one.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any

COSIGN_IMAGE = (
    "ghcr.io/sigstore/cosign/cosign:v3.1.3"
    "@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8"
)
TIMEOUT_SECONDS = 60
# Conservative: registry/tag/digest references never contain whitespace or shell metacharacters;
# this is a sanity check on a config-supplied string before it becomes an argv element, not an
# injection defense (subprocess.run([...]) never goes through a shell in the first place).
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,511}$")


class PluginSignatureError(RuntimeError):
    """The image is not signed, not signed by the declared identity, or could not be checked at
    all (network/registry failure) -- all three must block a plugin from running, so callers should
    never distinguish them in order to "fail open" on the third."""


@dataclass(frozen=True)
class VerifiedSignature:
    certificate_identity: str
    certificate_oidc_issuer: str
    log_index: int | None


def verify_plugin_image(
    image: str, certificate_identity: str, certificate_oidc_issuer: str
) -> list[VerifiedSignature]:
    """Raises PluginSignatureError unless `image` carries at least one valid Sigstore signature
    whose certificate matches both `certificate_identity` and `certificate_oidc_issuer` exactly --
    the same two flags `cosign verify --certificate-identity=... --certificate-oidc-issuer=...`
    takes. Returns the verified signature records on success; callers that only need a pass/fail can
    ignore the return value."""
    if not _SAFE_REF.match(image):
        raise PluginSignatureError(f"not a plausible image reference: {image!r}")
    argv = [
        "docker", "run", "--rm", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--memory=512m", "--pids-limit=128",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m", "-e", "HOME=/tmp",
        COSIGN_IMAGE, "verify",
        f"--certificate-identity={certificate_identity}",
        f"--certificate-oidc-issuer={certificate_oidc_issuer}",
        "-o", "json", image,
    ]  # fmt: skip
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except FileNotFoundError as exc:
        raise PluginSignatureError("docker is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise PluginSignatureError(f"cosign verify timed out after {TIMEOUT_SECONDS}s") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")
        lines = [ln for ln in err.splitlines() if ln.startswith("Error:")]
        tail = err.strip().splitlines()
        reason = lines[-1] if lines else (tail[-1] if tail else "unknown error")
        raise PluginSignatureError(f"{image}: signature verification failed: {str(reason)[:300]}")
    return _parse_verify_output(proc.stdout, image)


def _parse_verify_output(stdout: bytes, image: str) -> list[VerifiedSignature]:
    """cosign's `-o json` prints one JSON array of verified signature entries, never leaves this
    empty on a genuine success (an empty array with exit 0 would mean cosign itself has a bug, not
    that the image is untrusted) -- treated as a failure rather than silently "verified" either
    way. Each entry's `optional.Subject`/`optional.Issuer` carry the matched certificate identity
    (confirmed against cosign v3.1.3's real output, not guessed from docs);
    `optional.Bundle.Payload.logIndex` is the Rekor transparency-log entry this signature is
    recorded under."""
    try:
        records: list[dict[str, Any]] = json.loads(stdout.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PluginSignatureError(f"{image}: cosign returned unparseable output") from exc
    if not records:
        raise PluginSignatureError(f"{image}: cosign reported success but verified no signatures")
    out = []
    for rec in records:
        optional = rec.get("optional") or {}
        payload = (optional.get("Bundle") or {}).get("Payload") or {}
        out.append(
            VerifiedSignature(
                certificate_identity=str(optional.get("Subject", "")),
                certificate_oidc_issuer=str(optional.get("Issuer", "")),
                log_index=payload.get("logIndex"),
            )
        )
    return out
