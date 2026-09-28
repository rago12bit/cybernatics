"""Publish a signed audit-log checkpoint to Sigstore's Rekor transparency log (Week 30 backfill,
ADR-0019, plan §19.3).

Deliberately a separate module from `core/attest/cosign.py`, not an extension of it: that module
signs SBOM/scan artifacts completely offline (`--network=none`, `--tlog-upload=false`) by design --
a scan artifact's signature only needs to prove *who* signed it, and the sandboxed runner's
no-network invariant matters more there than a timestamp does. A checkpoint's entire purpose is the
opposite: being independently, publicly, verifiably timestamped, so that truncating or rewriting the
local chain *before* a checkpoint becomes detectable against a log neither Bulwark nor an attacker
controls. That needs a real network call to Rekor, so it gets its own narrowly-scoped container
invocation rather than loosening the shared one's guarantee for every other caller.

Key-based signing (the same `cosign generate-key-pair` / `COSIGN_PASSWORD` setup `core/attest`
already documents), not keyless: keyless (OIDC-bound, via Sigstore's Fulcio CA) needs an identity
provider this project doesn't integrate with for a long-running server outside of GitHub Actions'
own ambient OIDC token. Rekor's transparency-log guarantee doesn't require keyless signing -- a
key-based `cosign sign-blob` still uploads its signature to the public log unless explicitly told
not to, which is exactly the behavior this module wants and `core/attest`'s does not.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.attest.cosign import COSIGN_IMAGE, TIMEOUT_SECONDS, AttestError
from core.config import scratch_dir


def _workdir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="bulwark-rekor-", dir=scratch_dir()))
    d.chmod(0o755)
    return d


def _run_networked(args: list[str], key: Path, work: Path) -> None:
    """Like `core.attest.cosign._run`, but WITH network -- Rekor upload needs it. Everything else
    (read-only rootfs, dropped caps, no new privileges, resource caps) stays identical."""
    if not key.is_file():
        raise AttestError(f"key file not found: {key}")
    argv = [
        "docker", "run", "--rm", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--memory=512m", "--pids-limit=128",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m", "-e", "HOME=/tmp",
        f"--user={os.getuid()}:{os.getgid()}",
        "-v", f"{key.resolve()}:/keys/cosign.key:ro",
        "-v", f"{work}:/work",
    ]  # fmt: skip
    if "COSIGN_PASSWORD" in os.environ:
        argv += ["-e", "COSIGN_PASSWORD"]
    argv += [COSIGN_IMAGE, *args]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except FileNotFoundError as exc:
        raise AttestError("docker is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise AttestError("cosign timed out") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")
        lines = [ln for ln in err.splitlines() if ln.startswith("Error:")]
        tail = err.strip().splitlines()
        reason = lines[-1] if lines else (tail[-1] if tail else "unknown error")
        raise AttestError(f"cosign failed: {str(reason)[:300]}")


def sign_checkpoint(seq_end: int, chain_hash: str, key: Path) -> tuple[str, int | None]:
    """Signs `"{seq_end}:{chain_hash}"` and uploads the signature to the public Rekor instance.
    Returns (bundle_json, rekor_log_index) -- `rekor_log_index` is `None` if cosign's output didn't
    include one (an older cosign version, or the upload silently didn't happen); callers should
    treat that as "not actually checkpointed to Rekor yet," not as success.
    """
    work = _workdir()
    try:
        payload = f"{seq_end}:{chain_hash}"
        (work / "checkpoint.txt").write_text(payload)
        _run_networked(
            ["sign-blob", "--key", "/keys/cosign.key", "--yes", "--bundle", "/work/out.bundle",
             "/work/checkpoint.txt"],
            key, work,
        )  # fmt: skip
        bundle_text = (work / "out.bundle").read_text("utf-8")
        rekor_log_index = _extract_log_index(bundle_text)
        return bundle_text, rekor_log_index
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _extract_log_index(bundle_text: str) -> int | None:
    """The Sigstore bundle format nests the Rekor entry under
    `verificationMaterial.tlogEntries[0].logIndex`; tolerate any shape mismatch (a cosign version
    difference) by returning `None` rather than raising -- the checkpoint's signature is still
    valid either way, and `bulwark audit verify` reports a missing index as unverified-in-Rekor
    rather than crashing."""
    try:
        bundle = json.loads(bundle_text)
        entries = bundle.get("verificationMaterial", {}).get("tlogEntries", [])
        if entries and isinstance(entries[0].get("logIndex"), int):
            return int(entries[0]["logIndex"])
    except (ValueError, AttributeError, KeyError, TypeError):
        pass
    return None
