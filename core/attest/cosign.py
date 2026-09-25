"""Sign and verify scan artifacts with cosign, run in a locked-down container (no network, read-only).

Key-based only: you hold a cosign key pair (`cosign generate-key-pair`), its password goes in COSIGN_PASSWORD
in your environment (never on a command line), and Bulwark never stores or logs either. There is NO
transparency-log upload: a signature proves who held the key, not when it was made. Keyless (OIDC) signing
needs network and an identity provider and is not implemented here.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from core.config import scratch_dir

COSIGN_IMAGE = (
    "ghcr.io/sigstore/cosign/cosign:v3.1.3"
    "@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8"
)
TIMEOUT_SECONDS = 120
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
# cosign 3 defaults to a signing config that uploads to a transparency log; these turn that off.
_OFFLINE = ["--use-signing-config=false", "--tlog-upload=false", "--yes"]
_VERIFY_OFFLINE = ["--insecure-ignore-tlog"]


class AttestError(RuntimeError):
    pass


def _safe_name(path: Path) -> str:
    return path.name if _SAFE_NAME.match(path.name) else "artifact"


def _run(args: list[str], key: Path, key_name: str, work: Path) -> str:
    if not key.is_file():
        raise AttestError(f"key file not found: {key}")
    argv = [
        "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--memory=512m", "--pids-limit=128",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m", "-e", "HOME=/tmp",
        f"--user={os.getuid()}:{os.getgid()}",  # can read a 0600 key, and outputs belong to the caller
        "-v", f"{key.resolve()}:/keys/{key_name}:ro",
        "-v", f"{work}:/work",
    ]  # fmt: skip
    if "COSIGN_PASSWORD" in os.environ:
        argv += ["-e", "COSIGN_PASSWORD"]  # by name: the value never appears in the process list
    argv += [COSIGN_IMAGE, *args]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except FileNotFoundError as exc:
        raise AttestError("docker is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise AttestError("cosign timed out") from exc
    err = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        lines = [ln for ln in err.splitlines() if ln.startswith("Error:")]
        tail = err.strip().splitlines()
        reason = lines[-1] if lines else (tail[-1] if tail else "unknown error")
        hint = " (set COSIGN_PASSWORD to the key's password)" if "password" in err.lower() else ""
        raise AttestError(f"cosign failed: {str(reason)[:300]}{hint}")
    return err


def _workdir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="bulwark-cosign-", dir=scratch_dir()))
    d.chmod(0o755)
    return d


def sign_blob(blob: Path, key: Path, bundle_out: Path) -> None:
    """Write a Sigstore bundle holding the signature over `blob`."""
    work = _workdir()
    try:
        name = _safe_name(blob)
        shutil.copyfile(blob, work / name)
        _run(["sign-blob", "--key", "/keys/cosign.key", *_OFFLINE, "--bundle", "/work/out.bundle",
              f"/work/{name}"], key, "cosign.key", work)  # fmt: skip
        shutil.copyfile(work / "out.bundle", bundle_out)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def verify_blob(blob: Path, pub: Path, bundle: Path) -> None:
    """Raise AttestError unless `bundle` is a valid signature over exactly this file by this key."""
    work = _workdir()
    try:
        name = _safe_name(blob)
        shutil.copyfile(blob, work / name)
        shutil.copyfile(bundle, work / "in.bundle")
        _run(["verify-blob", "--key", "/keys/cosign.pub", *_VERIFY_OFFLINE, "--bundle", "/work/in.bundle",
              f"/work/{name}"], pub, "cosign.pub", work)  # fmt: skip
    finally:
        shutil.rmtree(work, ignore_errors=True)


def attest_blob(
    blob: Path, predicate: dict[str, Any], predicate_type: str, key: Path, bundle_out: Path
) -> None:
    """Sign an in-toto statement whose subject is `blob` and whose predicate is `predicate`."""
    work = _workdir()
    try:
        name = _safe_name(blob)
        shutil.copyfile(blob, work / name)
        (work / "predicate.json").write_text(json.dumps(predicate, sort_keys=True))
        _run(["attest-blob", "--key", "/keys/cosign.key", "--predicate", "/work/predicate.json",
              "--type", predicate_type, *_OFFLINE, "--bundle", "/work/out.bundle",
              f"/work/{name}"], key, "cosign.key", work)  # fmt: skip
        shutil.copyfile(work / "out.bundle", bundle_out)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def verify_attestation(blob: Path, predicate_type: str, pub: Path, bundle: Path) -> dict[str, Any]:
    """Verify signature, subject digest and predicate type; return the verified in-toto statement."""
    work = _workdir()
    try:
        name = _safe_name(blob)
        shutil.copyfile(blob, work / name)
        shutil.copyfile(bundle, work / "in.bundle")
        _run(["verify-blob-attestation", "--key", "/keys/cosign.pub", "--type", predicate_type,
              *_VERIFY_OFFLINE, "--bundle", "/work/in.bundle", f"/work/{name}"], pub, "cosign.pub", work)  # fmt: skip
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return statement_of(bundle)


def statement_of(bundle: Path) -> dict[str, Any]:
    """The in-toto statement inside a DSSE bundle. Only trust it after verify_attestation succeeded."""
    try:
        env = json.loads(bundle.read_text("utf-8"))["dsseEnvelope"]
        stmt = json.loads(base64.b64decode(env["payload"]))
        if not isinstance(stmt, dict):
            raise TypeError("statement is not an object")
        return stmt
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise AttestError(f"{bundle.name} is not an attestation bundle: {exc}") from exc
