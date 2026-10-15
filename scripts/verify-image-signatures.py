#!/usr/bin/env python3
"""Check the signature on every pinned image whose publisher signs it (THREAT-MODEL T10).

For each digest pinned in this repository (scripts/image_pins.py) whose repository is under `signed`
in docker/image-signers.json, runs `cosign verify` on that exact digest, requiring the recorded
signer: a digest proves the image is the one pinned, the signature proves who built it. Fails on a
pinned image that is in neither `signed` nor `unsigned`, so a new one is a decision, not a default.
Runs cosign from its own pinned image (signed by Sigstore, and checked here like the rest).

Usage: python scripts/verify-image-signatures.py            (needs Docker and network)
       python scripts/verify-image-signatures.py --plan     (what would be checked; no network)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from image_pins import ROOT, pinned_images, repository  # noqa: E402

SIGNERS = ROOT / "docker" / "image-signers.json"
COSIGN_REPO = "ghcr.io/sigstore/cosign/cosign"


def load_signers(path: Path = SIGNERS) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    return data


def plan(pins: dict[str, list[str]], signers: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(pinned refs to verify, pinned refs whose repository is in neither list)."""
    signed, unsigned = signers["signed"], signers["unsigned"]
    verify = [ref for ref in pins if repository(ref) in signed]
    unknown = [
        ref for ref in pins if repository(ref) not in signed and repository(ref) not in unsigned
    ]
    return verify, unknown


def cosign_args(ref: str, signer: dict[str, str]) -> list[str]:
    """`cosign verify` arguments requiring this signer: an exact identity, or a pattern anchored to
    the publisher's release workflow (its tag changes with each version)."""
    if "identity" in signer:
        who = ["--certificate-identity", signer["identity"]]
    else:
        who = ["--certificate-identity-regexp", signer["identity_regexp"]]
    return ["verify", *who, "--certificate-oidc-issuer", signer["issuer"], ref]


def cosign_image(pins: dict[str, list[str]]) -> str:
    refs = [ref for ref in pins if repository(ref) == COSIGN_REPO]
    if len(refs) != 1:
        raise SystemExit(f"expected one pinned cosign image, found {refs}")
    return refs[0]


def main(argv: list[str]) -> int:
    pins, signers = pinned_images(), load_signers()
    verify, unknown = plan(pins, signers)
    for ref in unknown:
        print(f"NOT LISTED  {ref}  ({', '.join(pins[ref])}): add it to docker/image-signers.json")
    if "--plan" in argv:
        for ref in verify:
            print(f"would verify  {ref}")
        return 1 if unknown else 0

    cosign = cosign_image(pins)
    failed = []
    for ref in verify:
        args = cosign_args(ref, signers["signed"][repository(ref)])
        r = subprocess.run(["docker", "run", "--rm", cosign, *args], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"verified    {ref}")
        else:
            failed.append(ref)
            print(f"FAILED      {ref}\n{r.stderr.strip()[-800:]}")
    print(f"{len(verify) - len(failed)} of {len(verify)} signed images verified; "
          f"{len(pins) - len(verify) - len(unknown)} pinned images have no signature to check")  # fmt: skip
    return 1 if failed or unknown else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
