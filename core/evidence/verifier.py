#!/usr/bin/env python3
"""Check a Bulwark evidence pack without trusting Bulwark (plan §47).

    python3 verify.py                 # in the unpacked pack's directory
    python3 verify.py path/to/pack    # a directory or the .zip

Standard library only, so an auditor can read every line of it. It checks:

1. every file against `manifest.json`'s SHA-256;
2. the audit-log extract: entry numbers are contiguous, each entry's `prev_hash` is the previous
   entry's hash, and each hash is recomputed -- from the full entry for this organization's own
   entries, and from its body digest for anyone else's (shown as hashes only);
3. each Rekor checkpoint in the pack names a hash that is in the extract at that position.

What it cannot check alone, and prints the commands for: the signature on `manifest.json`, and each
checkpoint's signature and its inclusion in the Rekor transparency log (both need cosign and the
signer's public key).

This file is copied into every pack as `verify.py`; Bulwark's own tests check that its hashes agree
with `core/audit.py`'s.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def hash_v1(e: dict[str, Any]) -> str:
    material = "|".join([str(e["seq"]), e["prev_hash"], e["timestamp"], e["actor"], e["action"],
                         e["target"], e["payload_digest"]])  # fmt: skip
    return hashlib.sha256(material.encode()).hexdigest()


def body_digest(e: dict[str, Any]) -> str:
    body = {k: e.get(k) for k in ("timestamp", "org_id", "actor", "action", "target",
                                  "payload_digest")}  # fmt: skip
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def hash_v2(seq: int, prev_hash: str, body: str) -> str:
    return hashlib.sha256(f"2|{seq}|{prev_hash}|{body}".encode()).hexdigest()


def verify_extract(extract: dict[str, Any]) -> dict[str, Any]:
    """The audit-log extract's own consistency, and which checkpoints it reaches."""
    entries = sorted(extract.get("entries") or [], key=lambda e: e["seq"])
    problems: list[str] = []
    recomputed = linked_only = disclosed = 0
    prev: dict[str, Any] | None = None
    by_seq: dict[int, str] = {}
    for e in entries:
        seq = int(e["seq"])
        if prev is not None:
            if seq != prev["seq"] + 1:
                problems.append(f"entries {prev['seq']} and {seq} are not consecutive")
            elif e["prev_hash"] != prev["entry_hash"]:
                problems.append(f"entry {seq} does not link to entry {prev['seq']}")
        elif seq == 1 and e["prev_hash"] != GENESIS_HASH:
            problems.append("entry 1 does not start from the genesis hash")
        version = int(e.get("version") or 1)
        withheld = bool(e.get("withheld"))
        disclosed += not withheld
        if version >= 2:
            body = e["body_digest"] if withheld else body_digest(e)
            if not withheld and e.get("body_digest") not in (None, body):
                problems.append(f"entry {seq}: its body digest does not match its contents")
            if hash_v2(seq, e["prev_hash"], body) == e["entry_hash"]:
                recomputed += 1
            else:
                problems.append(f"entry {seq}: its hash does not match its contents")
        elif withheld:
            linked_only += 1  # a version-1 entry of no one known: only its links can be checked
        elif hash_v1(e) == e["entry_hash"]:
            recomputed += 1
        else:
            problems.append(f"entry {seq}: its hash does not match its contents")
        by_seq[seq] = e["entry_hash"]
        prev = e
    anchored = []
    for cp in extract.get("checkpoints") or []:
        at = by_seq.get(int(cp["seq_end"]))
        if at is None:
            continue
        if at == cp["chain_hash"]:
            anchored.append(int(cp["seq_end"]))
        else:
            problems.append(f"checkpoint at entry {cp['seq_end']} names a different hash")
    last_disclosed = max((int(e["seq"]) for e in entries if not e.get("withheld")), default=None)
    return {
        "ok": not problems,
        "entries": len(entries),
        "disclosed": disclosed,
        "recomputed": recomputed,
        "linked_only": linked_only,
        "first_seq": entries[0]["seq"] if entries else None,
        "last_seq": entries[-1]["seq"] if entries else None,
        "anchored_at": anchored,
        "all_disclosed_anchored": bool(anchored)
        and (last_disclosed is None or max(anchored) >= last_disclosed),
        "problems": problems,
    }


def _files(target: Path) -> dict[str, bytes]:
    if target.is_file() and zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as z:
            return {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
    return {
        p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob("*") if p.is_file()
    }


def verify_pack(files: dict[str, bytes]) -> dict[str, Any]:
    problems: list[str] = []
    manifest = json.loads(files["manifest.json"])
    for name, digest in sorted(manifest["files"].items()):
        data = files.get(name)
        if data is None:
            problems.append(f"{name} is missing")
        elif hashlib.sha256(data).hexdigest() != digest:
            problems.append(f"{name} does not match the manifest")
    listed = set(manifest["files"]) | {"manifest.json", "manifest.json.sig"}
    extra = sorted(n for n in files if n not in listed)
    audit = verify_extract(json.loads(files["audit-extract.json"]))
    return {"manifest_ok": not problems, "problems": problems, "unlisted": extra, "audit": audit,
            "signed": "manifest.json.sig" in files}  # fmt: skip


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent
    files = _files(target)
    r = verify_pack(files)
    a = r["audit"]
    out = io.StringIO()
    print("Files against manifest.json:", "OK" if r["manifest_ok"] else "FAILED", file=out)
    for p in r["problems"]:
        print("  -", p, file=out)
    if r["unlisted"]:
        print("  not in the manifest (ignored):", ", ".join(r["unlisted"]), file=out)
    print(f"Audit-log extract: {'OK' if a['ok'] else 'FAILED'} -- entries {a['first_seq']} to "
          f"{a['last_seq']}, {a['disclosed']} shown in full, {a['recomputed']} hashes recomputed, "
          f"{a['linked_only']} checked by link only", file=out)  # fmt: skip
    for p in a["problems"]:
        print("  -", p, file=out)
    if a["anchored_at"]:
        print("  Rekor checkpoints at entries:", ", ".join(map(str, a["anchored_at"])), file=out)
        if not a["all_disclosed_anchored"]:
            print(
                "  The latest entries come after the last checkpoint: not yet anchored.", file=out
            )
    else:
        print("  No Rekor checkpoint covers this extract: its entries are not anchored.", file=out)
    print("\nStill to check with cosign and the signer's public key (cosign.pub):", file=out)
    if r["signed"]:
        print("  cosign verify-blob --key cosign.pub --bundle manifest.json.sig "
              "--insecure-ignore-tlog manifest.json", file=out)  # fmt: skip
    else:
        print(
            "  manifest.json is NOT signed: this pack proves nothing about who made it.", file=out
        )
    root = " --trusted-root trusted-root.json" if "trusted-root.json" in files else ""
    for cp in json.loads(files["audit-extract.json"]).get("checkpoints") or []:
        n = cp["seq_end"]
        print(
            f"  printf '%s' '{n}:{cp['chain_hash']}' > checkpoint-{n}.txt && cosign verify-blob "
            f"--key audit.pub --bundle checkpoints/{n}.bundle{root} checkpoint-{n}.txt",
            file=out,
        )
    sys.stdout.write(out.getvalue())
    return 0 if r["manifest_ok"] and a["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
