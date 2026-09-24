"""Scan workspace preparation.

Every scan target, whether a local dir, extracted archive or cloned repo, is first copied into a
private workspace containing only regular files with normalized permissions. This (a) enforces
the size/file-count limits for local directories too, (b) drops symlinks that could point outside
the target, and (c) makes files readable by the unprivileged container user (uid 10001).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from core.ingest import IngestError, Limits

_SKIP_DIRS = {".git", ".hg", ".svn"}


def prepare_workspace(src: Path, dest: Path, limits: Limits | None = None) -> Path:
    limits = limits or Limits()
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o755)
    total = count = 0
    root = src.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        rel = Path(dirpath).relative_to(root)
        (dest / rel).mkdir(parents=True, exist_ok=True)
        os.chmod(dest / rel, 0o755)
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue  # never follow links out of the target; skip sockets/devices
            size = p.stat().st_size
            total += size
            count += 1
            if count > limits.max_files:
                raise IngestError("target exceeds max file count")
            if total > limits.max_uncompressed_bytes:
                raise IngestError("target exceeds max total size")
            out = dest / rel / name
            shutil.copyfile(p, out)
            os.chmod(out, 0o644)
    return dest
