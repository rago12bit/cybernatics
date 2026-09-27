"""Resolve a user-supplied source (directory, archive file, or Git URL) into a scan workspace."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from core.config import scratch_dir
from core.gitfetch import clone_repo
from core.ingest import IngestError, Limits, extract_archive
from core.workspace import prepare_workspace


@contextmanager
def materialize(
    source: str, limits: Limits | None = None, ref: str | None = None
) -> Iterator[Path]:
    """Yield a sanitized, size-limited workspace for `source`; cleaned up on exit.

    `ref` (Week 30): only meaningful for a git `source`; see `core.gitfetch.clone_repo`.
    """
    with tempfile.TemporaryDirectory(prefix="bulwark-ws-", dir=scratch_dir()) as tmp:
        tmp_path = Path(tmp)
        staged: Path
        if source.startswith(("https://", "http://", "git@", "ssh://", "git://", "file://")):
            staged = clone_repo(source, tmp_path / "clone", limits, ref=ref)
        else:
            p = Path(source).expanduser()
            if p.is_dir():
                staged = p
            elif p.is_file():
                staged = extract_archive(p, tmp_path / "extracted", limits)
            else:
                raise IngestError(f"source not found: {source}")
        yield prepare_workspace(staged, tmp_path / "workspace", limits)
