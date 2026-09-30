"""Archive ingestion hardening (threats T3 decompression bomb, T4 zip slip).

Every limit is checked from archive metadata BEFORE anything is written, and again against the
bytes actually written, because metadata can lie.
"""

from __future__ import annotations

import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


class IngestError(Exception):
    """The archive violated a safety limit or contained a malicious entry."""


@dataclass(frozen=True)
class Limits:
    max_compressed_bytes: int = 100 * 1024 * 1024
    max_uncompressed_bytes: int = 500 * 1024 * 1024
    max_files: int = 20_000
    max_ratio: float = 100.0  # uncompressed / compressed
    max_depth: int = 64  # directory components in one entry's path


def _safe_dest(root: Path, name: str, limits: Limits) -> Path:
    """Resolve an entry name under root; reject anything that escapes it."""
    if name.startswith(("/", "\\")) or "\x00" in name:
        raise IngestError(f"unsafe entry name: {name!r}")
    depth = len(Path(name).parts)
    if depth > limits.max_depth:
        raise IngestError(f"entry exceeds max path depth ({depth} > {limits.max_depth}): {name!r}")
    dest = (root / name).resolve()
    if dest != root and root not in dest.parents:
        raise IngestError(f"path traversal in entry: {name!r}")
    return dest


def _check_totals(compressed: int, total: int, count: int, limits: Limits) -> None:
    if compressed > limits.max_compressed_bytes:
        raise IngestError("archive exceeds max compressed size")
    if count > limits.max_files:
        raise IngestError("archive exceeds max file count")
    if total > limits.max_uncompressed_bytes:
        raise IngestError("archive exceeds max uncompressed size")
    if compressed > 0 and total / compressed > limits.max_ratio:
        raise IngestError("archive exceeds max compression ratio (possible decompression bomb)")


def extract_archive(archive: Path, dest: Path, limits: Limits | None = None) -> Path:
    """Safely extract a .zip / .tar / .tar.gz into dest. Returns dest."""
    limits = limits or Limits()
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    compressed = archive.stat().st_size
    if compressed > limits.max_compressed_bytes:
        raise IngestError("archive exceeds max compressed size")
    if zipfile.is_zipfile(archive):
        _extract_zip(archive, root, compressed, limits)
    elif tarfile.is_tarfile(archive):
        _extract_tar(archive, root, compressed, limits)
    else:
        raise IngestError("unsupported archive type (expected zip, tar or tar.gz)")
    return dest


def _extract_zip(archive: Path, root: Path, compressed: int, limits: Limits) -> None:
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        _check_totals(compressed, sum(i.file_size for i in infos), len(infos), limits)
        written = 0
        for info in infos:
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise IngestError(f"symlink entries are not allowed: {info.filename!r}")
            target = _safe_dest(root, info.filename, limits)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(64 * 1024):
                    written += len(chunk)
                    _check_totals(compressed, written, len(infos), limits)
                    out.write(chunk)


def _extract_tar(archive: Path, root: Path, compressed: int, limits: Limits) -> None:
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        _check_totals(compressed, sum(m.size for m in members), len(members), limits)
        written = 0
        for m in members:
            if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                raise IngestError(f"links and special files are not allowed: {m.name!r}")
            target = _safe_dest(root, m.name, limits)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            src = tf.extractfile(m)
            if src is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with src, open(target, "wb") as out:
                while chunk := src.read(64 * 1024):
                    written += len(chunk)
                    _check_totals(compressed, written, len(members), limits)
                    out.write(chunk)
