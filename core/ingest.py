"""Archive ingestion hardening (threats T3 decompression bomb, T4 zip slip).

Every limit is checked from archive metadata BEFORE anything is written, and again against the
bytes actually written, because metadata can lie. The entry count is checked before the entries
are read into memory: a small upload can hold millions of empty entries.
"""

from __future__ import annotations

import stat
import struct
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


_EOCD = b"PK\x05\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_END = b"PK\x06\x06"
_CENTRAL = b"PK\x01\x02"


def _central_directory(archive: Path) -> tuple[int, int] | None:
    """(start, size) of a zip's central directory, found the way zipfile finds it (from the end
    record, so data prepended to the archive does not move it), or None when there is no end
    record in the last 64 KB, where zipfile looks for it too."""
    with open(archive, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        tail_len = min(end, 65535 + 22)
        f.seek(end - tail_len)
        tail = f.read()
        at = tail.rfind(_EOCD)
        if at < 0 or len(tail) < at + 22:
            return None
        eocd_pos = end - tail_len + at
        size = struct.unpack("<I", tail[at + 12 : at + 16])[0]
        if at >= 20 and tail[at - 20 : at - 16] == _ZIP64_LOCATOR:
            # Like zipfile: with a zip64 locator, the zip64 end record (just before it) is the one
            # to read, whatever the plain record says -- it holds the real count and size, and the
            # central directory ends where it starts.
            # An unreadable zip64 record is ignored, as zipfile ignores it.
            rec_pos = eocd_pos - 20 - 56
            f.seek(max(rec_pos, 0))
            rec = f.read(56)
            if rec_pos >= 0 and rec[:4] == _ZIP64_END:
                size = struct.unpack("<Q", rec[40:48])[0]
                eocd_pos = rec_pos
        return eocd_pos - size, size


def _count_zip_entries(archive: Path, limit: int) -> None:
    """Refuse a zip with more than `limit` entries before zipfile reads them: ZipFile() turns the
    whole central directory into objects at once, about 2 million for a 100 MB upload. Walks the
    46-byte headers without keeping them."""
    found = _central_directory(archive)
    if found is None:
        raise IngestError("archive has no zip end record")
    start, size = found
    count, pos = 0, start
    with open(archive, "rb") as f:
        while pos < start + size:
            f.seek(pos)
            head = f.read(46)
            if len(head) < 46 or head[:4] != _CENTRAL:
                # zipfile refuses this too ("bad magic number"); stopping here instead of handing
                # it over uncounted keeps a malformed directory from skipping the count.
                raise IngestError("archive's central directory is malformed")
            count += 1
            if count > limit:
                raise IngestError("archive exceeds max file count")
            name_len, extra_len, comment_len = struct.unpack("<HHH", head[28:34])
            pos += 46 + name_len + extra_len + comment_len


def _extract_zip(archive: Path, root: Path, compressed: int, limits: Limits) -> None:
    _count_zip_entries(archive, limits.max_files)
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
        # One header at a time, stopping at the first limit: getmembers() would read every header
        # into memory first, and a small tar.gz can hold millions of empty entries.
        declared, count = 0, 0
        for m in tf:
            count += 1
            declared += m.size
            _check_totals(compressed, declared, count, limits)
        members = tf.getmembers()  # the ones just read, at most max_files
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
