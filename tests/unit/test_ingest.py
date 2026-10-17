import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from core.ingest import IngestError, Limits, extract_archive


def make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_extracts_normal_zip(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"src/app.py": b"print(1)\n"})
    out = extract_archive(z, tmp_path / "out")
    assert (out / "src" / "app.py").read_bytes() == b"print(1)\n"


@pytest.mark.parametrize("name", ["../../evil.txt", "/etc/evil.txt", "a/../../evil.txt"])
def test_zip_slip_rejected(tmp_path: Path, name: str) -> None:
    z = make_zip(tmp_path / "a.zip", {name: b"x"})
    with pytest.raises(IngestError):
        extract_archive(z, tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()


def test_decompression_bomb_rejected(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "bomb.zip", {"zeros": b"\0" * 20_000_000})
    with pytest.raises(IngestError, match="ratio|uncompressed"):
        extract_archive(z, tmp_path / "out")
    assert not (tmp_path / "out" / "zeros").exists()


def test_file_count_limit(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "many.zip", {f"f{i}.txt": b"hello world %d" % i for i in range(20)})
    with pytest.raises(IngestError, match="file count"):
        extract_archive(z, tmp_path / "out", Limits(max_files=10))


def test_compressed_size_limit(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"a.txt": b"x" * 100})
    with pytest.raises(IngestError, match="compressed size"):
        extract_archive(z, tmp_path / "out", Limits(max_compressed_bytes=10))


def test_path_depth_limit(tmp_path: Path) -> None:
    deep_name = "/".join(f"d{i}" for i in range(10)) + "/f.txt"
    z = make_zip(tmp_path / "deep.zip", {deep_name: b"x"})
    with pytest.raises(IngestError, match="path depth"):
        extract_archive(z, tmp_path / "out", Limits(max_depth=5))


def test_path_depth_within_limit_is_extracted(tmp_path: Path) -> None:
    name = "a/b/c/f.txt"
    z = make_zip(tmp_path / "shallow.zip", {name: b"x"})
    out = extract_archive(z, tmp_path / "out", Limits(max_depth=5))
    assert (out / name).read_bytes() == b"x"


def test_zip_symlink_rejected(tmp_path: Path) -> None:
    p = tmp_path / "link.zip"
    with zipfile.ZipFile(p, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777) << 16  # symlink
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(IngestError, match="symlink"):
        extract_archive(p, tmp_path / "out")


def make_tar(path: Path, add: list[tuple[str, bytes, bytes | None]]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, data, link in add:
            ti = tarfile.TarInfo(name)
            if link is not None:
                ti.type = tarfile.SYMTYPE
                ti.linkname = link.decode()
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return path


def test_tar_extracts_and_rejects_traversal_and_links(tmp_path: Path) -> None:
    ok = make_tar(tmp_path / "ok.tar.gz", [("a/b.txt", b"hi", None)])
    assert (extract_archive(ok, tmp_path / "o1") / "a" / "b.txt").read_bytes() == b"hi"
    bad = make_tar(tmp_path / "bad.tar.gz", [("../../x", b"x", None)])
    with pytest.raises(IngestError, match="traversal"):
        extract_archive(bad, tmp_path / "o2")
    sym = make_tar(tmp_path / "sym.tar.gz", [("l", b"", b"/etc/passwd")])
    with pytest.raises(IngestError, match="links"):
        extract_archive(sym, tmp_path / "o3")


def test_unsupported_type(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"not an archive")
    with pytest.raises(IngestError, match="unsupported"):
        extract_archive(f, tmp_path / "o")


# The entry count is checked before the entries are read into memory (2026-10-17 audit): a small
# upload can hold millions of empty entries, and getmembers() / ZipFile() read every one first.


def _empty_tar(path: Path, n: int) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for i in range(n):
            tf.addfile(tarfile.TarInfo(f"f{i}"), io.BytesIO(b""))
    return path


def test_a_tar_with_too_many_entries_stops_at_the_limit_not_after_reading_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _empty_tar(tmp_path / "many.tar.gz", 500)
    read: list[int] = []
    real_next = tarfile.TarFile.next

    def counting_next(self: tarfile.TarFile) -> tarfile.TarInfo | None:
        read.append(1)
        return real_next(self)

    monkeypatch.setattr(tarfile.TarFile, "next", counting_next)
    with pytest.raises(IngestError, match="max file count"):
        extract_archive(archive, tmp_path / "out", Limits(max_files=10))
    # The 11th header is refused (tarfile reads one or two more just to detect the format); the
    # other ~490 are never read.
    assert len(read) < 20


def _empty_zip(path: Path, n: int, prefix: bytes = b"") -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(n):
            zf.writestr(f"f{i}", b"")
    path.write_bytes(prefix + buf.getvalue())
    return path


@pytest.mark.parametrize(
    "prefix", [b"", b"#!/bin/sh\nexit 0\n" * 64], ids=["plain", "data-in-front"]
)
def test_a_zip_with_too_many_entries_is_refused_before_zipfile_reads_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: bytes
) -> None:
    """Data in front of the archive (a self-extracting zip) must not throw the count off: the
    central directory is found from the end record, as zipfile finds it."""
    archive = _empty_zip(tmp_path / "many.zip", 500, prefix)

    def no_zipfile(*a: object, **kw: object) -> None:
        raise AssertionError("ZipFile() opened an archive over the entry limit")

    monkeypatch.setattr(zipfile, "ZipFile", no_zipfile)
    with pytest.raises(IngestError, match="max file count"):
        extract_archive(archive, tmp_path / "out", Limits(max_files=10))


def test_a_zip64_archive_is_counted_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Past 65,535 entries the end record says 0xFFFF and the real count is in the zip64 record."""
    archive = _empty_zip(tmp_path / "zip64.zip", 65_600)

    def no_zipfile(*a: object, **kw: object) -> None:
        raise AssertionError("ZipFile() opened an archive over the entry limit")

    monkeypatch.setattr(zipfile, "ZipFile", no_zipfile)
    with pytest.raises(IngestError, match="max file count"):
        extract_archive(archive, tmp_path / "out", Limits(max_files=1000, max_ratio=1e9))


def test_archives_under_the_limit_still_extract(tmp_path: Path) -> None:
    for archive in (
        _empty_zip(tmp_path / "ok.zip", 10, b"#!/bin/sh\n"),
        _empty_tar(tmp_path / "ok.tgz", 10),
    ):
        out = extract_archive(archive, tmp_path / archive.stem, Limits(max_files=10))
        assert len(list(out.iterdir())) == 10
