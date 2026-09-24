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
