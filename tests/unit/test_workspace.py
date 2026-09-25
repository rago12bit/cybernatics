import os
from pathlib import Path

import pytest

from core.ingest import IngestError, Limits
from core.source import materialize
from core.workspace import prepare_workspace


def test_copies_regular_files_normalizes_perms_skips_links_and_git(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("x")
    f = src / "pkg" / "a.py"
    f.write_text("print(1)")
    f.chmod(0o600)  # unreadable by the container user unless normalized
    (src / "link").symlink_to("/etc/passwd")
    ws = prepare_workspace(src, tmp_path / "ws")
    assert (ws / "pkg" / "a.py").read_text() == "print(1)"
    assert oct((ws / "pkg" / "a.py").stat().st_mode & 0o777) == "0o644"
    assert not (ws / "link").exists() and not (ws / ".git").exists()


def test_limits_enforced(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"{i}.txt").write_text("hello")
    with pytest.raises(IngestError, match="file count"):
        prepare_workspace(src, tmp_path / "w1", Limits(max_files=3))
    with pytest.raises(IngestError, match="total size"):
        prepare_workspace(src, tmp_path / "w2", Limits(max_uncompressed_bytes=10))


def test_materialize_directory_and_cleanup(tmp_path: Path) -> None:
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.py").write_text("x")
    with materialize(str(tmp_path / "proj")) as ws:
        kept = ws
        assert (ws / "a.py").exists()
    assert not kept.exists()


def test_materialize_missing_and_unsafe_sources(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="not found"), materialize(str(tmp_path / "nope")):
        pass
    for url in ("http://github.com/a/b", "file:///etc", "ssh://git@github.com/a/b"):
        with pytest.raises(IngestError), materialize(url):
            pass


def test_materialize_archive(tmp_path: Path) -> None:
    import zipfile

    z = tmp_path / "p.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("app/main.py", "print(1)")
    with materialize(str(z)) as ws:
        assert (ws / "app" / "main.py").exists()
    assert os.path.exists(z)


def test_installed_dependencies_caches_and_virtualenvs_are_not_copied(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "node_modules" / "left-pad").mkdir(parents=True)
    (src / "node_modules" / "left-pad" / "index.js").write_text("x")
    (src / "web" / "node_modules" / "a").mkdir(parents=True)
    (src / "web" / "node_modules" / "a" / "i.js").write_text("x")
    (src / "myenv" / "lib").mkdir(parents=True)
    (src / "myenv" / "pyvenv.cfg").write_text("home = /usr/bin")
    (src / "myenv" / "lib" / "big.py").write_text("x")
    (src / "__pycache__").mkdir()
    (src / "__pycache__" / "a.pyc").write_text("x")
    (src / "app.py").write_text("print(1)")
    (src / "package-lock.json").write_text("{}")
    (src / "notvenv").mkdir()
    (src / "notvenv" / "real.py").write_text("y")  # a plain directory is still scanned
    out = prepare_workspace(src, tmp_path / "ws")
    found = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert found == ["app.py", "notvenv/real.py", "package-lock.json"]
