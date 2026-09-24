from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from core.persistence.models import Base


@pytest.fixture(autouse=True)
def _isolated_workdir(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep every test's scratch/upload files out of the real temp dir."""
    monkeypatch.setenv("BULWARK_WORKDIR", str(tmp_path_factory.mktemp("work")))


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    d = tmp_path / "sample"
    d.mkdir()
    (d / "app.py").write_text("x = 1\n")
    return d
