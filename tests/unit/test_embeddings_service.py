"""core.embeddings.service.index_checkout: the whole analyze-chunk-embed-persist pass (plan §21.5),
against a real on-disk directory and a real `core.codeintel.analyze()` call -- not a hand-built
CodeGraph fixture."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from core.embeddings.service import index_checkout
from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID


def _asset(sessions: sessionmaker[Session]) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def test_index_checkout_end_to_end_against_a_real_directory(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "users.py").write_text(
        "def get_user(uid):\n    return db.execute('SELECT * FROM users WHERE id=?', (uid,))\n\n"
        "def delete_user(uid):\n    db.execute('DELETE FROM users WHERE id=?', (uid,))\n"
    )
    asset_id = _asset(sessions)
    with sessions() as s:
        stats = index_checkout(s, asset_id, tmp_path)
    assert stats["chunks"] == 2

    with sessions() as s:
        hits = repo.search_code_chunks(s, asset_id, "delete a user")
        assert hits and hits[0][0].symbol_name == "delete_user"


def test_reindexing_an_unchanged_checkout_does_not_grow_the_index(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    asset_id = _asset(sessions)
    with sessions() as s:
        index_checkout(s, asset_id, tmp_path)
        stats = index_checkout(s, asset_id, tmp_path)
    assert stats["chunks"] == 1
