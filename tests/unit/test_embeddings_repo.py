"""core.persistence.repo's code-chunk functions (Week 44, plan §21.5): refresh/search."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.embeddings.chunk import CodeChunk
from core.persistence import repo
from core.persistence.models import CodeChunkRow
from core.tenancy import DEFAULT_ORG_ID


def _asset(sessions: sessionmaker[Session], org_id: str = DEFAULT_ORG_ID) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=org_id,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def _chunk(name: str, text: str, line: int = 1) -> CodeChunk:
    return CodeChunk(
        id=f"app.py:{name}:{line}", path="app.py", symbol_name=name, qualified_name=name,
        kind="function", language="python", start_line=line, end_line=line + 1, text=text,
    )  # fmt: skip


def test_refresh_then_search_ranks_the_more_relevant_chunk_first(
    sessions: sessionmaker[Session],
) -> None:
    asset_id = _asset(sessions)
    chunks = [
        _chunk("get_user", "return db.execute('SELECT * FROM users WHERE id=?', (uid,))"),
        _chunk("delete_user", "db.execute('DELETE FROM users WHERE id=?', (uid,))", line=10),
    ]
    with sessions() as s:
        stats = repo.refresh_code_chunks(s, asset_id, chunks)
        assert stats == {"chunks": 2, "embedder": "hash-tfidf-1024-v1"}
    with sessions() as s:
        hits = repo.search_code_chunks(s, asset_id, "delete a user from the database")
        assert [row.symbol_name for row, _ in hits][0] == "delete_user"


def test_refreshing_again_replaces_rather_than_appends(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        repo.refresh_code_chunks(s, asset_id, [_chunk("f", "pass")])
        repo.refresh_code_chunks(s, asset_id, [_chunk("f", "pass")])
    with sessions() as s:
        rows = list(s.query(CodeChunkRow).filter(CodeChunkRow.asset_id == asset_id))
        assert len(rows) == 1


def test_search_before_any_refresh_returns_empty_not_an_error(
    sessions: sessionmaker[Session],
) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        assert repo.search_code_chunks(s, asset_id, "anything") == []


def test_search_is_scoped_to_the_requesting_org(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions, org_id="org-a")
    with sessions() as s:
        repo.refresh_code_chunks(s, asset_id, [_chunk("f", "return 1")])
    with sessions() as s:
        assert repo.search_code_chunks(s, asset_id, "return", org_id="org-b") == []
        assert len(repo.search_code_chunks(s, asset_id, "return", org_id="org-a")) == 1


def test_search_against_an_unknown_asset_returns_empty(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        assert repo.search_code_chunks(s, "no-such-asset", "anything") == []
