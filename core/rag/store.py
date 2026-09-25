"""Knowledge-base store: chunks plus their embeddings, in the same database as everything else.

On PostgreSQL the embedding is a pgvector `vector(1024)` column with an HNSW cosine index and search is
`ORDER BY embedding <=> query`. Everywhere else (SQLite in tests and quick local runs) the embedding is a
JSON array and search is a brute-force cosine in Python. Both give the same ranking; the corpus is ~2k rows,
so the fallback is instant. Choosing pgvector avoids running a separate vector database (ADR-009).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import JSON, Integer, String, Text, delete, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.types import TypeDecorator, TypeEngine, UserDefinedType

from core.persistence.models import Base
from core.rag.corpus_io import Chunk
from core.rag.embed import DIM, NAME, HashingEmbedder

_JSON = JSON().with_variant(JSONB(), "postgresql")


class _PgVector(UserDefinedType[Any]):
    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return f"vector({DIM})"


class Vector(TypeDecorator[list[float]]):
    """pgvector `vector(DIM)` on PostgreSQL, a JSON array elsewhere. No extra Python dependency."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        return _PgVector() if dialect.name == "postgresql" else dialect.type_descriptor(JSON())

    def process_bind_param(self, value: list[float] | None, dialect: Dialect) -> Any:
        if value is None or dialect.name != "postgresql":
            return value
        return "[" + ",".join(f"{x:.6f}" for x in value) + "]"

    def process_result_value(self, value: Any, dialect: Dialect) -> list[float] | None:
        if value is None:
            return None
        return [float(x) for x in json.loads(value)] if isinstance(value, str) else list(value)


class KbChunk(Base):
    __tablename__ = "kb_chunks"

    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # cwe | cheatsheet
    title: Mapped[str] = mapped_column(String(300))
    section: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    owasp: Mapped[list[str]] = mapped_column(_JSON)
    cwes: Mapped[list[str]] = mapped_column(_JSON)
    url: Mapped[str] = mapped_column(String(500))
    content_hash: Mapped[str] = mapped_column(String(64))
    embedding: Mapped[list[float]] = mapped_column(Vector())


class KbMeta(Base):
    __tablename__ = "kb_meta"

    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(_JSON)
    n: Mapped[int] = mapped_column(Integer, default=0)


@dataclass
class Hit:
    chunk: Chunk
    score: float


def _doc_text(c: Chunk) -> str:
    # Title and section repeat so they outweigh body words: "SQL Injection Prevention" should win a SQL query.
    return f"{c.title}. {c.title}. {c.section}. {c.text}"


def _to_chunk(r: KbChunk) -> Chunk:
    return Chunk(r.id, r.kind, r.title, r.section, r.body, tuple(r.owasp), tuple(r.cwes), r.url)


def load_corpus(s: Session, chunks: list[Chunk]) -> dict[str, Any]:
    """(Re)build the index from `chunks` in one transaction: fit IDF, embed, replace all rows."""
    emb = HashingEmbedder.fit([_doc_text(c) for c in chunks])
    vectors = emb.embed_documents([_doc_text(c) for c in chunks])
    s.execute(delete(KbChunk))
    s.execute(delete(KbMeta))
    for c, v in zip(chunks, vectors, strict=True):
        s.add(
            KbChunk(id=c.id, kind=c.kind, title=c.title[:300], section=c.section, body=c.text,
                    owasp=list(c.owasp), cwes=list(c.cwes), url=c.url, content_hash=c.content_hash,
                    embedding=v)
        )  # fmt: skip
    s.add(
        KbMeta(
            key="embedder", value={"name": emb.name, "dim": emb.dim, "idf": emb.idf}, n=len(chunks)
        )
    )
    s.flush()
    if s.get_bind().dialect.name == "postgresql":
        s.execute(text("ANALYZE kb_chunks"))
    s.commit()
    kinds: dict[str, int] = {}
    for c in chunks:
        kinds[c.kind] = kinds.get(c.kind, 0) + 1
    return {"embedder": emb.name, "chunks": len(chunks), "by_kind": kinds}


class KnowledgeBase:
    """Read side: load the embedder the index was built with, then search."""

    def __init__(self, s: Session) -> None:
        self.s = s
        meta = s.get(KbMeta, "embedder")
        if meta is None:
            raise RuntimeError("the knowledge base is empty: run `bulwark kb load`")
        if meta.value["name"] != NAME:
            raise RuntimeError(
                f"index was built with {meta.value['name']!r}, this code uses {NAME!r}: reload it"
            )
        self.embedder = HashingEmbedder(idf=list(meta.value["idf"]))
        self.size = meta.n
        self._pg = s.get_bind().dialect.name == "postgresql"

    def stats(self) -> dict[str, Any]:
        rows = self.s.execute(select(KbChunk.kind, KbChunk.id)).all()
        by: dict[str, int] = {}
        for kind, _ in rows:
            by[kind] = by.get(kind, 0) + 1
        return {
            "embedder": self.embedder.name,
            "chunks": self.size,
            "by_kind": by,
            "backend": "pgvector" if self._pg else "json",
        }

    def cwe(self, cwe_id: str) -> Chunk | None:
        r = self.s.get(KbChunk, cwe_id)
        return _to_chunk(r) if r and r.kind == "cwe" else None

    def candidates(self, cwes: set[str], owasp: set[str]) -> list[str]:
        """Cheat-sheet chunk ids that address one of these CWEs, else one of these OWASP categories."""
        by_cwe: list[str] = []
        by_owasp: list[str] = []
        for cid, cw, ow in self.s.execute(
            select(KbChunk.id, KbChunk.cwes, KbChunk.owasp).where(KbChunk.kind == "cheatsheet")
        ):
            if cwes & set(cw):
                by_cwe.append(cid)
            elif owasp & set(ow):
                by_owasp.append(cid)
        return by_cwe or by_owasp

    def search(
        self, query: str, k: int = 5, *, ids: list[str] | None = None, kind: str | None = None
    ) -> list[Hit]:
        """Top-k chunks by cosine similarity, optionally restricted to `ids` and/or a `kind`."""
        q = self.embedder.embed_query(query)
        if ids is not None and not ids:
            return []
        if self._pg:
            qv = "[" + ",".join(f"{x:.6f}" for x in q) + "]"
            where, params = ["1=1"], {"q": qv, "k": k}
            if ids is not None:
                where.append("id = ANY(:ids)")
                params["ids"] = ids
            if kind:
                where.append("kind = :kind")
                params["kind"] = kind
            rows = self.s.execute(
                text(f"SELECT id, 1 - (embedding <=> CAST(:q AS vector)) AS score FROM kb_chunks "
                     f"WHERE {' AND '.join(where)} ORDER BY embedding <=> CAST(:q AS vector) LIMIT :k"),
                params,
            ).all()  # fmt: skip
            found = {r.id: float(r.score) for r in rows}
            chunks = {
                r.id: _to_chunk(r)
                for r in self.s.scalars(select(KbChunk).where(KbChunk.id.in_(list(found))))
            }
            return [Hit(chunks[i], found[i]) for i in found if i in chunks]
        stmt = select(KbChunk)
        if ids is not None:
            stmt = stmt.where(KbChunk.id.in_(ids))
        if kind:
            stmt = stmt.where(KbChunk.kind == kind)
        # Queries are sparse (tens of non-zero buckets out of 1024): score only those, ~20x faster than a full dot.
        nz = [(i, x) for i, x in enumerate(q) if x]
        scored = [(sum(x * r.embedding[i] for i, x in nz), r) for r in self.s.scalars(stmt)]
        scored.sort(key=lambda t: (-t[0], t[1].id))
        return [Hit(_to_chunk(r), sc) for sc, r in scored[:k]]
