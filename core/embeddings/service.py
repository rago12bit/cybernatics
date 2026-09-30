"""Chunk a checkout and refresh one asset's code-chunk index in one call (plan §21.5) -- the
orchestration an indexing endpoint or job would call, mirroring `core.hypotheses.service
.generate_for_checkout`'s "analyze, then persist" shape. Unlike that module, nothing here calls a
model: chunking (`core.embeddings.chunk`) and embedding (`core.rag.embed.HashingEmbedder`, reused
rather than reinvented -- see ADR-0029) are both deterministic, so indexing has no "no model
configured" failure mode and is never gated by the LLM gateway.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.codeintel import analyze
from core.embeddings.chunk import chunk_checkout
from core.persistence.repo import refresh_code_chunks


def index_checkout(s: Session, asset_id: str, checkout: Path) -> dict[str, Any]:
    graph = analyze(checkout)
    chunks = chunk_checkout(checkout, graph)
    return refresh_code_chunks(s, asset_id, chunks)
