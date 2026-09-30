"""A pgvector `vector(dim)` column on PostgreSQL, a JSON array everywhere else -- no extra Python
dependency either way. Lives here (not in `core.rag.store`, its original home) so both `core.rag`
(the remediation knowledge base) and `core.embeddings` (per-asset code-chunk retrieval, Week 44) can
share one TypeDecorator without either importing the other: `core.rag.store` already depends on
`core.persistence.models`, so this module sits below both rather than introducing a cycle.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import JSON
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator, TypeEngine, UserDefinedType


class _PgVector(UserDefinedType[Any]):
    cache_ok = True

    def __init__(self, dim: int) -> None:
        self.dim = dim

    def get_col_spec(self, **kw: Any) -> str:
        return f"vector({self.dim})"


class Vector(TypeDecorator[list[float]]):
    """pgvector `vector(dim)` on PostgreSQL, a JSON array elsewhere."""

    impl = JSON
    cache_ok = True

    def __init__(self, dim: int) -> None:
        super().__init__()
        self.dim = dim

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        if dialect.name == "postgresql":
            return _PgVector(self.dim)
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value: list[float] | None, dialect: Dialect) -> Any:
        if value is None or dialect.name != "postgresql":
            return value
        return "[" + ",".join(f"{x:.6f}" for x in value) + "]"

    def process_result_value(self, value: Any, dialect: Dialect) -> list[float] | None:
        if value is None:
            return None
        return [float(x) for x in json.loads(value)] if isinstance(value, str) else list(value)
