"""Text embeddings without a model: hashed, IDF-weighted bag of words and bigrams.

Why not a neural embedding model: none ships with this stack, an API embedding call would send finding
text to a third party and add a hard dependency, and the corpus is small, technical and keyword-rich
(CWE names, "prepared statements", "deserialization"), where lexical features work well. The `Embedder`
protocol keeps the door open; a neural model can replace this behind the same interface (see docs/rag.md).
How well this retrieves is measured, not assumed: tests/rag_eval.py and docs/rag.md report the numbers.

The embedding is deterministic and offline. Feature hashing maps tokens into DIM buckets with a random
sign (so collisions cancel instead of accumulating); IDF is learned per bucket from the corpus at load
time and stored with the index, so queries are embedded with exactly the weights the documents were.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Protocol

DIM = 1024  # 384 collided too much (recall@5 71% -> 84% at 1024); 2000 is pgvector's index limit
NAME = "hash-tfidf-1024-v1"

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.+#-]*")
_STOP = frozenset(
    "a an the and or of to in for on with by from is are was be as at it its this that these those "
    "can may not no you your we our they their if then when which while also such use used using "
    "should must will would could than into any all more most other some each per via".split()
)


class Embedder(Protocol):
    name: str
    dim: int

    def embed_query(self, text: str) -> list[float]: ...
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...


def _stem(w: str) -> str:
    for suf in ("ations", "ation", "ings", "ing", "edly", "ed", "ies", "es", "s"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            return w[: -len(suf)] + ("y" if suf == "ies" else "")
    return w


def tokens(text: str) -> list[str]:
    """Lower-cased, stop-worded, lightly stemmed words, then adjacent-word bigrams."""
    words = [_stem(w.strip(".-+#")) for w in _TOKEN.findall(text.lower())]
    words = [w for w in words if len(w) > 1 and w not in _STOP]
    return words + [f"{a}_{b}" for a, b in zip(words, words[1:], strict=False)]


def _bucket(tok: str) -> tuple[int, float]:
    h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
    return h % DIM, 1.0 if (h >> 40) & 1 else -1.0


def _tf(text: str) -> dict[int, float]:
    counts: dict[str, int] = {}
    for t in tokens(text):
        counts[t] = counts.get(t, 0) + 1
    vec: dict[int, float] = {}
    for t, c in counts.items():
        b, sign = _bucket(t)
        vec[b] = vec.get(b, 0.0) + sign * (1.0 + math.log(c))
    return vec


def _normalise(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v] if n else v


@dataclass
class HashingEmbedder:
    idf: list[float]  # one weight per bucket, fitted on the corpus
    name: str = NAME
    dim: int = DIM

    @classmethod
    def fit(cls, documents: list[str]) -> HashingEmbedder:
        """IDF per bucket: rarely-hit buckets (specific terms) weigh more than ones every document hits."""
        df = [0] * DIM
        for d in documents:
            for b in _tf(d):
                df[b] += 1
        n = max(len(documents), 1)
        return cls(idf=[math.log((1 + n) / (1 + c)) + 1.0 for c in df])

    def _embed(self, text: str) -> list[float]:
        v = [0.0] * DIM
        for b, w in _tf(text).items():
            v[b] = w * self.idf[b]
        return _normalise(v)

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    """Vectors from this module are unit length, so the dot product is the cosine."""
    return sum(x * y for x, y in zip(a, b, strict=True))
