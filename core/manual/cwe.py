"""Searching weaknesses for the CWE picker (plan §43.2), from the MITRE CWE extract the knowledge
base already bundles (`core/rag/corpus/cwe.jsonl`, attribution in its NOTICE.md). Any CWE number
can still be entered; this list is what the picker suggests."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_CORPUS = Path(__file__).resolve().parent.parent / "rag" / "corpus" / "cwe.jsonl"
_ID = re.compile(r"^\s*(?:cwe[-_ ]?)?(\d{1,6})\s*$", re.IGNORECASE)


@lru_cache(maxsize=1)
def catalogue() -> tuple[tuple[str, str], ...]:
    rows = []
    with _CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            d = json.loads(line)
            rows.append((str(d["id"]), str(d["name"])))
    return tuple(sorted(rows, key=lambda r: int(r[0].split("-")[1])))


def normalize(value: str) -> str | None:
    """`CWE-89` for "89", "cwe 89" or "CWE-89"; None for anything that is not a CWE number."""
    m = _ID.match(value or "")
    return f"CWE-{int(m.group(1))}" if m and int(m.group(1)) > 0 else None


def name_of(cwe: str) -> str | None:
    return dict(catalogue()).get(cwe)


def search(query: str, limit: int = 20) -> list[tuple[str, str]]:
    """Exact id first, then names containing every word of the query, shortest name first."""
    q = (query or "").strip()
    if not q:
        return list(catalogue()[:limit])
    exact = normalize(q)
    words = [w for w in re.split(r"\W+", q.lower()) if w]
    hits = [
        (cid, name)
        for cid, name in catalogue()
        if cid == exact or (words and all(w in f"{cid} {name}".lower() for w in words))
    ]
    hits.sort(key=lambda r: (r[0] != exact, len(r[1])))
    if exact and not any(cid == exact for cid, _ in hits):
        hits.insert(0, (exact, ""))  # a real CWE the bundled extract does not describe
    return hits[:limit]
