"""Measure retrieval quality against real findings (tests/fixtures/rag_eval.json).

A case is a finding seen in a real scan (title, description, CWEs). A cheat sheet counts as *relevant* when
its curated CWE list (scripts/build-corpus.py) includes one of the finding's CWEs. Two things are measured:

  semantic   the finding is searched WITHOUT its CWE or OWASP metadata, as happens for a finding a scanner
             gave no CWE. Hit@k: is a relevant sheet in the top k?  MRR: 1/rank of the first relevant one.
  pipeline   the full `context_for` path with metadata. Reports how often the FIRST guidance item is relevant.

The ground truth is our own curated sheet-to-CWE table, so this checks retrieval consistency, not whether
the advice is correct; correctness of generated fixes is evaluated by hand in Week 14.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select

from core.models import Category, Finding, Location, Taxonomy
from core.rag.retrieve import context_for
from core.rag.store import KbChunk, KnowledgeBase

FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "rag_eval.json"
KS = (1, 3, 5)


def load_cases(path: Path = FIXTURE) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return cases


def _sheet_cwes(kb: KnowledgeBase) -> dict[str, set[str]]:
    sheets: dict[str, set[str]] = {}
    for title, cwes in kb.s.execute(
        select(KbChunk.title, KbChunk.cwes).where(KbChunk.kind == "cheatsheet")
    ):
        sheets.setdefault(title, set()).update(cwes)
    return sheets


def _finding(case: dict[str, Any], *, metadata: bool) -> Finding:
    tax = Taxonomy(
        Category(case["category"]),
        cwe=tuple(case["cwes"]) if metadata else (),
        owasp_top_10_2021=tuple(case["owasp"]) if metadata else (),
    )
    return Finding(
        id="e",
        title=case["title"],
        description=case["description"],
        location=Location("x", 1, 1),
        taxonomy=tax,
    )


def evaluate(kb: KnowledgeBase, cases: list[dict[str, Any]]) -> dict[str, Any]:
    sheets = _sheet_cwes(kb)
    hits = {k: 0 for k in KS}
    rr = 0.0
    first_ok = 0
    n = 0
    for case in cases:
        relevant = {t for t, cw in sheets.items() if cw & set(case["cwes"])}
        if not relevant:
            continue
        n += 1
        # semantic-only: no CWE / OWASP metadata, whole cheat-sheet corpus, ranked by chunk then de-duplicated by sheet
        q = _finding(case, metadata=False)
        order: list[str] = []
        for h in kb.search(f"{q.title} {q.description}", 30, kind="cheatsheet"):
            if h.chunk.title not in order:
                order.append(h.chunk.title)
        rank = next((i + 1 for i, t in enumerate(order) if t in relevant), None)
        for k in KS:
            hits[k] += bool(rank and rank <= k)
        rr += 1 / rank if rank else 0.0
        ctx = context_for(_finding(case, metadata=True), kb)
        first_ok += bool(ctx.guidance and ctx.guidance[0].title in relevant)
    return {
        "cases": n,
        "semantic": {**{f"hit@{k}": round(hits[k] / n, 3) for k in KS}, "mrr": round(rr / n, 3)},
        "pipeline_first_guidance_relevant": round(first_ok / n, 3),
    }
