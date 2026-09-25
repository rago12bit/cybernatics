#!/usr/bin/env python3
"""Precompute reference guidance for the sample scan's findings (web/lib/demo-guidance.json).

The public sample site has no API, so it ships the guidance the API would return: produced by the real
retrieval code over the real corpus, not written by hand. There is no AI text in it, ever: the sample site
runs no model. Re-run after changing the corpus, retrieval, or web/lib/demo-data.json.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.llm.service import static_suggestion  # noqa: E402
from core.models import finding_from_dict  # noqa: E402
from core.persistence.models import Base  # noqa: E402
from core.rag.corpus_io import read_corpus  # noqa: E402
from core.rag.retrieve import context_for  # noqa: E402
from core.rag.store import KnowledgeBase, load_corpus  # noqa: E402


def main() -> None:
    demo = json.loads((ROOT / "web/lib/demo-data.json").read_text())
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    out: dict[str, dict] = {}
    with Session(engine) as s:
        load_corpus(s, read_corpus())
        kb = KnowledgeBase(s)
        for raw in demo["findings"]:
            f = finding_from_dict(raw)
            r = static_suggestion(f, context_for(f, kb), "reference guidance")
            out[f.id] = asdict(r)
    (ROOT / "web/lib/demo-guidance.json").write_text(json.dumps(out, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"{len(out)} findings")


if __name__ == "__main__":
    main()
