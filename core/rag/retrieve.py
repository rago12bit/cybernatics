"""Retrieval for the remediation layer: what reference text should accompany a finding?

Order of evidence (most to least specific), so the model is handed authoritative text first:
  1. the CWE entries for the finding's own CWE ids (exact lookup);
  2. cheat-sheet sections that address those CWEs (else the finding's OWASP categories), ranked by
     similarity to the finding's title and description;
  3. only when the finding has neither: the closest cheat-sheet sections overall (`basis="semantic"`).

The query is built from the finding's TITLE and DESCRIPTION, never its code snippet: the snippet comes
from the scanned repository (attacker-controlled) and may hold prompt-injection text or, if redaction
missed something, a secret. Everything returned is public reference text; it is still passed to a model
as data, not instructions (threat T8, docs/THREAT-MODEL.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.models import Finding
from core.rag.store import Hit, KnowledgeBase
from core.taxonomy import cwe_name, normalize_cwe

MAX_PER_SHEET = 2  # diversity: do not hand the model three sections of the same document
CWE_SHARE = (
    0.25  # each CWE entry may use at most this share of the budget; the rest is for guidance
)


@dataclass
class Reference:
    source: str  # "cwe" | "cheatsheet"
    title: str
    section: str
    url: str
    text: str
    score: float | None = None


@dataclass
class RemediationContext:
    basis: str  # "cwe" | "owasp" | "semantic" | "none"
    cwe_entries: list[Reference] = field(default_factory=list)
    guidance: list[Reference] = field(default_factory=list)

    def total_chars(self) -> int:
        return sum(len(r.text) for r in [*self.cwe_entries, *self.guidance])


def _query(f: Finding) -> str:
    names = [n for c in f.taxonomy.cwe if (n := cwe_name(c))]
    return " ".join([f.title, f.description[:400], *names])


def _ref(h: Hit) -> Reference:
    c = h.chunk
    return Reference(c.kind, c.title, c.section, c.url, c.text, round(h.score, 4))


def context_for(
    f: Finding, kb: KnowledgeBase, *, k: int = 3, max_chars: int = 6000
) -> RemediationContext:
    cwes = {c for c in map(normalize_cwe, f.taxonomy.cwe) if c}
    owasp = set(f.taxonomy.owasp_top_10_2021)
    ctx = RemediationContext(basis="none")

    for cid in sorted(cwes, key=lambda c: int(c.split("-")[1]))[:2]:
        doc = kb.cwe(cid)
        if doc:
            cap = int(
                max_chars * CWE_SHARE
            )  # CWE-20 alone is many pages: never let it starve the guidance
            ctx.cwe_entries.append(
                Reference("cwe", doc.title, doc.section, doc.url, doc.text[:cap])
            )

    ids = kb.candidates(cwes, owasp)
    if ids:
        by_cwe = bool(cwes) and any(
            set(h.chunk.cwes) & cwes for h in kb.search(_query(f), 1, ids=ids)
        )
        ctx.basis = "cwe" if by_cwe else "owasp"
        pool = kb.search(_query(f), k * 4, ids=ids)
    else:
        ctx.basis = "semantic"
        pool = kb.search(_query(f), k * 4, kind="cheatsheet")

    seen: dict[str, int] = {}
    budget = max_chars - ctx.total_chars()
    for h in pool:
        if len(ctx.guidance) >= k or budget <= 0:
            break
        if seen.get(h.chunk.title, 0) >= MAX_PER_SHEET:
            continue
        seen[h.chunk.title] = seen.get(h.chunk.title, 0) + 1
        ref = _ref(h)
        ref.text = ref.text[:budget]
        budget -= len(ref.text)
        ctx.guidance.append(ref)
    if not ctx.cwe_entries and not ctx.guidance:
        ctx.basis = "none"
    return ctx
