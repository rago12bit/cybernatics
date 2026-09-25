# Remediation knowledge base (RAG)

Reference text for the LLM remediation layer: CWE definitions and OWASP cheat-sheet guidance, searchable in
PostgreSQL. **Nothing here calls an LLM yet** (that starts in Week 12); this is the retrieval half. Decision
record: [ADR-009](adr/0009-remediation-knowledge-base.md).

## Use

```bash
bulwark kb load                           # build the index from the committed corpus (about a second)
bulwark kb stats                          # embedder, counts, backend (pgvector or json)
bulwark kb search "prototype pollution" -k 3 --kind cheatsheet
```

In code:

```python
from core.rag.retrieve import context_for
from core.rag.store import KnowledgeBase

ctx = context_for(finding, KnowledgeBase(session))   # RemediationContext
ctx.basis          # "cwe" | "owasp" | "semantic" | "none": how the guidance was chosen
ctx.cwe_entries    # the finding's own CWE entries (description, consequences, mitigations)
ctx.guidance       # up to k cheat-sheet sections, each with source URL and similarity score
```

`docker compose up` runs the migration that creates the tables and enables the pgvector extension; run
`docker compose exec worker bulwark kb load` once afterwards.

## What is in the corpus

| | Count | Source | Licence |
|---|---:|---|---|
| CWE entries | 211 | MITRE CWE 4.20 (`cwec_latest.xml`) | CWE Terms of Use |
| Cheat-sheet chunks | 1,697 (59 sheets) | OWASP Cheat Sheet Series @ `c04039a` | CC BY-SA 4.0 |

Which CWEs: all 196 in the OWASP Top 10 mapping plus 30 that scanners actually emitted in our real scans.
15 of the 226 requested ids are CWE *categories* or views, not weaknesses, so they have no entry. Sheets are
tagged with OWASP categories and CWE ids by our own curation (`SHEETS` in `scripts/build-corpus.py`), which is
a judgment call, not OWASP's assertion. Every OWASP Top 10 category has at least one sheet (tested).
Rebuild with `python scripts/build-corpus.py` (needs network; the output is committed).

## How retrieval works

1. Exact lookup of the finding's CWE entries (each capped at 25% of the character budget).
2. Cheat-sheet chunks tagged with those CWEs (else those OWASP categories), ranked by cosine similarity
   between the query (title + description + CWE names) and the chunk, at most two per sheet.
3. If the finding has no CWE and no OWASP tag: closest chunks overall.

The query never includes the code snippet: it is attacker-controlled repository text and could carry
prompt-injection or, if redaction missed it, a secret.

## Measured quality

Evaluation set: 80 unique real findings from scans of nodejs-goof and the sample project (skewed toward
dependency findings: prototype pollution and denial of service are 45% of cases). A sheet is "relevant" when
our curated table lists one of the finding's CWEs, so this checks retrieval consistency, not whether the
advice is right. Reproduce: `pytest tests/unit/test_rag.py -k quality`.

| Mode | Hit@1 | Hit@3 | Hit@5 | MRR |
|---|---:|---:|---:|---:|
| Semantic only (no CWE/OWASP given), 1024 dims | 52.5% | 70% | 84% | 0.64 |
| Same, 384 dims (first version) | 37.5% | 60% | 71% | 0.52 |

| Mode | First guidance item relevant |
|---|---:|
| Full pipeline with CWE/OWASP metadata | 100% |

The 100% is close to by construction (results are filtered to sheets tagged with the finding's CWE); it mainly
proves the pipeline returns guidance at all. It did not at first: two long CWE entries used up the whole
budget and returned nothing for 7.5% of cases. That is fixed and has a regression test.

## Limits

- **Lexical, not semantic.** A query that shares no words with the right sheet misses it ("server fetches a
  URL supplied by the user" does not find the SSRF sheet). Findings that carry a CWE do not depend on this.
- The dimension (1024) was picked by sweeping on the same 80 cases it is reported on.
- English only; ~1,900 chunks, so no scaling claims. HNSW is built but not needed at this size.
- Chunks are reference text, not verified fixes. Whether generated fixes are correct is evaluated by hand in
  Week 14.
- The cheat-sheet chunks are CC BY-SA: redistribute them under that licence (see `core/rag/corpus/NOTICE.md`).
