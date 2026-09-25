# ADR-009: Remediation knowledge base on pgvector, with a model-free embedder

Status: Accepted (2026-09-25, Week 11)

## Context
The LLM remediation layer (Weeks 12-14) needs grounding text per finding: what the weakness is (CWE) and how to
fix it (OWASP cheat sheets). The design doc asks for a local corpus and a vector store that avoids adding
another service.

## Decision
1. **Corpus**: 211 CWE entries (every CWE in the OWASP Top 10 table plus those scanners emitted in our real
   scans) and 1,697 chunks from 59 OWASP cheat sheets. Built by `scripts/build-corpus.py`, committed under
   `core/rag/corpus/`, versions pinned in `SOURCES.json`. Nothing is fetched at scan time.
2. **Store**: two tables in the existing PostgreSQL (`kb_chunks`, `kb_meta`). pgvector `vector(1024)` with an
   HNSW cosine index. SQLite (tests, quick local runs) stores the vector as JSON and searches in Python; both
   produce identical rankings (checked on real Postgres). The Postgres image is `postgres:16-alpine` plus
   pgvector v0.8.0 compiled from source (`docker/postgres/Dockerfile`), so existing data volumes keep working.
3. **Embedder**: hashed, IDF-weighted bag of words and bigrams (`core/rag/embed.py`), no ML model, offline,
   deterministic. IDF is fitted at load time and stored with the index. An `Embedder` protocol allows a neural
   model later; the index records which embedder built it and refuses to be queried by another.
4. **Retrieval** (`core/rag/retrieve.py`): exact CWE lookup first, then cheat-sheet chunks that address the
   finding's CWEs (else its OWASP categories) ranked by similarity, else pure similarity. The query uses the
   finding's title and description, **never its code snippet**.

## Why not a neural embedding model
No embedding model ships with this stack. An API call would send finding text to a third party and make a
network dependency of something that should work offline; a local model (sentence-transformers) pulls in
PyTorch (hundreds of MB) for a 2k-chunk corpus. The corpus is keyword-rich, and lexical retrieval plus
CWE/OWASP metadata is enough to be useful. The cost is real and measured (below).

## Measured (80 real findings, `tests/fixtures/rag_eval.json`; see docs/rag.md)
Without metadata, the right sheet is first 52.5% of the time and in the top 5 84% of the time. With CWE
metadata the first guidance item is a relevant sheet in 100% of cases. Dimension was chosen by sweeping
384 to 2000 on this same set (384: 71% top-5; 1024: 84%; 2000: 84%); it is one parameter, but it is tuned on
the data it is reported on.

## Consequences
- Plain-English queries without shared vocabulary miss (for example, "server fetches a URL supplied by the
  user" does not find the SSRF sheet). Findings with a CWE or OWASP tag do not depend on this.
- Changing the embedder or dimension means a new migration and `bulwark kb load`.
- CC BY-SA share-alike applies to the cheat-sheet chunks (`core/rag/corpus/NOTICE.md`); the rest stays Apache-2.0.
- Everything retrieved is passed to a model as data, never instructions (T8).
