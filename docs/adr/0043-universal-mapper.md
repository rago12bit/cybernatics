# ADR-0043: A saved mapping is a deterministic, sandboxed parser; the model only drafts it

Status: Accepted (2026-10-05), Week 59 (plan §42.4, §50 "Mapping assistant"). Builds on
[ADR-0040](0040-one-ingest-path.md) (one ingest path) and [ADR-0042](0042-dedup-strategies-per-source.md)
(deduplication per source).

## Context

Fourteen parsers cover the standard formats and the most-used tools. Every organization also has a
report nobody wrote a parser for: an in-house scanner's JSON, a vendor's CSV export, a pen-test tool's
XML. The plan (§42.4) asks for a universal mapper: upload a sample, "the model proposes field mappings
... a person reviews and edits them, with a live preview ... the saved mapping is a deterministic
parser. The model helped write it; it is never in the import path."

Three things had to be decided: what a mapping can express, where it runs, and what the model is
allowed to see and do.

## Decision

### A mapping is data, compiled into an `IngestParser` (`core/imports/parsers/universal.py`)

A `MappingSpec` names the format (JSON, CSV, XML), where the records are, the tool's name (the
`source`: what "reported by" says and what deduplication settings are chosen for), a category, and one
path per field: title (required), severity, description, path, line, rule, CWE, CVE, URL, package,
version, ecosystem, recommendation, references. A severity map turns the tool's own words into ours;
anything still unknown is Info and said so, as every ported parser does.

`UniversalParser(spec)` is an `IngestParser` like the others: it streams, it never raises on bad
input, a file not read to the end is an error (so it can never close anything), and it builds web and
dependency findings with the same helpers the built-in parsers use (`dast_finding`, package identity),
so a mapped Nessus-like CSV and the real Nessus parser agree on what identifies a finding.

### The path language is deliberately smaller than JSONPath

`$`, `.key`, `["key"]`, `[n]`, `[*]` for JSON; `child/grandchild`, `@attr`, `.` for XML (local
names); a column name for CSV. No filters, recursive descent, slices or scripts.

Considered: `jsonpath-ng` (the plan's own resource list). Rejected for the import path because a
mapping is evaluated against attacker-controlled files, and everything JSONPath adds beyond this
subset -- filter expressions, `..` -- is either code-like or has a cost that depends on the data. The
subset covers every real report in the evaluation, its cost is linear in the record, and a person can
read any path at a glance. A records path must be keys and `[*]` ending in `[*]`, because it is turned
into an `ijson` streaming prefix: a mapped file is never loaded whole.

### It runs in the parser sandbox

The spec is written beside the uploaded file and the same container runs it (`worker.py --mapping`),
so a mapped import has exactly the isolation of a built-in one. Describing a sample's shape for the
mapping screen (`analyze.py`, `worker.py --analyze`) also reads uploaded bytes and runs there too.

### Saved mappings are versioned by insertion and tenant-isolated (migration 0030)

`ingest_mappings` follows `dedup_settings`: an edit adds a row with the next version and never changes
an earlier one. An import names the exact row (`universal:<id>`), so what parsed a past import is
always known. Direct `org_id` with the forced RLS policy; a mapping id from another org resolves as
unknown. A mapping's source cannot be a built-in parser's or scanner's name, or the two would share
deduplication settings. Saving is audit-logged.

### The model drafts from a description, and its draft is checked against it

The model is shown the *analysis* -- candidate record paths, field paths, three short examples each --
with secrets scrubbed and the whole thing nonce-fenced as untrusted data, never the file. Its reply is
then checked against that same analysis (`mapper.sanitize`): a records path or field path the sample
does not have, a field that does not exist, or a severity that is not one is dropped and listed in the
draft's notes. With no model configured, the budget spent (`check_org`/`record_org`, the org's monthly
cap), or a reply that does not hold up, the draft comes from name matching instead, and says so. The
prompt is versioned (`core/llm/prompts/mapper/v1.md`) with a promptfoo evaluation whose assertion is
the same `sanitize`.

Either way the draft is only a draft: saving needs a person (and `ingest:write`), the preview runs the
mapping exactly as an import would, and the import itself never calls a model.

### Suggested, never picked

When nothing built-in recognises an upload with confidence, saved mappings whose `sniff` matches it
are offered among the "detected" formats; one is used only when named. A mapping that half-fits a
file would otherwise silently produce half the findings.

## Consequences

- An unsupported format is an afternoon's mapping, not a parser and a release -- and the plan's
  "15 formats" milestone can count saved mappings honestly only as what they are: mappings.
- Fuzzed like a parser: three fixed mappings and the sample analysis are fuzz targets
  (`tests/fuzz/mappings.py`) in the nightly matrix.
- Not supported, deliberately: computed fields (concatenating two paths), per-record categories, and
  filters. A report that needs them needs a parser.
- The model's draft quality is measured by its eval set, which was not run in this environment (no
  local model); the draft's *safety* does not depend on its quality, because nothing it says reaches
  an import without a person and a deterministic parser in between.
