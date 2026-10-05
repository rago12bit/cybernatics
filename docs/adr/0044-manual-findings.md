# ADR-0044: Manual findings are an ingest source; evidence is encrypted and only ever downloaded

Status: Accepted (2026-10-05), Week 59 (plan §43.2, §52 threat T24). Builds on
[ADR-0040](0040-one-ingest-path.md) and the runtime correlation of
[ADR-0035](0035-dast-scanning.md).

## Context

Pen testers and code reviewers find things no scanner does. The plan (§43.2) asks for a form: title,
a searchable CWE, severity from a CVSS 4.0 calculator "with the vector stored alongside the score",
a location that "can be a route picked from code intelligence" -- so a manual finding on `POST
/orders` "links to that handler's code and taint paths automatically" -- steps, impact,
recommendation, and evidence "encrypted at rest and never rendered inline". Threat T24: an HTML or
SVG evidence file that runs script.

## Decision

**One more ingest source, not a parallel store.** A manual finding becomes a canonical Finding and is
applied through `core.imports.service.apply_import` (source `manual`) into a Test -- "Manual review"
in the project's standing import engagement unless an engagement is named. It is therefore an
ordinary Issue: triage, deduplication, tickets and every later v3 feature apply to it, and the import
that created it can be reverted. `close_missing` is always off. Its rule id is a hash of what it
says and where, so submitting the same finding twice is one Issue (the import is idempotent) and two
different findings on one handler are two. What the Finding has no field for -- the CVSS vector, the
steps as written, the location kind, the automated Issue it matched -- is kept in a
`manual_findings` row (migration 0031, forced RLS) beside the Issue, cascading away with it.

**CVSS 4.0 from one implementation.** The `cvss` library (RedHatProductSecurity, LGPL-3.0, used
unmodified) scores vectors; the calculator screen asks `POST /v2/cvss/v4` for every score instead of
re-implementing FIRST's lookup tables in the browser. Eight vectors were checked against FIRST's own
calculator and are fixed in the tests. A 0.0 ("None") score is Info. A person may set a severity
without CVSS; the vector is then simply absent.

**Routes come from code intelligence.** Every scan now stores its HTTP entrypoints (any framework the
code graph knows, with the verb and the handler's file and line: `scans.entrypoints`); older scans
fall back to the Python-only route map. A picked route puts the finding at its handler. Linking to
automation reuses `core.dast.correlate`, the conservative match that marks a static finding
"confirmed at runtime": same handler, nearby line, related CWE family. When it matches, the manual
finding records the automated Issue and carries its taint path as evidence. No CWE, or no static
finding there, means no link -- never a guess.

**Evidence: sniffed, encrypted, downloaded.** Attachments are stored in the database (so RLS covers
them), at most 10 MB and 20 per finding. Their type is sniffed from the bytes; the claimed type and a
sanitized name are kept for display only; HTML, SVG, XML and PDF are flagged as active content. With
OpenBao configured, each is encrypted with a fresh AES-256-GCM data key wrapped by the org's key, the
row id as associated data; without it they are stored unencrypted and say so -- the same "off means
off" posture as scan artifacts. They are never rendered: the UI only offers a download, through a
five-minute link signed (HMAC) for one attachment and one org, served as `application/octet-stream`
with `Content-Disposition: attachment`, `nosniff`, `default-src 'none'; sandbox` and `no-store`. The
link needs no cookie or bearer token, so `BULWARK_ATTACHMENTS_ORIGIN` can point downloads at a
separate origin that holds neither.

## Consequences

- Recording is `ingest:write`, reading `ingest:read`, like any import.
- Found while building it, and fixed: correlation rebuilds findings without their taint path, so a
  path is attached after it; and the issue page only looked in the latest native scan, so an issue
  only an import or a person reported could not be opened at all -- it now shows the issue's most
  recent occurrence from any source.
- Not done: editing a recorded finding (record a corrected one and revert the old), retests (§43.3,
  Week 64), and per-org link secrets (the HMAC key is `BULWARK_LINK_SECRET`, else derived from the
  deployment's API token).
