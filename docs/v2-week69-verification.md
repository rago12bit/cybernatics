# Week 69 verification: VEX, compliance and evidence packs (plan §46.3, §47, §55.5)

A factual record of what was built, run and measured, and of milestone M15. The decision is
[ADR-0053](adr/0053-vex-compliance-evidence.md); the user guides are [vex.md](vex.md) and
[compliance.md](compliance.md).

## What was built

- **Go reachability** (`core/reachability/golang.py`): imports, the names used from each imported
  package and every selected method name, from the Go source a scan checks out; `go.mod`'s direct and
  indirect requirements; Go components now get "imported by application code" like Python and
  JavaScript. Kept per project (`code_usage`) after every full scan. The advisory engine now stores
  the vulnerable functions Go records name (the Go feed is re-read once to pick them up).
- **VEX** (`core/vex`): evidence per use (Go: vulnerable functions not used; Python, JavaScript: the
  package not imported), "Draft VEX for the others" on the impact view, proposals confirmed or
  rejected by a person with a personal token, confirmation dismissing the matching Issue with the
  justification, reopening withdrawing it, OpenVEX v0.2.0 and CycloneDX 1.6 exports, a project VEX
  page. Dependency Issues can be dismissed with an OpenVEX justification.
- **Compliance** (`core/compliance`): five framework files citing source, version and terms; an ASVS
  4.0.3 checklist per project where only a person marks a requirement met.
- **Evidence packs** (`core/evidence`): preview, a signed zip (PDF, JSON, the audit extract,
  checkpoint bundles, `verify.py`, manifest), an Evidence page.
- **The audit log** gets version-2 entries that carry their organization inside the hash, so an
  organization's extract can show other organizations' entries as hashes only.
- **Rekor**: `bulwark audit checkpoint --rekor-url` for a private Rekor; `bulwark audit verify
  --pub [--trusted-root]` checks every checkpoint's signature and log entry.
- **Migration 0041**; API `/v2/advisories/{key}/vex-drafts`, `/v2/vex/{id}/confirm|reject|withdraw`,
  `/v2/projects/{id}/vex[/openvex|/cyclonedx]`, `/v2/compliance/frameworks`,
  `/v2/projects/{id}/asvs`, `/v2/evidence-packs[/preview|/{id}/bundle]`.

## Found and fixed along the way

1. **Week 68: every adopted vulnerability in a project matched one Issue.** Advisory findings skipped
   the import path's `prepare` step, so all had an empty fingerprint. Found when confirming a VEX
   statement could not find its Issue. Week 68's test that an advisory Issue is osv-scanner's Issue
   passed for the same wrong reason (its osv-scanner findings were not prepared either); it now runs
   them through `prepare` as a scan does, and a new test fails without the fix.
2. **Week 30: the Rekor log index was never recorded with cosign 3.** Bundles are protobuf JSON:
   the index is a string, and an index of 0 is left out. Found against the local Rekor; now read as
   written, tested with the two real bundles.
3. **`bulwark audit verify` did not check checkpoints at all** beyond counting them; it now checks
   that each names the hash at its position, and with `--pub` verifies each against Rekor.
4. **Go module names from Syft**: reachability is assessed on the module path from the purl.
5. **In the browser**: "Checked 1 Go files"; "Draft VEX for the other 3 uses" when it was all of
   them, and a line under the disabled button saying no use had evidence after all three were
   drafted; the Issue column said "Open" for Issues the VEX confirmation had dismissed; the ASVS
   filters stretched full width; "1 issues open"; row headers in the global upper-case style.
6. **Evidence pack**: Bulwark's own Advisories re-imports counted as scans in coverage; two PDF
   column headers broke mid-word.
7. **By the benchmark**: open Issues per CWE were read twice per project and each read the whole
   stored finding; now once per project and only the CWE field (preview 4.2 s to 2.3 s at 100,000
   Issues, results identical).

## Checked against real systems

- **Local Rekor** (Rekor 1.4.3 with Trillian 1.7.2 and MySQL, in Docker on 127.0.0.1 only; nothing
  published to Sigstore's public instance): `bulwark audit checkpoint --rekor-url` uploaded the chain
  head (log indexes 2 and 3 recorded); `bulwark audit verify --pub --trusted-root` verified the
  signature and the log entry offline. A bundle with its log entry removed, or with a forged
  timestamp, fails; so does a checkpoint text with a different hash.
- **Evidence pack, end to end**: generated in the browser with signing on; fetched with curl;
  `verify.py` under the system Python (outside the repository): manifest OK, 14 audit hashes
  recomputed, anchored at entry 13; cosign verified the manifest signature and the checkpoint against
  the local Rekor's trusted root, with no network; an edited manifest and a wrong checkpoint hash
  both fail; `verify.py` reports an edited `evidence.json`.
- **VEX documents**: OpenVEX against the OpenVEX v0.2.0 JSON schema and CycloneDX against the 1.6
  schema (with format checking): no errors; deliberately broken copies are rejected. `vexctl` 0.4.4
  (OpenVEX's own tool, checksum-verified) merged the document and filtered a SARIF file with it:
  the `not_affected` CVE was removed, the `affected` one kept.
- **Real OSV data** (Maven, PyPI, Go, 6 October) and KEV, and five small services written for the
  check, analysed by Bulwark's own reachability: the three Go services import `golang.org/x/net`;
  the crawler calls `html.Parse`, the gateway only tokenizes, the notifier only escapes. For
  CVE-2021-33194 the crawler is "affected, calls html.Parse (cmd/crawl/main.go)"; the others are
  proposable. For CVE-2023-44487 nothing is proposed -- correctly: GitHub's record names no
  functions, and Go's database files the same flaw as CVE-2023-39325 with its functions, for which
  all three are proposed.
- **Postgres 16, migration 0041** up, down to 0040 and up; RLS enabled and forced on `code_usage`,
  `vex_statements`, `compliance_statuses` and `evidence_packs`.
- **RLS**: `tests/integration/test_vex_compliance_rls_docker.py` passes as `bulwark_worker`; with RLS
  off on any one of the four tables it fails; all 60 RLS tests pass.

## Milestone M15: the new-CVE morning (journey J7)

Driven in the browser by me (an automated agent), on the seeded data above, timed from sign-in:

| Run | Steps | Time |
|---|---|---|
| 1 | sign in; the morning list; CVE-2023-44487 (known exploited, 3 projects); Issues in one click; the same flaw's Go record CVE-2023-39325; Draft VEX; confirm 3 proposals; the project's VEX page | **1 min 57 s** |
| 2 (re-seeded) | sign in; CVE-2023-39325; Issues in one click; Draft VEX; confirm 3 (each Issue dismissed with the justification) | **1 min 2 s** |

Under the five minutes M15 asks, but by an agent that does not read: a person reading the evidence
before confirming takes longer, and the time on task with people is Week 74's usability study.
The rest of M15: component search answers "where do we use this?" in under 30 ms at the 95th
percentile (Week 67); advisory impact shows reachability per project, now function-level for Go;
VEX exports carry the evidence; rules and ticket sync handle the routine (Weeks 65-66).

## Scale

`scripts/bench-evidence.py` on Postgres 16 as `bulwark_worker` under forced RLS: 50 projects, 2,000
Issues each (100,000), every Issue with an occurrence and a CWE, SLA policies, 20,000 audit entries,
all five frameworks, a 90-day period.

| | Time |
|---|---|
| Preview (everything but the PDF and zip) | 2.3 s |
| The whole pack (PDF, zip, 9.1 MB with 43,000 audit entries) | 3.0 s |
| ASVS level 2 for one project (2,000 Issues) | < 0.1 s |

Built in the request; a deployment with millions of Issues needs packs built on the worker.

## Tests

- Backend: `test_vex.py` (5: Go source, drafting and deciding, confirm/reopen and the exports, a
  dependency Issue dismissed in VEX vocabulary, a full scan recording Go usage), `test_compliance.py`
  (5: the audit extract, the mappings, the ASVS checklist, the evidence pack run through its own
  `verify.py`, signing), `test_advisories.py` (+1: two vulnerabilities, two Issues),
  `test_audit_rekor.py` (+1: real bundles).
- Web: `vex-compliance.test.tsx` (5, with axe).
- Integration: `test_vex_compliance_rls_docker.py`.

## Not done, or not proven

- **The blind review of 100 VEX proposals** (plan §60) has not been done: it needs a person who has
  not seen Bulwark's answers, and real projects (none were cloned). `scripts/vex-review-kit.py` makes
  the sheet and scores it; it was run once on the seeded data to check that it works, which measures
  nothing.
- VEX evidence does not follow calls into other dependencies, and is import-level outside Go.
- Only PyPI, npm, Go and Maven vulnerabilities appear in VEX (the advisory engine's ecosystems).
- Rekor: a local instance only, by choice; nothing was published to the public log.
- Audit entries from before migration 0041 can only be checked by link in an extract.
- Evidence packs are built synchronously.
