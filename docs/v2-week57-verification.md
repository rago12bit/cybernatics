# Weeks 57-59 verification -- Ported parsers and deduplication (plan Phase 14, §42.2-§42.3)

Honest record of what was built, run and measured. Weeks 57 (ported parsers, batch 1), 58 (batch 2
and per-source deduplication) and the dedup half of 59's neighbourhood were done as one body of work in
seven tasks (the universal mapper and manual findings -- Week 59 -- are separate, later tasks).
Decisions: [ADR-0041](adr/0041-dast-and-network-identity.md) (what identifies a DAST or network
finding) and [ADR-0042](adr/0042-dedup-strategies-per-source.md) (deduplication per source).

## What was built

| # | Task | Result |
|---|---|---|
| 1 | ZAP, Nuclei; DefectDojo fixtures; DAST identity | two parsers, a vendoring script that reads DefectDojo's expected results out of its tests, ADR-0041 |
| 2 | Burp, Nessus, OpenVAS | three parsers; the first parser to admit a DTD (Burp's own), and only that |
| 3 | Sandbox hardening and throughput | the parser container streams its result; an ingest throughput benchmark; fuzz runs |
| 4 | Grype, Trivy, Snyk | parsers that read a report with the function a native scan uses (Grype, Trivy) or a two-pass reader (Snyk) |
| 5 | GitLab security reports, Checkov | one parser for GitLab's five report types; Checkov |
| 6 | Dedup engine | five strategies, versioned per-source settings (migration 0029), applied to imports and scans |
| 7 | Dedup dry run, API and screen | preview/apply with merges and splits, `wait_for_dedup`, the Matching screen |

## Bugs found and fixed along the way

1. **DAST findings were merged, collapsed and made quadratic** (the serious one; it predates this work
   and affected the native DAST campaigns). Found by importing a real ZAP report, and it was three
   separate mechanisms: correlation saw every DAST finding "at the same place" (no file, no line) and
   merged any two alerts sharing a CWE; the fingerprint ignored the route; and the location-independent
   fallback key matched every URL an alert fired on to the first Issue made for it -- 130 findings of
   one report became 15 Issues. All three fixed (ADR-0041); the regression tests fail without each fix,
   the quadratic one in 34 s. One consequence: existing DAST Issues are re-created once.
2. **The parser sandbox ran out of memory at ~250,000 findings and said "try again."** Found pushing
   95 MB reports through the real container. The worker built three copies of the findings; it now
   writes them as it parses (300,000 findings in 18 s), partial findings of an unreadable file are never
   built, and a timed-out or killed container says so instead of "try again".
3. **Burp's own DOCTYPE would have made every real Burp file unreadable** under the rule that refuses all
   DTDs. `iter_xml(allow_dtd=True)` admits an internal element declaration and nothing else; an entity or
   an external DTD is still an error (tested, including inside the container).
4. A stdlib HTML parser used to strip markup from ZAP descriptions took 2.3 s on 20,000 characters of
   hostile markup (quadratic); replaced by RE2.
5. `-1` (ZAP's "no CWE") was read as CWE-1 by a too-loose pattern.
6. A Nessus CSV in DefectDojo's own samples has `75` where 7.5 was meant; as a CVSS score that turned a
   High into a Critical. Impossible scores are now ignored, with a warning.
7. Trivy showed NVD's CVSS beside a severity another source (GitHub) had decided; it now shows the score
   of the source that decided (found by comparing with DefectDojo's expected results).
8. **Test-suite finds** (not product bugs, but they would have lied): three "no prefix reads complete"
   property tests had a wrong boundary condition and failed intermittently under Hypothesis; found by
   running them repeatedly, and fixed by saying precisely what a cut at a row boundary is.
9. Three of my own mutation checks silently mutated nothing (a pattern that matched a docstring, a
   `git checkout` on an untracked file, a `str.replace` that did not match after reformatting) and
   "survived"; each was redone until it really changed the code and was killed.

## Validated against real, live things -- not mocks

- **DefectDojo's own sample reports and the results its tests expect.** `scripts/sync-dd-fixtures.py`
  reads the expected values (counts, titles, severities, rule ids, CWEs, CVSS, locations, components) out
  of DefectDojo's unit tests with `ast` and vendors the samples from a pinned commit. **156 sample files,
  135 count expectations and 319 field expectations** across the ten ported parsers all agree, except
  **12 differences and 2 deliberate refusals, each recorded in `tests/unit/test_ingest_defectdojo.py` with
  its reason** (examples: DefectDojo titles a Tenable.io finding with the asset's name; folds every
  licence into a finding; folds same-text SAST findings on different lines; keeps `GET` and `DELETE` of
  one URL apart). Two Grype samples over 3 MB are not vendored; they were checked locally against the
  pinned hashes (1,509 and 1,567 findings, both matching).
- **Same function as a native scan.** An uploaded Grype, Trivy or Checkov report yields exactly the
  findings the native adapter yields from the same bytes (golden outputs of the project's own images);
  the ZAP and Nuclei readings are shared with the native DAST adapters.
- **Independent oracles, not our own parser:** a ZAP reimport's new/unchanged/closed counts equal the
  set arithmetic of the XML (stdlib ElementTree); a Nessus reimport after removing one plugin from one
  host closes exactly that one; after a real dedup change on real Postgres, reimporting the second ZAP
  scan gave 4 new / 14 unchanged / 1 closed, equal to a title-set oracle computed from the XML.
- **Real Postgres under Row-Level Security** as the non-superuser worker role: 61 integration tests
  pass, including a dedup merge and its inverse split (foreign keys, the (project, category, fingerprint)
  uniqueness) and another org being unable to read, preview or apply anything to a project it does not own.
- **The real sandbox container:** every ported parser, smallest and largest vendored sample, gives the
  same findings in the container as in-process; a Burp entity and a ZAP external entity are refused
  inside it; a dense 300,000-row CSV parses; 525,000 rows is refused for the findings limit with that
  reason.
- **Fuzzing, for real, briefly.** Atheris in a Linux container, 10 parsers: batch 1 (zap, nuclei, burp,
  nessus, openvas) **246,598 runs**, batch 2 (grype, trivy, snyk, gitlab, checkov) **422,471 runs in 60 s
  each**; no crash or hang. (Batch 1's wall clock ran long because the machine slept mid-run; the run
  counts are what libFuzzer reported.)
- **A real browser against the real stack** (local API and Next dev server on the throwaway Postgres):
  the Matching screen listed the sources, a preview of hashing ZAP by title said "would merge 75 issues
  into 9 and split none" (81 Issues -> 15), applying it moved all 130 occurrences, recorded version 1
  with its effect, an outbox event and an audit entry, and a reimport afterwards matched by the new key.
- **Throughput** (`benchmarks/ingest_throughput.py`, results in `benchmarks/results/ingest-2026-10-04.json`,
  files tiled from real samples to ~95 MB, Postgres under RLS, Apple silicon laptop):

  | Report | Records | Parse only (peak) | Parse + prepare (peak) | Whole import to Postgres (peak) |
  |---|---:|---|---|---|
  | Nessus XML, 95 MB | 27,342 | 1.4 s, 19,000/s (31 MB) | 2.3 s (236 MB) | 11.4 s, 2,400/s (516 MB) |
  | SARIF, 95 MB | 117,504 | 3.9 s, 30,000/s (31 MB) | 7.7 s (745 MB) | 32.0 s, 3,700/s (1.5 GB) |

- **Mutation checks.** Each of these makes tests fail: removing the DAST correlation guard, the host or
  route from the fingerprint, the DAST fallback exclusion; Burp's DTD allowance; the Nessus score bands;
  the OpenVAS "not Done" rule; CSV strictness and the ragged-row check; the Checkov counters-only rule;
  the GitLab location classifier; the dedup digest check, triage reset, ticket repointing, fallback
  clearing and oldest-survivor rule; and, in the screen, preview clearing on edit, the apply guards, the
  digest, and the field requirement.
- Backend: `ruff`, `black`, `mypy` (251 source files) clean; 2,322 unit tests collected, all pass (the
  one pre-commit CLI test needs `.venv/bin` on `PATH`). Web: 247 tests, `tsc` clean, `npm run build` clean.

## What this does NOT prove (read before relying on it)

- **Deduplication quality is not measured.** The plan's evaluation is precision and recall against
  hand-labelled duplicate pairs from three tools across ten repositories. That corpus does not exist.
  `benchmarks/dedup_strategies.py` measures only what each strategy *changes* on real reports (for
  example `tool_id` merges GitLab's 467 SAST findings into 109 Issues; on the DAST tools it changes
  nothing, by design) -- not whether the change is right.
- **Real ZAP and Nuclei output was not produced here.** Their samples are DefectDojo's; ZAP's JSON
  report has no real sample (the JSON test is built from a real XML one), and the images to run them
  were not pulled. Everything else was checked against real files, but ZAP versions after 2.16 and
  Nuclei's newest JSON are untested.
- **Closing is not scoped to the hosts a report covers**: a Nessus or OpenVAS report covering fewer hosts
  than the last one lists the missing hosts' Issues as closed. The preview shows the count, and the docs
  say so; making it host-aware is not done (ADR-0041).
- **The fuzzing is minutes, not weeks**, and the nightly job (now 14 parsers) has not run on CI.
- **Throughput numbers are for tiled real files**, more uniform than a real 100 MB scan, on one laptop;
  the whole import at 117,000 findings peaks at 1.5 GB in the importing process, and the dry run has not
  been measured on a very large project.
- **Request and response bodies in ZAP and Burp reports are not stored** (one line each is kept); the
  HTTP method is not part of a DAST finding's identity, so `GET` and `POST` of one URL with one check are
  one Issue.
- **CI results for these commits have not been observed** (no `gh` here), and nothing is pushed or tagged.
- The fix agent's verification record on a real pull request and the five LLM-gated evaluation rows are
  still open (they need a live model).
