# Evaluation v3 (plan §60) -- in progress

The plan's v3 evaluation table, filled in as each area is built, and **including what does not
flatter the project**. A row says what was measured, on what, and what it does not show; a row with
nothing measured says "not measured" and why. Phase 14 (Weeks 57-59) is the first to contribute.

| Area | Metric | Result | Status |
|---|---|---|---|
| Ported parsers | Issues produced and field-level agreement with DefectDojo's expected results, on DefectDojo's sample reports | 10 parsers, 156 sample files: **all parse; 135 count and 319 field expectations agree except 12 recorded differences and 2 deliberate refusals**; two samples over 3 MB checked locally | **Measured** -- [docs/v2-week57-verification.md](v2-week57-verification.md); the differences are listed with reasons in `tests/unit/test_ingest_defectdojo.py` |
| Reimport | Share of correct new, unchanged, reopened and closed counts | Random report sequences against an independent oracle (Week 54); real ZAP and Nessus reimports against XML set arithmetic (Week 57) -- all correct | **Measured** -- generated sequences, not a corpus of real histories |
| Deduplication | Precision and recall of merges, per strategy | -- | **Not measured** -- needs hand-labelled duplicate pairs from three tools across ten repositories; what each strategy *changes* on real reports is in `benchmarks/results/dedup-strategies-2026-10-04.json`, which is not accuracy |
| Advisory matching | Agreement with osv-scanner | -- | Not yet built (Week 68) |
| VEX proposals | Confirmed `vulnerable_code_not_in_execute_path` claims | -- | Not yet built (Week 69) |
| Ingest | Findings per second and peak memory on a 100 MB report | 95 MB: Nessus XML **2,400 findings/s end to end, 516 MB peak**; SARIF **3,700/s, 1.5 GB peak** (parse alone: 19,000-30,000/s, ~31 MB) | **Measured** on files tiled from real samples, one laptop, Postgres under RLS -- more uniform than a real scan; [results](../benchmarks/results/ingest-2026-10-04.json) |
| Parser safety | Crashes found and fixed by fuzzing; attack-file tests passing | 10 parsers fuzzed in a Linux container, **669,000 runs** (batches of 60-90 s), **no crash or hang**; XXE, entity-expansion, DTD, billion-laughs and depth-bomb files refused in-process and in the container; one **real memory exhaustion found and fixed** (the sandbox at ~250,000 findings) | **Measured, briefly** -- the nightly job (14 parsers) has not run on CI |
| Rules engine | Rule evaluation latency at p95 under load | -- | Not yet built (Week 65) |
| Dashboards | Widget latency at p95 with one million Occurrences | -- | Not yet built (Week 70) |
| UX | SUS and time on task for J6-J10 | -- | Not yet run (Week 74) |
| SSO | SAML attack cases passing | -- | Not yet built (Week 75) |

## What the Phase 14 numbers do not show

- **Agreement with DefectDojo is agreement with DefectDojo's tests**, not with ground truth. Where
  Bulwark differs on purpose (a finding per place, licence findings not imported, an empty Nuclei file
  closing nothing) the difference is in the test file with its reason.
- The ingest numbers are throughput on a laptop for files built by repeating real records; the whole
  import peaks at 1.5 GB for 117,000 SARIF findings, and nothing was run at the plan's other scale
  (one million Occurrences) here.
- Fuzzing found one real bug (memory, not a crash) in minutes of running; that is evidence the harness
  works, not that the parsers are clean.
