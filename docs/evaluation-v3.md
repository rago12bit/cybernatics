# Evaluation v3 (plan §60)

The plan's v3 evaluation table, filled in as each area is built, and **including what does not
flatter the project**. A row says what was measured, on what, and what it does not show; a row with
nothing measured says "not measured" and why. Phase 14 (Weeks 57-59) is the first to contribute.

| Area | Metric | Result | Status |
|---|---|---|---|
| Ported parsers | Issues produced and field-level agreement with DefectDojo's expected results, on DefectDojo's sample reports | 10 parsers, 156 sample files: **all parse; 135 count and 319 field expectations agree except 12 recorded differences and 2 deliberate refusals**; two samples over 3 MB checked locally | **Measured** -- [docs/v2-week57-verification.md](v2-week57-verification.md); the differences are listed with reasons in `tests/unit/test_ingest_defectdojo.py` |
| Reimport | Share of correct new, unchanged, reopened and closed counts | Random report sequences against an independent oracle (Week 54); real ZAP and Nessus reimports against XML set arithmetic (Week 57) -- all correct | **Measured** -- generated sequences, not a corpus of real histories |
| Deduplication | Precision and recall of merges, per strategy | -- | **Not measured** -- needs hand-labelled duplicate pairs. The study is built and waits for labels: a blind labelling page over the 25-repository corpus, precision per kind of merge and the missed-merge rate among look-alikes ([evaluation-merge-accuracy.md](evaluation-merge-accuracy.md)). What each strategy *changes* on real reports is in `benchmarks/results/dedup-strategies-2026-10-04.json`, which is not accuracy |
| Advisory matching | Agreement with osv-scanner | **21,619 of 21,721** package versions agree on the same OSV data and SBOMs; in all 102 differences Bulwark reports more, each explained | **Measured** -- [evaluation-advisory-matching.md](evaluation-advisory-matching.md); boundary versions, not real SBOMs |
| VEX proposals | Confirmed `vulnerable_code_not_in_execute_path` claims | -- | **Not measured** -- built (Week 69); the blind review of 100 proposals needs a reviewer and real projects; the kit is `scripts/vex-review-kit.py` ([docs/v2-week69-verification.md](v2-week69-verification.md)) |
| Ingest | Findings per second and peak memory on a 100 MB report | 95 MB: Nessus XML **2,400 findings/s end to end, 516 MB peak**; SARIF **3,700/s, 1.5 GB peak** (parse alone: 19,000-30,000/s, ~31 MB) | **Measured** on files tiled from real samples, one laptop, Postgres under RLS -- more uniform than a real scan; [results](https://github.com/rago12bit/cybernatics/blob/main/benchmarks/results/ingest-2026-10-04.json) |
| Parser safety | Crashes found and fixed by fuzzing; attack-file tests passing | 10 parsers fuzzed in a Linux container, **669,000 runs** (batches of 60-90 s), **no crash or hang**; XXE, entity-expansion, DTD, billion-laughs and depth-bomb files refused in-process and in the container; one **real memory exhaustion found and fixed** (the sandbox at ~250,000 findings) | **Measured, briefly** -- minutes per parser, not weeks. The nightly job on CI (9 scanner adapters and 18 report parsers, 2 minutes each) passed its first run on 2026-10-13 |
| Rules engine | Rule evaluation latency at p95 under load | Synthetic event stream at 50, 200, 500 and 1,000 Issue events/s, ten rules, as `bulwark_worker` under RLS: **p95 14, 19, 22 and 21 ms** per `opa eval`; one dispatcher keeps up to about 500 events/s (the rules' own writes are the limit), and at 1,000/s falls behind to ~520/s | **Measured** -- [benchmarks/README.md](https://github.com/rago12bit/cybernatics/blob/main/benchmarks/README.md#the-rules-engine-under-a-synthetic-event-stream-plan-45-60); one Mac, Postgres in Docker, rules more eager than most |
| Dashboards | Widget latency at p95 with one million Occurrences | **Every widget under 300 ms at p95**; slowest metric 99 ms, slowest request 124 ms | **Measured** on a synthetic million Occurrences, Postgres under RLS, one laptop -- [results](https://github.com/rago12bit/cybernatics/blob/main/benchmarks/metrics/one-million-occurrences.json), [v2-week70-71-verification.md](v2-week70-71-verification.md) |
| UX | SUS and time on task for J6-J10 | -- | **Not measured** -- the study needs five security leads or pen testers; the protocol, seed and scorer are ready ([ux-study-v3-protocol.md](ux-study-v3-protocol.md)). J6-J10 run as Playwright tests, which say the flows complete, not how long a person takes |
| SSO | SAML attack cases passing | **13 of 13**: unsigned, another key, tampered, three kinds of signature wrapping, NameID comment injection, another service, unsolicited and crossed, expired, replayed, billion-laughs metadata -- each refused for its own reason | **Measured** against pysaml2's own IdP -- [v2-week75-verification.md](v2-week75-verification.md); not against a commercial IdP: only Keycloak was signed in through (OIDC and SAML, in CI since 2026-10-14); Google, Entra ID and Okta use standard OIDC but were not tested |

## What the Phase 14 numbers do not show

- **Agreement with DefectDojo is agreement with DefectDojo's tests**, not with ground truth. Where
  Bulwark differs on purpose (a finding per place, licence findings not imported, an empty Nuclei file
  closing nothing) the difference is in the test file with its reason.
- The ingest numbers are throughput on a laptop for files built by repeating real records; the whole
  import peaks at 1.5 GB for 117,000 SARIF findings, and nothing was run at the plan's other scale
  (one million Occurrences) here.
- Fuzzing found one real bug (memory, not a crash) in minutes of running; that is evidence the harness
  works, not that the parsers are clean.
