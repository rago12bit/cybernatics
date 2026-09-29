# Benchmarks

Reproduce with `benchmarks/run.sh <label>` (needs Docker, the scanner images and network for the
git clones). Each run writes versioned JSON to `benchmarks/results/`.

## Deduplication rate (design doc §10.2, metric 1)

`dedup rate = 1 - unique / raw`, where *raw* is the sum of every scanner's findings and *unique* is
what remains after cross-tool correlation ([ADR-004](../docs/adr/0004-fingerprinting-and-correlation.md)).

Measured 2026-09-25, default branch HEAD of each repo, all five scanners, correlation parameters
`line_window=3`, `snippet_overlap=0.8`, `min_tokens=4`.
Scanner images: bandit=1.7.10, semgrep=1.90.0, gitleaks=v8.21.0, trivy=0.55.2, osv-scanner=2.6.0.
Result file: `results/dedup-2026-09-25-v2-aligned-scope.json`.

| Repository | Languages | Raw findings | Unique findings | Dedup rate | Merged across tools | Wall time |
|---|---|---:|---:|---:|---:|---:|
| VAmPI | python | 23 | 21 | **8.7%** | 2 | 40s |
| NodeGoat | javascript | 771 | 463 | **40.0%** | 291 | 78s |
| nodejs-goof | javascript | 601 | 305 | **49.2%** | 284 | 24s |
| Vulnerable-Flask-App | javascript, python | 212 | 155 | **26.9%** | 48 | 89s |
| terragoat | Terraform / Docker | 945 | 880 | **6.9%** | 65 | 224s |
| **All 5** | | **2552** | **1824** | **28.5%** | | |

Robustness (metric 5): **5 / 5** repositories completed with no scanner failing or timing out.

### How to read this number
- It depends on the **repository mix**. Dependency-heavy projects overlap the most because two SCA
  tools (Trivy, OSV-Scanner) independently report the same advisories (`nodejs-goof`
  49.2%, `NodeGoat` 40.0%). Infrastructure-as-code repositories overlap the
  least because only Trivy scans Terraform (`terragoat` 6.9%). Code scanning
  (Bandit + Semgrep) sits in between (`VAmPI` 8.7%, `Vulnerable-Flask-App`
  26.9%).
- It measures **duplicate reduction, not correctness**. A merged finding can still be a false
  positive. Precision/recall against labelled corpora comes in Phase 6 (OWASP Benchmark, Juliet).
- Five repositories is a **baseline, not the final corpus** (the target is 20-30).

## Incremental scanning (plan §20.1/§36, Week 36)

Median PR scan time against a full scan, with the content-addressed result cache
(`core/cache.py`) warm. Reproduce with `python -m benchmarks.incremental.run --repo NodeGoat`.

Methodology: clone once, run one full scan with an empty cache (cold), then simulate a small pull
request -- edit 3 existing files -- and rescan with the *same* cache directory, three times, taking
the median. This is one repository with a small, fixed edit size, not the plan §34 evaluation
("replay the last 20 merged PRs of each repository in the 30-repository corpus") -- that is a
separate, larger evaluation task for a later phase; this is the narrower thing Week 36 itself asks
to measure. Result file: `results/incremental-2026-09-29-nodegoat.json`.

| Repository | Tools | Cold full scan | Warm PR scan (median of 3, 3 files changed) | Speedup |
|---|---|---:|---:|---:|
| NodeGoat | bandit, semgrep, gitleaks, trivy, osv-scanner | 71.2s | **19.6s** | **3.6x** |

Target (§20.1): under 60 seconds for a typical 50-file pull request. **Met** on this repository
(19.6s), with a 3-file change -- a smaller diff than the target's "typical 50-file" case, but the
warm-scan time is dominated by a cost that doesn't scale with diff size (see below), so a larger
diff on this repository would not be expected to cost much more.

### Why the speedup is 3.6x and not closer to instant
Caching eliminates re-running each *tool* against unchanged files -- confirmed directly: with zero
files touched, `core.cache.ResultCache` reports 100% hits and `cached_outcomes()` itself completes
in under 0.1s, down from the cold run's ~55s of actual Bandit/Semgrep/Gitleaks/Trivy/OSV-Scanner
execution. But the warm run still takes ~17-20s, almost all of it in `core.correlation.correlate()`
-- cross-tool deduplication over NodeGoat's 771 raw findings, measured in isolation at ~16.8s. That
step runs over *every* finding regardless of which files changed or where their results came from,
so it isn't sped up by this week's cache at all, and dominates once tool execution is no longer the
bottleneck. Making correlation itself incremental (skip re-comparing two findings whose files are
both unchanged since the last scan) would be the natural next optimization, but is out of this
week's scope -- noted here rather than left for someone to rediscover by profiling.

### An honest before/after: aligning scanner scope
The first run scored **19.2%** (2088 -> 1686). On `NodeGoat` only 83 of OSV-Scanner's 292 findings
had a Trivy match, which looked like a weak matcher. Investigating showed the matcher was fine: Trivy
**skips dev dependencies by default** while OSV-Scanner includes them, so the tools were not
scanning the same thing (208 of the 209 unmatched findings were on package versions Trivy reported
nothing for). With `--include-dev-deps`, **291 of 292** matched. The change is kept in the Trivy
adapter and pinned by a regression test; the original run is preserved as
`results/dedup-2026-09-25-v1-trivy-default-scope.json` for the record.
