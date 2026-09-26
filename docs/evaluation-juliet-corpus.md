# Evaluation: Juliet, a real-repository corpus, and prioritization

Three measurements, produced by the scripts in `benchmarks/` and taken from a single run each on 2026-09-26. Raw
results are committed in `benchmarks/results/`. The OWASP Benchmark result is in
[evaluation-owasp.md](evaluation-owasp.md).

## 1. Juliet Test Suite for Java 1.3 (detection rate per CWE)

Juliet (NIST SARD; 15,848 files staged from 24 security CWE directories) has a `bad`
method with the flaw and matching `good` methods without it. Ground truth is method-level, from the naming
convention (`benchmarks/juliet/regions.py`): a finding counts for the `bad` side if it starts inside a `bad*`
method (or a `_bad.java` file) and for the `good` side if it starts inside a `good*` method. That gives
15,192 real cases and 15,330 safe cases. A real case is detected if the
scanner names the CWE (`exact`), a CWE in the same family (`related`, see `benchmarks/juliet/score.py`), or anything
(`any`).

Only Semgrep analyses Java, so this is Semgrep's result, not an ensemble's. The scan took 937 s
in 11 chunks. A single scan of everything exceeds the tool's 900 s limit; my first attempt timed
out and produced no findings, so the runner now scans in chunks of 1,500 files.

| Matcher | Recall (95% CI) | False-alarm rate | Precision | F1 | TPR − FPR |
|---|---|---:|---:|---:|---:|
| exact | 21.7% (21.0%–22.3%) | 19.5% | 52.4% | 30.6% | +0.022 |
| related | 23.8% (23.1%–24.5%) | 19.6% | 54.6% | 33.1% | +0.042 |
| any | 41.7% (40.9%–42.4%) | 35.9% | 53.5% | 46.8% | +0.057 |

Per CWE (`related` matcher):

| CWE | Real | Safe | Detection rate (recall) | False-alarm rate | Score |
|---|---:|---:|---:|---:|---:|
| CWE-113 | 2088 | 2124 | 0% | 0% | +0.00 |
| CWE-134 | 1044 | 1062 | 0% | 0% | +0.00 |
| CWE-15 | 696 | 696 | 0% | 0% | +0.00 |
| CWE-209 | 34 | 34 | 0% | 0% | +0.00 |
| CWE-23 | 696 | 696 | 9% | 2% | +0.08 |
| CWE-256 | 58 | 59 | 0% | 0% | +0.00 |
| CWE-259 | 174 | 174 | 0% | 0% | +0.00 |
| CWE-315 | 58 | 59 | 0% | 0% | +0.00 |
| CWE-319 | 580 | 590 | 45% | 44% | +0.01 |
| CWE-321 | 58 | 58 | 0% | 0% | +0.00 |
| CWE-327 | 34 | 34 | 100% | 100% | +0.00 |
| CWE-328 | 51 | 51 | 67% | 0% | +0.67 |
| CWE-338 | 34 | 34 | 0% | 0% | +0.00 |
| CWE-36 | 696 | 696 | 9% | 2% | +0.08 |
| CWE-470 | 696 | 696 | 61% | 57% | +0.04 |
| CWE-601 | 522 | 522 | 10% | 10% | +0.00 |
| CWE-614 | 17 | 17 | 100% | 0% | +1.00 |
| CWE-643 | 696 | 708 | 8% | 8% | +0.00 |
| CWE-78 | 696 | 696 | 9% | 2% | +0.08 |
| CWE-80 | 1044 | 1044 | 10% | 0% | +0.10 |
| CWE-81 | 522 | 522 | 0% | 0% | +0.00 |
| CWE-83 | 522 | 522 | 10% | 0% | +0.10 |
| CWE-89 | 3480 | 3540 | 56% | 50% | +0.06 |
| CWE-90 | 696 | 696 | 64% | 59% | +0.05 |

What this shows, and what it does not:

- Detection is low overall (24%) and very uneven. Semgrep's open-source rules do well on
  pattern-shaped weaknesses (CWE-328 weak hash, CWE-614 cookie without Secure, CWE-327) and poorly on the
  taint-style ones that make up most of Juliet. My explanation, not verified rule by rule: most Juliet variants
  route the value through helper methods, fields or other classes, which Semgrep's single-function matching does
  not follow, and some CWEs (113, 134, 259, 321, 338) probably have no matching rule at all.
- Where it does fire on injection-type CWEs (89, 90, 319, 470) it fires about as often on the safe `good` methods
  as on the flawed ones, so a finding there carries almost no signal. The TPR − FPR score of +0.04 says the same.
- The 24 CWEs are the security ones that map to a scanner. The other 89 Juliet directories (arithmetic, null
  pointer, resource handling) were left out as out of scope, so this is not a score over all of Juliet.
- Juliet is synthetic: small self-contained programs written to be analysable. It says little about real
  repositories.

## 2. Real-repository corpus (25 projects)

`benchmarks/corpus/corpus.json` pins 25 public repositories by commit: 12 deliberately vulnerable (VAmPI, NodeGoat,
WebGoat, terragoat, ...) and 13 ordinary (flask, requests, express, gin, gson, ...). Each was scanned with the five
default scanners through the real sandbox, one repository at a time, with nothing else running. The plan asked for
20 to 30; this is 25. Per-repository numbers: `benchmarks/results/corpus-2026-09-26-v2-optimized.json` (the numbers below; see the correction and
performance notes after the table).

| Measure | Result |
|---|---|
| Repositories scanned | 25 of 25 |
| Tool runs (skipped tools not counted) | 94 |
| Crash rate (error or timeout) | 0.0% (0 failures) |
| Raw findings, before correlation | 11,319 |
| Unique findings, after correlation | 10,313 |
| Dedup rate, pooled | 8.9% |
| Dedup rate, median repository | 2.0% |
| Dedup rate, vulnerable apps / ordinary repos | 19.9% / 1.3% |
| Wall time per repository: median / p90 / max | 6 s / 42 s / 75 s |
| Wall time, whole corpus | 338 s |

Reading it:

- **Dedup depends on what you scan.** Vulnerable apps have the same flaw reported by several tools (Semgrep and
  Bandit, Trivy and OSV-Scanner on the same lockfile) so about a fifth of findings merge. Ordinary repositories
  produce mostly single-tool findings and merge about 1%. The pooled 8.9% is between the two and is not a general
  figure. Do not quote it without the split.
- **Crash rate 0% is one run.** It is not a reliability guarantee: zero failures in 94 runs bounds the true
  rate at roughly 3% (rule of three, 95%).
- **Wall time** includes sandbox start-up for each tool and the correlation step; the machine is one laptop running
  Docker Desktop. terragoat is the slowest (75 s), and that is Trivy's IaC scan (measured in Week 25).
- **Correction to the first run (`corpus-2026-09-26-v1.json`, kept for the "before" timings).** dvpwa reported 65
  unique findings there and 224 in the rerun. Semgrep gives up on a rule/file pair after 5 s and still exits
  successfully, so under CPU pressure it silently returned 5 findings instead of 169. Bulwark now reports this
  (`warnings` in the tool status, and on stderr in the CLI). I checked whether my other headline numbers were
  affected by rerunning the OWASP and Juliet scans: predictions were identical and no timeouts were reported.
  Only the first corpus run's dvpwa figure was wrong.
- The wall times above are after the Week 25 optimizations ([evaluation.md](evaluation.md#performance)). The
  first run's were 47 s median and 214 s max; dvpwa and NodeGoat are still slow because of vendored JavaScript.
- No claim of accuracy comes from this table. The corpus has no ground truth; it measures behaviour and cost.
- Small oddities: cfngoat yields 2 findings and terragoat's languages show "-" because IaC is not a language. Checkov,
  which would cover them better, is tier 2 and not in the default five.

## 3. Prioritization quality (risk score vs severity only)

Question: when a user reads only the top K findings, does ordering by Bulwark's risk score put more real
vulnerabilities there than ordering by severity alone? Method (`benchmarks/prioritize.py`): scan the OWASP
Benchmark with Semgrep through the full pipeline, label each finding true (the test is a real vulnerability and the
finding names its weakness) or false, rank three ways, and report top-K precision. Ties are scored by expected value,
not input order. The bootstrap interval resamples findings 500 times with a fixed seed.

2894 findings, 1395 true positives (48.2% base rate); 7 distinct risk scores, 2 distinct severities.

| Top-K | Risk score | Severity only | Random | Risk − severity (95% CI) |
|---:|---:|---:|---:|---:|
| 10 | 69.2% | 52.4% | 48.2% | +16.8% (-10.7% to +40.3%) |
| 20 | 63.3% | 52.4% | 48.2% | +10.9% (-6.4% to +28.3%) |
| 50 | 56.8% | 52.4% | 48.2% | +4.4% (-2.0% to +10.8%) |
| 100 | 54.6% | 52.4% | 48.2% | +2.2% (-0.6% to +5.3%) |

Reading it:

- The risk score is ahead at every K, and the lead is largest at the top, but **every interval includes zero**, so
  this run does not show the risk score beating severity. It is weak evidence in that direction, not a result.
- Both rankings sit close to random (48.2%). With one scanner there are only 2 severities and 7 distinct risk scores
  (rule-level severity and confidence), so the score has almost nothing to separate findings with. That is a property
  of this setup, not a general ceiling.
- **What is not evaluated:** the parts of the score built for dependencies (EPSS, CISA KEV, reachability) have no
  exploitation ground truth in any dataset I have, so their effect on ordering is unmeasured here. Their
  contribution is argued in [risk-score.md](risk-score.md), not measured. Multi-scanner agreement, which raises
  confidence in the score, is also absent because only one scanner analyses Java.
- Only OWASP Benchmark findings were used; Juliet predictions store CWEs, not scores.

## Reproducing

```bash
python -m benchmarks.juliet.run fetch && python -m benchmarks.juliet.run scan --label v1
python -m benchmarks.juliet.run score benchmarks/results/juliet-java-1.3-<date>-v1.predictions.json.gz
python -m benchmarks.corpus.run scan --label v1        # fetches 25 repos at pinned commits
python -m benchmarks.prioritize collect --label v1 && python -m benchmarks.prioritize score <records.json>
```

Juliet is downloaded at run time (77 MB, sha256 pinned in the script) and not redistributed. Run each on an
otherwise idle machine if you want comparable wall times.

