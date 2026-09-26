# Evaluation

What was measured, how, and what it does and does not show. Every figure is produced by a script in `benchmarks/`
from a result file committed in `benchmarks/results/`, from one run on one machine (a laptop running Docker
Desktop with 10 CPUs) in September 2026. Run-to-run variation was not measured; the OWASP and Juliet scans were
repeated once after the Week 25 changes and gave identical predictions.

| Question | Benchmark | Detail |
|---|---|---|
| Does it find real vulnerabilities, and how often does it cry wolf? | OWASP Benchmark 1.2beta | [evaluation-owasp.md](evaluation-owasp.md) |
| Per weakness type? | Juliet 1.3 (Java) | [evaluation-juliet-corpus.md](evaluation-juliet-corpus.md#1-juliet-test-suite-for-java-13-detection-rate-per-cwe) |
| Does it run reliably on real code, and how much does correlation merge? | 25-repository corpus | [evaluation-juliet-corpus.md](evaluation-juliet-corpus.md#2-real-repository-corpus-25-projects) |
| Does the risk score order findings better than severity? | OWASP Benchmark, top-K | [evaluation-juliet-corpus.md](evaluation-juliet-corpus.md#3-prioritization-quality-risk-score-vs-severity-only) |
| How fast is a scan? | corpus wall time | [below](#performance) |

## Results

| Measure | Result |
|---|---|
| OWASP: recall / false-positive rate / F1 (`related` matcher, Semgrep) | 88.2% (CI 86.4–89.8) / 43.7% / 77.0% |
| OWASP: Benchmark score (TPR − FPR) | +0.445 (exact matcher +0.374, any +0.226) |
| Juliet: recall / false-alarm rate / score | 23.8% / 19.6% / +0.042 |
| Corpus: tool-run failures | 0 of 94 |
| Corpus: dedup, vulnerable apps / ordinary repos / pooled | 19.9% / 1.3% / 8.9% |
| Corpus: wall time per repository, median / p90 / max | 6 s / 42 s / 75 s |
| Top-20 precision: risk score / severity only / random | 63.3% / 52.4% / 48.2% (difference not significant) |

## How to read them

- **Only Semgrep analyses Java.** The OWASP and Juliet numbers are Semgrep's, not an ensemble's, so they say
  nothing about whether combining scanners helps. That question needs a language with several analysers, which
  neither suite provides.
- **Detection is strong where the flaw is a pattern and weak where it needs data flow.** OWASP recall is 88%, but
  the false-positive rate on injection categories is 65–88%. On Juliet the detection rate is 24% and where
  injection CWEs are detected the safe variants are flagged about as often.
- **Dedup depends on the target.** Roughly a fifth of findings merge on deliberately vulnerable apps, about 1% on
  ordinary repositories. Do not quote the pooled figure alone.
- **Zero crashes in 94 runs bounds the true crash rate at about 3%** (rule of three, 95%). It is not a
  reliability guarantee.
- **Prioritization is not shown to help.** The risk score is ahead of severity-only at every K, but every
  confidence interval includes zero, and with one scanner there are only 7 distinct scores. The parts of the score
  built for dependencies (EPSS, KEV, reachability) cannot be evaluated: no dataset has exploitation ground truth
  for them.
- **Not measured at all:** AI fix quality, the VS Code extension and GitHub Action in their real hosts, secret
  detection recall (Gitleaks has no benchmark here), SCA accuracy against ground truth.
- **Synthetic vs real.** OWASP and Juliet are synthetic. The corpus is real code but has no ground truth, so it
  measures behaviour and cost, not accuracy.

## Performance

Week 25 profiled the corpus scan. Tools already run in parallel, so a scan takes as long as its slowest tool, and
that was Semgrep in 21 of 25 repositories (median 52 s), Trivy in 3 (IaC repositories).

| Finding | Change | Measured effect |
|---|---|---|
| Semgrep spent ~26 s of every scan loading 337 small rule files (config time 25.9 s of 26.2 s on an empty repo) | Rules are merged into one file per language at image build time, ids preserved (`docker/semgrep/merge-rules.py`) | config time 26 s → 1 s. Rule ids and findings identical on 6 repositories, then across the whole corpus (except dvpwa, below) |
| Semgrep was limited to 1 CPU | `cpus=4` and `--jobs=4` for Semgrep | 20–40% faster on larger repos; no effect on rule loading |
| Trivy IaC scan of terragoat took 133 s at 1 CPU | `cpus=4` for Trivy | 68 s |
| Semgrep silently skips a rule/file after 5 s and exits 0 | Bulwark now reports `warnings` on the tool status and on stderr | dvpwa returned 5 findings under load instead of 169 |

Result on the corpus (`corpus-2026-09-26-v1.json` before, `...-v2-optimized.json` after):

| | Before | After |
|---|---|---|
| Median wall time per repository | 46.9 s | 6.2 s |
| 90th percentile | 74.2 s | 41.5 s |
| Slowest | 214 s (terragoat) | 75 s (terragoat) |
| Whole corpus | 1,235 s | 338 s |
| OWASP Benchmark Semgrep scan | 202 s | 30 s |
| Juliet Semgrep scan (11 chunks) | 937 s | 313 s |

Unique findings were identical for 24 of 25 repositories. dvpwa went from 65 to 224 because the first run lost
Semgrep findings to timeouts under CPU pressure (see above); the optimized run and repeated direct runs agree on
169 Semgrep findings. The OWASP and Juliet reruns gave identical predictions, so those headline results were not
affected.

What was not fixed:

- **Trivy misconfiguration scanning is slow when more than one IaC scanner is enabled.** On terragoat, Terraform
  alone takes 1.6 s and any second scanner (Dockerfile, Kubernetes, CloudFormation) brings it to about 130 s, though
  each alone is fast. This looks like Trivy 0.55.2 behaviour. The obvious workaround (one invocation per scanner)
  needs a wrapper the sandbox runner does not have, so it is left as is; 4 CPUs halve it.
- **Vendored JavaScript.** dvpwa and NodeGoat spend ~40 s matching rules against bundled libraries such as
  `materialize.js`. Skipping vendored files would be faster and would also hide findings, so it is not done by
  default.
- **Capacity trade-off.** Semgrep and Trivy now take up to 4 CPUs each per scan. On a busy worker that raises the
  CPU a single scan can consume; the sandbox still caps it. The values are in the adapters' `ToolSpec`.
- Wall times here are from an otherwise idle laptop. A shared or smaller host will be slower, and Semgrep's
  timeout behaviour above is the main way that shows up as missing findings, now flagged.

## Reproducing

See [evaluation-juliet-corpus.md](evaluation-juliet-corpus.md#reproducing) and
[evaluation-owasp.md](evaluation-owasp.md). Public suites are downloaded at run time and not redistributed. Run
each on an otherwise idle machine to compare wall times.
