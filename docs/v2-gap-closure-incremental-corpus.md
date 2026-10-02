# Incremental scanning: corpus expansion (closing part of docs/evaluation-v2.md's own gap)

Honest record of additional measurement, done after v2.0.0 shipped, to shrink -- not erase --
another gap `docs/evaluation-v2.md` already disclosed: the incremental-scanning benchmark
(`benchmarks/incremental/run.py`) had only ever been run against one repository (NodeGoat, Week 36).
This runs it against six more of the corpus's deliberately-vulnerable repositories.

## Method

Same script, same methodology it already documents in its own module docstring: clone the repo once
(already cached at its pinned commit), run one full cold-cache scan with
`DEFAULT_TOOLS = (bandit, semgrep, gitleaks, trivy, osv-scanner)`, then touch 3 real source files
(a trailing comment line, simulating a small pull request) and rescan with the same cache directory,
3 repetitions, reporting the median. Ran against pygoat, vulpy, dvna, VAmPI, Vulnerable-Flask-App,
and dvpwa -- the Python/JavaScript corpus repositories already cloned and cached for the taint-engine
corpus expansion ([docs/v2-gap-closure-taint-corpus.md](v2-gap-closure-taint-corpus.md)) done the same
day.

## Results

| Repo | Cold full scan | Median warm (PR) scan | Speedup |
|---|---:|---:|---:|
| NodeGoat (Week 36, unchanged) | 71.2s | 19.6s | 3.6x |
| dvpwa | 46.0s | 3.5s | 13.1x |
| Vulnerable-Flask-App | 27.6s | 23.1s | 1.2x |
| pygoat | 8.9s | 3.1s | 2.8x |
| vulpy | 6.0s | 3.1s | 2.0x |
| VAmPI | 5.4s | 2.2s | 2.5x |
| dvna | 4.0s | 1.9s | 2.1x |

6 of 7 repositories show a real, substantial speedup from the content-addressed cache (2.0x-13.1x);
all beat the plan's own <60s warm-scan target by a wide margin regardless of repository size.

**Vulnerable-Flask-App is the one outlier (1.2x) and is disclosed, not hidden.** Scanning it directly
(outside the benchmark) showed Semgrep alone taking 45.5s on this repository with its own reported
warning, `1 rule/file pairs timed out and were skipped` -- the same class of per-rule timeout already
seen and disclosed on `dvpwa` in the taint-engine corpus work. A timed-out rule/file pair is the most
likely explanation for why this repository's warm scan barely benefited from the cache (if a result
is never produced for a pair because it timed out, there is nothing to cache or reuse on the next
run) -- plausible given the concrete evidence, but not confirmed by instrumenting the cache's own
hit/miss counters for this specific timeout path, which would be needed to state it as settled fact
rather than the likely explanation.

## What this does NOT prove (read before relying on it)

- **Still 7 repositories, not the plan's own "last 20 merged PRs of each repository in the
  30-repository corpus."** This is one synthetic 3-file edit per repository, not real historical pull
  requests, and 7 of 25 corpus repositories, not all of them.
- **The 3 additional "ordinary" (non-teaching-vulnerable) repositories this pass attempted --
  flask, requests, express -- were not completed.** The benchmark run against them was interrupted
  partway through (killed deliberately, mid-scan, due to a real-time memory concern on the host
  machine) rather than left to finish; no result file exists for any of the three, and none of their
  numbers appear above. Re-running them is straightforward (the same command, one repo at a time)
  but wasn't redone this pass.
- **The Vulnerable-Flask-App cache-effectiveness anomaly's root cause is a plausible explanation
  backed by direct evidence (the same repo's own observed Semgrep rule timeout), not a confirmed one**
  -- confirming it would mean instrumenting `core.cache.ResultCache`'s own hit/miss accounting for a
  timed-out tool/file pair specifically, not done here.
- **All 7 repositories are small, deliberately-vulnerable teaching projects**, not the large,
  real-world production codebases the plan's own scale concern is really about -- the unattempted
  `flask`/`requests`/`express` repositories would have been a better test of that, which is exactly
  why they were worth attempting even though this pass didn't finish them.
