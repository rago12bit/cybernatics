# Evaluation: OWASP Benchmark v1.2beta

How well do Bulwark's scanners find real vulnerabilities in a labelled corpus, and how often do they cry wolf?
This is the first measurement of *correctness* (the deduplication benchmark measures only duplicate reduction).

**Headline (Semgrep, the only scanner here that analyses Java):** it finds **88%** of the real vulnerabilities and
also flags **44%** of the safe look-alikes, so precision is 68%, F1 77%, and the Benchmark's own score
(recall minus false-positive rate) is **+0.445** on a scale where 0 is a coin flip. It is excellent on
pattern-shaped weaknesses and weak on data-flow ones (below).

## Method

- **Corpus:** [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) tag `1.2beta`, commit
  `2734ae4`: **2,740** small Java servlets in 11 weakness categories. **1,415** are really vulnerable, **1,325** are
  "fake": they look vulnerable but are not (input replaced by a constant, sanitised, or never reaching the sink). The
  answer for each is in the corpus's own CSV (its SHA-256 is recorded in the result file). GPL-2.0; downloaded at run
  time by `python -m benchmarks.owasp.run fetch` (about 150 MB), never committed here.
- **What was scanned:** only the 2,740 `.java` test files and `pom.xml` (the repository also ships other tools'
  reference results, which must not be seen by the scanners).
- **How each tool was run:** through Bulwark's own runner, in its sandbox, one tool at a time (so findings are not
  merged across tools), with each finding's CWE enriched by Bulwark's taxonomy. Findings outside the test files are
  counted but not scored.
- **Scoring per test case:** *predicted positive* means the tool reported that weakness in that file. TP, FP, TN, FN
  follow. **Recall** = TP / real; **false-positive rate** = FP / fake; **precision** = TP / flagged; **F1**; and the
  Benchmark's score **TPR − FPR**. 95% Wilson intervals are in the result file. Precision and F1 are shown as n/a
  when a tool flagged nothing, never as 0.
- **What counts as "reported that weakness" is a judgment call**, so three matchers are scored and published
  together (`benchmarks/owasp/score.py`):
  - `exact`: a finding with the case's own CWE id.
  - `related`: exact, plus CWE ids that describe the same weakness for that category. Deliberately narrow:
    crypto {327, 326, 780}, hash {328, 327, 916}, weak randomness {330, 338, 331, 335}. A cookie missing HttpOnly
    (CWE-1004) earns no credit for a missing Secure flag (CWE-614). **`related` is the headline.**
  - `any`: any finding in the file. An upper bound with no credit for being right; it shows how much the matcher
    matters.

## Results (Semgrep, community Java rules pinned at build, semgrep 1.90.0)

Wall time 200 s for all 2,740 files. Result files: `benchmarks/results/owasp-1.2beta-2026-09-26-v1.*.json`.

| Matcher | Recall (95% CI) | False-positive rate | Precision | F1 | Score (TPR − FPR) | TP / FP / TN / FN |
|---|---:|---:|---:|---:|---:|---|
| exact | 79.0% (76.8–81.1) | 41.7% | 66.9% | 72.5% | +0.374 | 1118 / 552 / 773 / 297 |
| **related** | **88.2%** (86.4–89.8) | **43.7%** | **68.3%** | **77.0%** | **+0.445** | 1248 / 579 / 746 / 167 |
| any | 90.0% (88.3–91.4) | 67.4% | 58.8% | 71.1% | +0.226 | 1273 / 893 / 432 / 142 |

### By category (`related`)

| Category | Real | Fake | Recall | False-positive rate | Score |
|---|---:|---:|---:|---:|---:|
| weakrand (insecure randomness) | 218 | 275 | 100% | 0% | +1.00 |
| securecookie (no Secure flag) | 36 | 31 | 100% | 0% | +1.00 |
| crypto (weak cipher) | 130 | 116 | 100% | 23% | +0.77 |
| hash (weak hash) | 129 | 107 | 69% | 0% | +0.69 |
| xss | 246 | 209 | 82% | 52% | +0.30 |
| xpathi | 15 | 20 | 93% | 65% | +0.28 |
| sqli | 272 | 232 | 93% | 73% | +0.20 |
| pathtraver | 133 | 135 | 90% | 79% | +0.12 |
| ldapi | 27 | 32 | 96% | 88% | +0.09 |
| trustbound | 83 | 43 | 52% | 42% | +0.10 |
| cmdi (command injection) | 126 | 125 | 93% | 87% | +0.06 |

## What the numbers say

- **Two very different regimes.** Categories decided by *what is called* (a weak random generator, an unsafe hash, a
  cookie without Secure) are solved: near-perfect recall and almost no false positives. Categories decided by *where
  the data came from* (SQL, command, LDAP, XPath injection and path traversal) have 65–88% false-positive rates: the
  score sits just above a coin flip (+0.06 to +0.28).
- **A likely cause, checked on one example, not proven.** The rules match the dangerous call (string concatenated
  into a query) but Semgrep's community rules do little data-flow tracking. In a sampled false positive
  (`BenchmarkTest00104`) the "tainted" value is replaced by a constant behind an always-true condition, and Semgrep
  flags the query anyway. 170 safe sqli cases were flagged. Other causes were not ruled out.
- **The matcher matters.** Crediting any finding in a file (`any`) drops the score from +0.445 to +0.226 because it
  also counts 314 more false alarms: reporting *something* is not the same as reporting the right thing.

## What this does not tell you

- **Only one scanner analyses Java here.** Bandit, gosec and the others do not apply; Gitleaks found nothing in the
  corpus (0% recall, scored as such); Trivy and OSV-Scanner cover dependencies, not these servlets. So there is **no
  ensemble result**: with one analysing tool an ensemble equals it, and the harness says so instead of printing a
  duplicate row. Showing what multiple tools add needs a corpus several of them cover (Week 24's Juliet suite, or
  the Python and JavaScript repositories).
- **It is a synthetic corpus.** The Benchmark is small, uniform servlets written to be scored; real code differs, and
  tools can be tuned to it. Treat the numbers as a comparison instrument, not a promise about your code.
- **No comparison with other tools was made.** No published scorecard was reproduced or cited.
- **One run, one rule-pack version, one tag.** The Benchmark is known to have quirks; `1.2beta` is the tag the design
  targets, not the final 1.2 release.
- **`related` is my mapping**, chosen before seeing scores and kept narrow, but it is a choice: see `exact` if you
  disagree.

## Found while doing it

- **Maven projects never triggered the dependency scanners**: `pom.xml` was not in the list of files that mark a
  repository as having dependencies, so Trivy and OSV-Scanner were skipped on it. Fixed (with a test). Scanning the
  corpus's `pom.xml` for dependencies was not part of the scoring.
- The dedup benchmark script had started running every registered scanner after tier 2 landed; it is pinned back to
  the original five so its published numbers stay reproducible.

## Reproduce

```bash
python -m benchmarks.owasp.run fetch                       # about 150 MB, needs git and network
python -m benchmarks.owasp.run scan --label v1             # needs Docker and the scanner images; about 4 minutes
python -m benchmarks.owasp.run score benchmarks/results/owasp-1.2beta-<date>-v1.predictions.json
```

Scoring reads the saved per-test predictions, so it re-runs without any scanner.
