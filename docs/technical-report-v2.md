# Cross-Tool Correlation, Taint-Confirmed Reachability Ranking, and Mechanically Verified Fixes in an Open-Source Security Scanning Pipeline

*Bulwark v2.0.0 technical report. Source and reproduction instructions:
<https://github.com/rago12bit/cybernatics>. An informal, plain-language companion post is at
[blog-v2.0.0.md](blog-v2.0.0.md).*

## Abstract

Running several open-source static analysis tools against one codebase produces a union of findings
with substantial redundancy and no shared notion of severity. We describe three mechanisms in Bulwark,
an open-source scanning platform, that address this: (1) cross-tool **correlation**, which merges
findings describing the same underlying defect using a composite fingerprint rather than relying on
any single tool's own identifiers; (2) **taint-confirmed reachability ranking**, which augments a
severity-and-exploitability risk score with a binary signal derived from static data-flow analysis —
whether a reported sink is demonstrably reached from an HTTP entrypoint — rather than treating every
static-analysis finding as equally actionable; and (3) a **verified-fix** pipeline in which a
model-proposed patch is accepted only after it is shown, mechanically, not to regress the finding, the
originating tool, the full scanner suite, or the project's own test suite. We report measurements
against the OWASP Benchmark, the Juliet Test Suite, a 25-repository corpus, and a hand-verified
spot-check against real deliberately-vulnerable applications, and we are explicit about which claims
remain unmeasured because they require a live, costly model call this evaluation environment does not
have provisioned.

## 1. Introduction

A developer running Bandit, Semgrep, Gitleaks, Trivy and OSV-Scanner against one repository receives
five reports in five formats with five severity vocabularies. The same SQL injection may appear as a
Bandit finding and a Semgrep finding; the same vulnerable dependency may appear in both Trivy and
OSV-Scanner's output. The engineering problem we address is not detection — that is delegated to
mature, independently maintained tools — but **normalization, correlation, and prioritization** over
their combined output.

Two further problems compound this. First, a reported weakness (e.g., "this function may be callable
with attacker-controlled input") is not the same claim as "this function *is* callable with
attacker-controlled input from a concrete, traceable entrypoint" — the former is what most SAST tools
report; the latter requires data-flow analysis most of them do not perform. Second, once a true
positive is identified and prioritized, nothing in a conventional pipeline closes the loop: a suggested
fix, if offered at all, is typically unverified prose or an unapplied diff.

This report describes how Bulwark v2.0.0 addresses all three.

## 2. System Overview

Each configured scanner executes in an isolated container (`--network=none --read-only
--cap-drop=ALL`, non-root, resource-limited) against a read-only mount of the target. Raw tool output
is parsed into a canonical `Finding` record (location, taxonomy, native and normalized severity,
evidence). This canonical representation is the substrate correlation, ranking, and the fix pipeline
all operate on.

## 3. Correlation

### 3.1 Method

Two findings are considered the same underlying defect if they satisfy one of two identity rules: (a)
**dependency identity** — same package name/ecosystem and a shared vulnerability advisory identifier
(CVE/GHSA/etc.), independent of which SCA tool reported it; or (b) **code identity** — same file, a
configurable line-proximity window, and either a shared CWE or sufficient snippet token overlap,
independent of each tool's own internal rule identifier. Rule (b) exists because no two SAST tools
share a rule-naming scheme; relying on rule-id equality would merge nothing across tools.

Every contributing tool's evidence is retained on the merged record; the highest normalized severity
among contributors is kept, never averaged or discarded.

### 3.2 Results

Measured on a 25-repository corpus (12 deliberately vulnerable applications, 13 ordinary open-source
projects), all five default scanners, one run per repository on an otherwise-idle machine:

| | Deliberately vulnerable apps | Ordinary repositories | Pooled |
|---|---:|---:|---:|
| Dedup rate | 19.9% | 1.3% | 8.9% |
| Tool-run failures | 0 / 94 | | |

The pooled figure is not independently meaningful: deliberately vulnerable test applications
concentrate the kind of dependency overlap (two SCA tools reporting the same advisory) that drives
most of the merging; ordinary repositories' findings rarely overlap at all. We report both strata
rather than the pooled number alone for this reason.

## 4. Taint-Confirmed Reachability Ranking

### 4.1 Method

The taint engine performs intraprocedural and limited interprocedural data-flow analysis (tree-sitter
parse trees; language-specific source/sink/sanitizer catalogs for Python, JavaScript and Go) to
determine whether a declared *sink* (e.g., `eval`, a raw SQL `query` call, `child_process.exec`) is
reached by data originating at a declared *source* (an HTTP framework's request object). Deliberately,
**the engine does not emit new findings**: it only annotates an existing SAST finding from another
tool, at the same file and line, with a confirmed reachability signal. A finding with no corresponding
taint-sink match is left annotated `reachable: null` — "unknown," never a fabricated "not reachable" —
the same discipline this platform's existing package-level dependency-reachability analysis already
applies.

A confirmed reachable finding's `scoring.confidence` is set to a fixed high value (0.9), which this
platform's existing risk-scoring formula already treats as the dominant likelihood term for any finding
category without CVE/EPSS/KEV data (SAST, secrets, IaC). This reuses an existing, already-reviewed
scoring path rather than introducing a second, parallel rule that would need to be kept consistent
with it.

### 4.2 Results

**Reachability confirmation (spot-check).** We ran the full pipeline (Bandit, Semgrep) against two
real, deliberately vulnerable JavaScript applications (NodeGoat, nodejs-goof) already present in our
corpus, then manually inspected every confirmed-reachable finding against the underlying source. All
three confirmations (NodeGoat, `app/routes/contributions.js:32-34`, data from an Express request body
flowing to `eval`) were verified true positives by inspection — the target file's own source comment
reads "Insecure use of eval() to parse inputs," with a safe alternative commented out directly below
it. Notably, the originating report (Semgrep's `eval-detected` rule) is a syntactic pattern match with
no data-flow component; the taint engine's contribution is specifically the *flows-from-request*
claim, which the pattern rule alone cannot make. This is a small, hand-verified sample (N=3) and does
not constitute a corpus-scale precision/recall study; we report it as such rather than extrapolating.

**Ranking.** We evaluate whether ordering findings by the full risk score (severity combined with
EPSS, CISA KEV status, and reachability) yields better top-K precision than ordering by severity alone,
using the OWASP Benchmark (2,894 Semgrep findings, 1,395 true positives by the Benchmark's own ground
truth) with expected-value tie-breaking:

| Top-K | Risk score | Severity only | Random | Difference (95% CI) |
|---:|---:|---:|---:|---:|
| 10 | 69.2% | 52.4% | 48.2% | +16.8 pp (−10.7, +40.3) |
| 20 | 63.3% | 52.4% | 48.2% | +10.9 pp (−6.4, +28.3) |
| 50 | 56.8% | 52.4% | 48.2% | +4.4 pp (−2.0, +10.8) |
| 100 | 54.6% | 52.4% | 48.2% | +2.2 pp (−0.6, +5.3) |

The risk score leads at every K, with the largest margin at the smallest K, but every confidence
interval includes zero: **this dataset does not demonstrate a statistically significant improvement**
over severity-only ranking. We attribute this in part to the dataset's low score cardinality (only one
Java-capable scanner contributes, yielding 7 distinct risk scores and 2 distinct severities across the
whole corpus) and to the complete absence of exploitation ground truth for the dependency-specific
signals (EPSS, KEV) in any benchmark available to us — the OWASP Benchmark contains no dependency
findings at all. We report this as a negative result rather than omit it.

## 5. Mechanically Verified Fix Generation

### 5.1 Method

Given a finding, a model proposes a patch. Rather than presenting this patch directly, the system
executes a four-stage verification loop before any human sees it as "ready for review": (1) apply the
patch in an isolated, network-denied sandbox; (2) re-run the specific rule that produced the original
finding, confirming it no longer fires; (3) re-run the full configured scanner suite over the patched
code, confirming no new finding is introduced; (4) run the project's own test suite, confirming no
regression. Only a patch that survives all four stages is offered for human approval as a pull
request; a patch that fails any stage is discarded, not shown with a caveat. The system deliberately
does not attempt to automatically merge a verified patch — human approval remains mandatory.

### 5.2 Results and a disclosed limitation

The contract, prompt construction, verification-loop control flow, and PR-creation mechanics are
implemented and unit-tested against the real control-flow paths (valid model reply, a malformed reply
repaired once, exhausted retries) using fake model clients covering each path. **The acceptance rate of
verified fixes, and blind human review of proposed patches, require a live model and ongoing per-run
cost; this evaluation environment is not provisioned with one, and we report this gap explicitly
rather than substitute a smaller, unrepresentative number.** The mechanism's correctness under
adversarial input (a planted prompt-injection payload attempting to redirect the patch outside the
finding's own file, or to claim a real finding is a false positive) is separately verified: 60 payload
x contract combinations across the full LLM-consuming surface (this fix pipeline, the triage assistant,
the attack-path narrator) were tested, and all 60 were correctly rejected by the parsing contract
regardless of what the (simulated) model returned.

## 6. Limitations and Threats to Validity

- **Single-analyzer coverage for Java.** Both the OWASP Benchmark and Juliet results are Semgrep's
  alone; no claim here generalizes to an ensemble of Java analyzers, which we do not have.
- **The taint-engine result is a spot-check, not a corpus study**, and does not evaluate recall against
  vulnerability classes outside the three sink categories exercised (JavaScript `eval`/`exec`/`query`).
- **Scale measurements (p95 latency, autoscaling behavior) were taken on a single developer machine**
  and a local `kind` cluster, not a provisioned production environment; relative findings (a bottleneck
  exists, a fix resolves it) are more robust than the absolute millisecond figures.
- **No independent replication.** All measurements in this report were produced by the same team that
  built the system under test, on infrastructure that team controls. We mitigate this only by
  publishing method, raw result files, and reproduction commands alongside every number.

## 7. Related Work

Cross-tool SAST aggregation is the explicit design goal of DefectDojo (OWASP), which this project's
third development phase (not covered in this report) is explicitly modeled on for ingest and
vulnerability-management workflow, while deliberately not reusing its name or branding. Taint analysis
for web application vulnerability detection is long-studied (e.g., Livshits and Lam, 2005, for Java);
our contribution is narrower and more modest — using taint analysis purely as a *confirmation* signal
over findings other tools already produced, rather than as an independent detector, to keep the
analysis tractable within a multi-language, multi-tool pipeline. LLM-assisted vulnerability
remediation has seen substantial recent interest; our verified-fix design's distinguishing property is
that acceptance is gated on reproducible, mechanical verification (rule re-check, full scanner re-run,
test suite) rather than on the model's own confidence or a single rerun of the triggering check alone.

## 8. Conclusion

Correlation, taint-confirmed reachability, and mechanically verified fixes are three independent
mechanisms addressing three distinct failure modes of a naive multi-scanner pipeline: redundant
reports, undifferentiated severity, and unverified remediation. We report real measurements for all
three, including a negative result (ranking improvement not statistically demonstrated on available
data) and an explicit, unfilled gap (verified-fix acceptance rate, which needs a live model this
evaluation was not provisioned with). We consider the explicit reporting of what is not yet measured to
be as much a contribution of this work as the mechanisms themselves.

## Reproducibility

All result files referenced are committed at `benchmarks/results/` in the source repository. Commands
to reproduce every number in this report are in [evaluation-v2.md](evaluation-v2.md),
[evaluation-owasp.md](evaluation-owasp.md), [evaluation-juliet-corpus.md](evaluation-juliet-corpus.md),
and `benchmarks/README.md`.
