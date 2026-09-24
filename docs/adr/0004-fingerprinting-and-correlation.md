# ADR-004: Cross-tool correlation and fingerprinting scheme

Status: Accepted (2026-09-25)

## Context
Five scanners over one repository produce overlapping reports of the same defects, and they disagree
on almost everything a naive comparison would use:

- **Line numbers.** Bandit reports the assignment building a SQL string (line 6); Semgrep reports the
  `execute()` call that uses it (line 7).
- **Snippets.** Bandit quotes numbered context lines; Semgrep quotes only the matched expression.
- **Identifiers.** OSV reports `GHSA-…` with CVE aliases; Trivy reports the `CVE-…` directly. Trivy
  says ecosystem `pip`, OSV says `PyPI`.
- **CWEs.** Bandit calls a hardcoded password CWE-259; Gitleaks calls the same line CWE-798.
- **Granularity.** Semgrep fires two rules on one `subprocess.call(..., shell=True)`.

Exact-match fingerprinting fails on all of these. The goal is to merge reports of one defect without
merging two different defects.

## Decision
Findings are correlated in `core/correlation` (pure functions over `Finding`; no I/O).

### Matching (`same_defect`)
**SCA** (findings with a `package`): merge iff same `(ecosystem, name, version)` **and** they share a
vulnerability identifier (any of CVE / GHSA / PYSEC / ..., compared case-insensitively over
`taxonomy.aliases ∪ taxonomy.cve`). Ecosystems are normalized (`pip`/`PyPI` → `pypi`). Grouping is
transitive, so one OSV advisory covering CVE-A and CVE-B absorbs Trivy's two separate findings.

**Code, IaC and secrets:** merge iff all of the following hold:
1. same file path;
2. compatible category (`sast`↔`sast`; `sast`↔`secrets` allowed, nothing else crosses);
3. overlapping **CWE family** (a small explicit parent/child map: 259, 260, 321 → 798);
4. line ranges within `LINE_WINDOW = 3` lines of each other (distance between ranges, not points);
5. snippet evidence: token-set **overlap coefficient ≥ 0.8** over normalized snippets, or, when a
   snippet is a redaction placeholder or has fewer than `MIN_TOKENS = 4` tokens (no evidence either
   way), the findings must be on **adjacent lines** (distance ≤ 1).

Snippet normalization strips line-number prefixes and comments and masks identifiers, strings and
numbers, so `query = "SELECT " + user_id` and `q = "SELECT x" + uid` compare equal.

**Overlap coefficient, not Jaccard.** One tool routinely quotes more context than another, so the
smaller snippet is usually a subset of the larger. Jaccard punishes that; containment does not.

**Never merge a tool with itself.** Two findings from the same tool *and the same rule* are distinct
occurrences (two identical call sites are two defects) even when a third tool's finding spans both.
The cluster union refuses any merge that would put one `(tool, rule)` in a cluster twice. Different
rules from the same tool on one defect (Semgrep's two `shell=True` rules) *do* merge, and both rule
ids are kept.

### Merging
- **Severity:** the maximum across members; every tool's native label is kept in
  `scoring.native_severity`.
- **Confidence:** noisy-OR over the members, `1 − Π(1 − cᵢ)`, capped at 0.99. Agreement between
  independent scanners raises confidence; two rules from the *same* tool do not raise
  `agreement_count`, which counts distinct tools.
- **Primary member** (title, location, description): highest severity, then confidence, then a fixed
  tool priority. CWE / OWASP / CVE / alias / reference lists are unioned.

### Fingerprints
- **SCA (exact):** `sha256(ecosystem | name | version | primary_id)` where `primary_id` is the
  smallest CVE, else the smallest alias. Identical whichever tool reported it.
- **Code:** `sha256(smallest CWE in family | path | hash of normalized snippet)`; for placeholder
  snippets, the line number replaces the snippet hash. Survives whitespace, comment and renaming
  changes and line movement. It is *best effort* across different tool sets, because the quoted
  snippet depends on which tool led the merge.

### Ordering and safety
Correlation runs **before** redaction. Redaction placeholders are identical strings and would
otherwise look like matching snippets, merging unrelated defects that merely sit near a secret
(covered by a regression test).

## Alternatives considered
- **Exact `(cwe, path, line)` match.** Fails on the ±1–3 line disagreement seen in the very first
  real example (Bandit 6 vs Semgrep 7).
- **Line-only proximity.** Merges unrelated defects on neighbouring lines.
- **ML / embedding similarity.** Non-deterministic, unexplainable to a user who asks "why were
  these merged?", and unnecessary given the structure above.

## Consequences
- Every merge decision is explainable from the rules above; the UI shows "Flagged by 2 of 2 code
  scanners" with each tool's own severity and rule.
- The thresholds (`LINE_WINDOW`, `SNIPPET_OVERLAP`, `MIN_TOKENS`) are recorded alongside every
  benchmark run, so they can be tuned against evidence rather than intuition.
- Known limits: no cross-file matching (a taint flow spanning files is reported at each end);
  CWE families beyond the credential group are not mapped; IaC/Dockerfile findings have no CWE, so
  they only ever merge within Trivy.

## Measured results (2026-09-25)
Baseline over five public repositories (`benchmarks/README.md`, `benchmarks/results/`):
**2552 raw findings -> 1824 unique, a 28.5% deduplication rate**, ranging from
6.9% (Terraform-only) to 49.2% (dependency-heavy), with all five repos completing.

Evidence about the matcher itself: on NodeGoat, **291 of OSV-Scanner's 292 findings** were matched to a
Trivy finding once both scanned the same scope, and the single miss was a genuinely different advisory.
The first run's apparently poor overlap (83 of 292) was a *scanner-scope* difference (Trivy skips dev
dependencies by default), not a matching failure, which is why the Trivy adapter now passes
`--include-dev-deps`. Lesson recorded: when cross-tool agreement looks low, check that the tools are
scanning the same thing before tuning the matcher.
