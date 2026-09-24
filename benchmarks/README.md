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

### An honest before/after: aligning scanner scope
The first run scored **19.2%** (2088 -> 1686). On `NodeGoat` only 83 of OSV-Scanner's 292 findings
had a Trivy match, which looked like a weak matcher. Investigating showed the matcher was fine: Trivy
**skips dev dependencies by default** while OSV-Scanner includes them, so the tools were not
scanning the same thing (208 of the 209 unmatched findings were on package versions Trivy reported
nothing for). With `--include-dev-deps`, **291 of 292** matched. The change is kept in the Trivy
adapter and pinned by a regression test; the original run is preserved as
`results/dedup-2026-09-25-v1-trivy-default-scope.json` for the record.
