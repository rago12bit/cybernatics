# Bulwark 1.0.0: what a scanner correlation pipeline actually gets you

I spent 26 weeks building Bulwark, a security scanner that runs five open-source tools in locked-down
containers, merges what they find into one deduplicated list, and ranks it by a risk score instead of raw
severity. This week I tagged `v1.0.0`. Here's what it does, what I measured, and where it falls short — with
numbers, not adjectives.

## The idea

Run Bandit, Semgrep, Gitleaks, Trivy and OSV-Scanner against a repository and you get five separate reports.
A SQL injection shows up as a Bandit finding, a Semgrep finding and a CWE entry; a vulnerable npm package shows
up in both Trivy and OSV-Scanner. Nobody reads five overlapping lists, so most people read one and ignore the
rest, which throws away whatever the other four saw.

Bulwark's job is narrow: normalize every tool's output into one schema, correlate what's the same
vulnerability, and score what's left by how likely it is to matter (severity, EPSS exploitation probability,
CISA KEV, and whether the code path is reachable), not just by the tool's own severity label. Everything runs
in a container with no network access, a read-only filesystem, dropped capabilities and a non-root user,
because the whole point is to point untrusted third-party scanners at code you don't fully trust either.

## What shipped

- **Five scanners by default** (Bandit, Semgrep, Gitleaks, Trivy, OSV-Scanner), four more opt-in (Grype,
  Checkov, gosec, Dockle).
- **Correlation and a risk score** — EPSS, CISA KEV, and static reachability analysis, not just severity.
- **LLM-backed fix suggestions**, retrieval-grounded in CWE and OWASP cheat-sheet text, labelled as AI-generated
  and never presented as a verdict.
- **A CLI, a REST + WebSocket API, a web UI, a VS Code extension and a GitHub Action** — one pipeline, four
  surfaces.
- **SBOMs (CycloneDX 1.6) and signed attestations** (in-toto provenance, cosign).
- **Observability**: structured logs, OpenTelemetry tracing, Prometheus metrics.

All of it is in the [CHANGELOG](../CHANGELOG.md); the architecture is in [docs/adr](adr/).

## What I actually measured

I didn't want to ship a scanner and just assert it works, so weeks 23–25 were entirely about evaluation:
a public benchmark with labelled ground truth, a synthetic per-CWE suite, and a corpus of real repositories.
Full method and limits: [docs/evaluation.md](evaluation.md).

| Measure | Result |
|---|---|
| OWASP Benchmark: recall / false-positive rate / F1 | 88.2% (CI 86.4–89.8) / 43.7% / 77.0% |
| Juliet (per-CWE, Java): recall / false-alarm rate | 23.8% / 19.6% |
| Corpus (25 repos, 94 tool runs): crash rate | 0 |
| Corpus: dedup, vulnerable apps / ordinary repos | 19.9% / 1.3% |
| Corpus: wall time per repository, median / p90 | 6 s / 42 s |
| Top-20 precision: risk score / severity-only / random | 63.3% / 52.4% / 48.2% |

A few things worth saying plainly, because a benchmark table with no caveats is just marketing:

- **All of this is Semgrep's number, not an ensemble's.** Only one of the five default scanners analyses Java,
  so neither Java benchmark says anything about whether combining scanners improves detection. That question
  needs a language with more than one analyser in the default set, which I don't have yet.
- **Detection is strong where the flaw is a syntactic pattern and weak where it needs data-flow analysis.**
  88% recall on OWASP Benchmark sounds good until you see the false-positive rate on injection categories:
  65–88%. On Juliet, a synthetic suite built to isolate individual weaknesses, recall drops to 24%, and where
  Semgrep does flag an injection CWE it flags the safe variant about as often as the vulnerable one. That
  finding carries almost no signal.
- **The risk score is not shown to beat severity-only ranking.** It's ahead at every top-K I measured, but the
  95% confidence interval on the difference includes zero every time. With one scanner and only two severity
  levels in play, there isn't much for the score to separate findings with. I'm reporting the honest result of
  that limitation, not the flattering headline.
- **Zero crashes in 94 tool runs is one run on one laptop, not a reliability guarantee.** By the rule of three,
  that only bounds the true crash rate at roughly 3% with 95% confidence.
- **Correlation's dedup rate depends entirely on what you scan.** Deliberately vulnerable test apps have the
  same bug reported by two tools about a fifth of the time; ordinary open-source repositories, about 1%. A
  single pooled "dedup rate" number without that split is close to meaningless.

Performance got a real pass too: I found Semgrep was spending ~26 seconds of every scan just loading 337 small
rule files, merged them into one file per language at image build time, and that plus giving Semgrep and Trivy
more CPU quota took the corpus's median per-repository wall time from 47 seconds to 6. Chasing that down also
surfaced a real correctness bug — Semgrep silently drops a rule/file pair after a 5-second timeout and still
exits 0, so a CPU-starved run can lose most of its findings with no error. Bulwark now surfaces that as a
`warnings` field instead of staying quiet about it.

## What's not measured, and what's not done

- **SCA prioritization** (does the risk score help for vulnerable dependencies specifically) has no dataset
  with exploitation ground truth, so it's unevaluated. I say so rather than guess.
- **The VS Code extension and GitHub Action** are built and unit-tested but have not run in a real VS Code
  install or on GitHub's runners. That's the next real-world test, not a benchmark.
- **AI fix suggestion quality** is unmeasured — I have no rubric or human evaluation for it yet.
- **Auth is one shared bearer token.** This isn't multi-user software yet; don't point it at the public
  internet.

## Try it

```bash
git clone https://github.com/Rag2102/cyberimp
cd cyberimp && ./scripts/init-env.sh
docker compose --profile scanners build && docker compose up -d
# http://localhost:3000 — the first page is a real sample report, no sign-in needed
```

Source, docs and the full evaluation writeups: <https://github.com/Rag2102/cyberimp>.
