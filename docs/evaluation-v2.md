# Evaluation v2 (plan §34, Week 52)

Every row of the plan's own evaluation table, filled in honestly: measured and cited where real work
already exists, freshly measured this week where that was feasible without a live model, and clearly
marked **not measured** where it genuinely isn't -- most commonly because the feature needs a live
`ANTHROPIC_API_KEY` this environment does not have, a gap every one of those features' own weekly
verification docs already disclosed individually. This document's job is to put all eleven rows in
one place, not to re-litigate or soften what they already said.

## Results

| Area | Metric | Result | Status |
|---|---|---|---|
| Incremental scanning | Median PR scan time; speedup over a full scan | NodeGoat: 71.2s cold → 19.6s warm (**3.6x**), target <60s met | Partial -- 1 repository, not the full "last 20 PRs × 30-repo corpus" ask |
| Taint engine | Precision/recall, Python & JS, vs. Semgrep taint mode | 9/9 hand-verified true positives across 5 of 8 corpus repositories, 0 false confirmations | Partial -- larger real spot-check (was 3/3 on 1 repo), not a corpus-scale study; no Semgrep-taint-mode comparison |
| Ranking | Top-20 precision: risk score vs. severity-only vs. random | 63.3% / 52.4% / 48.2% (95% CI includes 0) | **Measured** -- already published, [below](#ranking-detail) |
| Verified fixes | Share of TPs verified-fixed; blind human review; regressions | -- | **Not measured** -- needs a live model |
| Triage assistant | Precision/recall of "likely false positive" vs. OWASP Benchmark labels | -- | **Not measured** -- needs a live model |
| Hypotheses lane | Precision on seeded auth flaws + Juice Shop | -- | **Not measured** -- needs a live model |
| Copilot | Valid-citation rate; answer correctness (100-question set) | -- | **Not measured** -- needs a live model |
| LLM security | Attack success rate per release (red-team corpus) | 60/60 adversarial payload x contract combinations correctly rejected (structural defenses) | Partial -- deterministic-defense pass rate, not a live-model attack-success-rate (needs `garak` + a live model) |
| UX | SUS before/after; time to first scan; task success | -- | **Not measured** -- baseline study never run (real participants needed) |
| Scale | p95 API latency; scans per hour | Scan submission: p95 675ms; results browsing: p95 1.84s (single dev laptop) | **Measured** -- Week 50, [docs/v2-week50-verification.md](v2-week50-verification.md) |
| Platform security | Fuzzing crashes found/fixed; ASVS Level 2 coverage | 0 crashes (manual boundary probe; Atheris itself doesn't build on macOS); full ASVS 4.0.3 Level 2 self-audit | **Measured** -- Week 48, [docs/ASVS-SELF-ASSESSMENT.md](ASVS-SELF-ASSESSMENT.md) |

Also carried over from the v1/early-v2 evaluation (scanning and correlation, not re-run here because
nothing about them changed since):

| Measure | Result |
|---|---|
| OWASP Benchmark: recall / false-positive rate / F1 (`related` matcher, Semgrep) | 88.2% / 43.7% / 77.0% |
| Juliet: recall / false-alarm rate / score | 23.8% / 19.6% / +0.042 |
| 25-repository corpus: tool-run failures | 0 of 94 |
| 25-repository corpus: dedup, vulnerable apps / ordinary repos / pooled | 19.9% / 1.3% / 8.9% |

Full detail: [docs/evaluation.md](evaluation.md), [docs/evaluation-owasp.md](evaluation-owasp.md),
[docs/evaluation-juliet-corpus.md](evaluation-juliet-corpus.md).

## Taint engine: what was actually measured

The taint engine (`core/taint/`) doesn't detect vulnerabilities on its own -- it confirms whether a
SAST finding some other scanner already reported is *reachable* from a real HTTP entrypoint
(`core/taint/reachability.py`'s own documented design). So "precision and recall on labelled cases"
means: of the SAST findings it could confirm, were the confirmations correct, and of the ones it
could have confirmed, how many did it?

**Method.** Ran the real scan pipeline (`bulwark scan --tools bandit,semgrep`, no mocks) against 8
already-cached, real, deliberately-vulnerable repositories from this project's own 25-repo corpus --
every Python/JavaScript one it has (NodeGoat, nodejs-goof from Week 52; VAmPI, Vulnerable-Flask-App,
pygoat, dvpwa, vulpy, dvna added afterward) -- then read the flagged source by hand to check each
confirmation against the real code. Full method, two real bugs found and fixed along the way (a
resolver name-collision that could silently erase real taint, and a missing `subprocess.Popen`
catalog entry), and three freshly-confirmed real scope limits:
[docs/v2-gap-closure-taint-corpus.md](v2-gap-closure-taint-corpus.md).

**Result: 9 confirmed reachable findings across 5 of 8 repositories, 9/9 hand-verified genuine true
positives, 0 false confirmations** -- up from the original 3/3 on NodeGoat alone:
- NodeGoat (unchanged): 3 findings, `app/routes/contributions.js:32-34`,
  `eval(req.body.preTax)` et al. -- NodeGoat's own documented "A1 SSJS Injection" tutorial
  vulnerability, the file's own comment reads `// Insecure use of eval() to parse inputs`.
- pygoat: 4 SAST findings confirmed reachable (`cmd_lab`'s and `mitre_lab_17_api`'s
  `subprocess.Popen` command injections, `cmd_lab2`'s and `mitre_lab_25_api`'s direct `eval`
  injections -- one of the four only found after this week's bug fixes, see the linked doc), plus a
  5th genuine reachable sink (`ImageMath.eval`) with no SAST finding at that exact line to attach to.
- Vulnerable-Flask-App: 1 (`request.json`-sourced SQL injection via `db.engine.execute`).
- dvna: 1 (`req.body.login`-sourced SQL injection via `db.sequelize.query`).
- VAmPI, dvpwa, vulpy: 0 confirmed each, for three different, real, documented reasons (an
  OpenAPI-path-parameter source the catalog doesn't recognize; an ambiguous same-named function
  across the repo's own parallel `bad`/`good` implementations; an `aiohttp` app, a framework
  `core.codeintel`'s entrypoint detector doesn't cover) -- not silent gaps, each confirmed and named
  in the linked document.
- Every confirmed finding's originating SAST rule fires on the pattern alone (`eval()`,
  `subprocess.Popen(..., shell=True)`, a raw `.execute()`/`.query()` call), tainted or not -- the
  taint engine's actual contribution is narrowing each one down to "and this argument provably comes
  from this HTTP request," which the pattern rule alone cannot say.

**What this is not**: a corpus-scale precision/recall study, and not a comparison against Semgrep's
own taint mode specifically (its bundled community rules use pattern mode here; a taint-mode
comparison would need hand-authored Semgrep taint rules for the same source/sink pairs, which wasn't
built). This is a real, hand-verified spot-check, larger than before -- 9 confirmed cases across 8
repositories, 0 false confirmations -- not the full "labelled Python and JavaScript corpus" the plan
describes, and no Go-language vulnerable repository exists in the corpus at all.

## Ranking detail

Already measured and published in [docs/evaluation-juliet-corpus.md](evaluation-juliet-corpus.md#3-prioritization-quality-risk-score-vs-severity-only);
reproduced here because it's one of §34's own named rows, not because anything changed:

| Top-K | Risk score | Severity only | Random | Risk − severity (95% CI) |
|---:|---:|---:|---:|---:|
| 10 | 69.2% | 52.4% | 48.2% | +16.8% (-10.7% to +40.3%) |
| 20 | 63.3% | 52.4% | 48.2% | +10.9% (-6.4% to +28.3%) |
| 50 | 56.8% | 52.4% | 48.2% | +4.4% (-2.0% to +10.8%) |
| 100 | 54.6% | 52.4% | 48.2% | +2.2% (-0.6% to +5.3%) |

The risk score leads at every K, but every confidence interval includes zero -- this is weak evidence
in its favor, not a demonstrated result. "Severity only" here is a fair stand-in for v1's own
pre-EPSS/KEV ranking, since that's literally what v1.0 sorted by before Week 9 added EPSS and KEV.
The parts of the score that matter most for dependency findings (EPSS, KEV, reachability) have no
exploitation ground truth in this dataset, so their effect on ordering is argued in
[risk-score.md](risk-score.md), not measured here -- unchanged since the original measurement.

## LLM security detail

`tests/redteam/` (see [docs/redteam.md](redteam.md)) runs 20 adversarial payloads against every
contract that parses raw model text (`core.llm`, `core.triage_assistant`, `core.attackpath`) -- 60
payload x contract combinations, all 60 correctly rejected, plus four more targeted suites (patch
confinement, severity immutability under injection, Copilot tool-scope enforcement, a real
secret-forwarding bug this suite itself caught and fixed). This is a **structural defense** pass
rate: it proves the contracts can't be tricked into producing a harmful result regardless of what a
model says. It is not the plan's "attack success rate per release," which needs `garak` actually
attacking a live model and tracking how often persuasion succeeds -- deliberately deferred, same
reasoning `docs/redteam.md` already gives: that needs a real API key, ongoing spend per run, and a
probe-budget decision, not something to fake with a hardcoded number.

## What this does NOT prove (read before relying on it)

- **Five of eleven rows need a live model and were not measured**: verified-fix acceptance/blind
  review, triage assistant precision/recall, hypotheses lane precision, Copilot citation/correctness,
  and the LLM security *attack success rate* specifically (its structural-defense pass rate *is*
  measured, above). Every one of these gaps was already disclosed in that feature's own week
  (41/42/43/44) -- this document doesn't newly discover them, just collects them.
- **The UX row has no "before" or "after."** The baseline usability study (Week 31) was never run
  with real participants; there is nothing to compare a redesign against yet.
- **The taint engine measurement is a spot-check (N=9 confirmed cases across 5 of 8 repositories), not a
  corpus-scale study**, and makes no claim about recall against vulnerability classes outside its
  declared sink categories, or against the 4 corpus repositories whose own language (Java,
  CloudFormation, Terraform) has no taint catalog at all. The Go catalog specifically has never been
  run against a real vulnerable repository -- the corpus has none.
- **Scale and platform-security numbers are a single developer laptop's**, not a provisioned
  server's -- see each one's own week for the full caveat.
- **Incremental scanning is one repository with a 3-file edit**, not the plan's "last 20 merged PRs
  of each repository in the 30-repository corpus" -- `benchmarks/incremental/run.py` supports more
  repos; running it across the full corpus was not done this week.
