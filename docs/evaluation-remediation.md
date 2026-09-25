# Evaluating AI fix quality

**Status: not yet run.** Everything below is built and tested, but the evaluation itself needs two things this
project does not have inside the repository: a model API key, and a person to score the answers. No result from
this evaluation is reported anywhere until it has been run and scored. The README says the same.

Goal (plan, Week 14): sample 50 generated fixes, hand-score their correctness, and record the result honestly.

## What is ready

| Piece | Where | State |
|---|---|---|
| A fixed sample of 50 real findings | `benchmarks/remediation/sample.jsonl` | Committed, deterministic (seed 1) |
| Runner (uses the product's own prompt, contract and patch check) | `benchmarks/remediation/run.py generate` | Tested with fake models; not run with a real one |
| Blinded offline scoring page | `run.py scorer` | Tested in a simulated browser |
| Report with confidence intervals and a README table | `run.py report` | Tested on synthetic scores; refuses unscored data |
| Automatic patch check (does it apply to the code?) | `core/llm/patchcheck.py` | Tested against the real `patch` tool |

## The sample

50 findings from real scans of four public vulnerable projects (NodeGoat, nodejs-goof, Vulnerable-Flask-App,
VAmPI): **35 code findings** (each a different rule, so the sample is not dominated by the one noisy Semgrep rule
that produced 111 of NodeGoat's findings) and **15 dependency findings** (each a different CVE). Secrets are
excluded (no code is sent for them) and so is anything without a usable code snippet. Code findings can carry a
patch; dependency findings are scored on the fix advice only.

Known limits of the sample: only JavaScript and Python code, no infrastructure-as-code findings, and the projects
are deliberately vulnerable teaching apps, so their flaws are more textbook than real-world code. Rebuild or
enlarge it with `run.py sample EXPORT.json ... -n 50 --seed 1` (exports come from
`GET /scans/{id}/export?format=json`).

## How to run it

```bash
pip install -e ".[llm]"

# 1. See what would be sent and how many tokens (no key, nothing leaves the machine)
python benchmarks/remediation/run.py generate --dry-run
#    50 calls, about 87,000 input tokens in total, output capped at 1,500 tokens per call

# 2. Generate answers. This SENDS finding text and code snippets to your model provider.
export BULWARK_LLM_ENABLED=1 BULWARK_LLM_API_KEY=...   # never commit or paste a key into a chat
python benchmarks/remediation/run.py generate

# 3. Score them: open the page, judge each item, click "Download scores.json"
python benchmarks/remediation/run.py scorer --results benchmarks/remediation/runs/<run>/results.jsonl

# 4. Turn scores into numbers and a README table
python benchmarks/remediation/run.py report --results benchmarks/remediation/runs/<run>/results.jsonl --scores scores.json
```

The report is written to `benchmarks/results/remediation-<date>.json`. It records the model, the prompt version
and the date, so a later run with a different model is a separate, comparable result.

## The rubric (what "correct" means)

Score each item from the code and the answer, not from how confident or fluent the answer sounds. The page hides
the model's own confidence and the automatic patch check so they cannot sway you.

| Question | 0 | 1 | 2 |
|---|---|---|---|
| **Explanation accurate?** | Wrong or misleading | Partly right | Accurate for this code |
| **Fix correct?** | Wrong, would not fix it, or harmful | Generic or incomplete | Correct and specific to this code |
| **Patch correct?** (only if a patch is shown) | Wrong or breaks the code | Helps but needs edits | Correct as written |

Two yes/no flags: **unsafe** (following it would introduce a new vulnerability or a bad practice) and
**hallucination** (it refers to code, APIs or files that are not in the snippet). The **baseline** question
(optional) applies the fix rubric to the non-AI reference text shown beside it, so the report can say whether the
model adds anything over plain CWE and OWASP guidance.

Guidance for hard cases: a fix that is right in principle but names a function the snippet does not show is a 1
and a hallucination. A patch that applies cleanly but changes behaviour is a 0. If the model's answer was rejected
and reference text was shown instead, score the fix on that text and say so in the notes.

## What is reported, and how to read it

For the items the model answered: the share whose fix is correct (score 2) and acceptable (score 1 or 2), the
share with an accurate explanation, the **unsafe** and **hallucination** rates, and, for answers with a patch,
the share the automatic check found to match the code and the share you scored correct. Also: results by
category, whether the model's stated confidence predicts your score (calibration), how many answers fell back to
reference text and why, and, if you scored the baseline, how often the AI beat, tied or lost to it.

Every rate comes with a 95% Wilson interval and its sample size. **With about 50 items the intervals are wide**
(a measured 70% is consistent with roughly 56% to 81%), so small differences are noise.

## Limits of this design

- **One scorer.** Correctness is a judgement; a single person's scores are not the ground truth. Getting a second
  person to score the same page and comparing would be better, and is not built.
- **The patch check is necessary, not sufficient.** "Applies to the code shown" says nothing about whether the
  fix is right. It also cannot check patches that reach beyond the stored snippet (they are marked unverified).
- **A fix is not run.** Nothing here compiles the patched code or reruns the scanner to see the finding vanish.
  That would be a stronger test and is future work.
- **Small, single-model, single-prompt.** It says nothing about other models or prompt versions until they are run.
- The scorer knows which model is being tested; a blind comparison of two models is not built.
