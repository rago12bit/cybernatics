# Talk outline: "Bulwark: what I learned building a security scanner correlation platform"

For a college tech club or a local OWASP chapter meeting (plan §33, Week 52 task 4). ~20-25 minutes
plus Q&A. Giving the talk is yours; this is the outline and speaker notes, in the same honest voice as
[blog-v2.0.0.md](blog-v2.0.0.md) and the [technical report](technical-report-v2.md) it's drawn from.

## 1. Hook (1 min)

Open with the live homepage (`localhost:3000`), let the Juice Shop replay run while you talk: "This is
a real scan of a real, deliberately vulnerable app, happening live on screen. By the end of this talk
you'll know exactly how the three interesting parts of it work, and — just as importantly — what I
still can't honestly claim about it."

## 2. The problem (2 min)

- Five open-source scanners, five formats, five severity vocabularies, massive overlap.
- Show a raw finding from two different tools side by side for the same bug. Nobody reads five
  reports; most people read one and silently lose whatever the other four caught.
- One sentence on scope: "I'm not building a better detector. Bandit, Semgrep, Trivy already exist and
  are good at this. I'm building the layer on top: merge, rank, and eventually fix."

## 3. Correlation (4 min)

- The core idea: two identity rules, not one magic fingerprint. Dependency findings merge on a shared
  advisory id (CVE/GHSA); code findings merge on file + line window + shared CWE or snippet overlap.
- Why rule-id matching doesn't work: no two tools name a SQL-injection rule the same thing.
- **Real number**: 19.9% of findings merge on deliberately vulnerable test apps, about 1.3% on ordinary
  open-source repos. Make the point explicit: *report both numbers, never the pooled one alone* — it's
  an easy place to accidentally mislead an audience.

## 4. Taint-confirmed reachability (6 min) — the centerpiece

- The gap: a SAST tool says "this function could be dangerous." It usually can't say "and here's proof
  user input actually reaches it."
- Live demo moment: open the taint-confirmed `eval()` finding from the Juice Shop/NodeGoat demo. Show
  the taint path UI. Say out loud: "Semgrep's rule just pattern-matches `eval(...)`. My taint engine
  additionally proves the argument comes from `req.body`. That's the whole contribution, visualized."
- Be honest about the measurement here on stage, don't skip it: "I hand-verified 3 real cases on one
  real app. That's a spot-check, not a published precision/recall number. I'll show you exactly why
  that distinction matters" — segue into:
- **The ranking result that didn't work**: show the top-20 precision table. Risk score beats
  severity-only at every K... but every confidence interval includes zero. "I could have cut this
  slide. I kept it because reporting a result you don't like is the actual point of doing evaluation at
  all, not a footnote you bury."

## 5. Verified fixes (5 min)

- The loop: propose a patch → re-run the rule → re-run every scanner → run the project's own tests →
  only then offer it to a human. Draw this as a simple diagram live if you have a whiteboard.
- The key framing line: "An LLM suggesting a diff is cheap. An LLM suggesting a diff that's been
  mechanically proven not to break your test suite is a much smaller, much more defensible claim —
  and it's the one I'm actually making."
- Disclose the gap on stage, don't wait for Q&A to be asked: "The acceptance rate — how often a
  verified fix actually gets approved by a real reviewer — needs a live model running continuously,
  which costs real money I haven't spent yet. I'm not going to make up a number for this talk."

## 6. What I'd tell past-me (3 min)

- Pick 2-3 real "found and fixed" stories from the CHANGELOG with specific numbers — these land better
  live than architecture slides. Good candidates: the `reap_stale_scans` RLS bug (silently a no-op in
  any real deployment, found this project's own Week 50), the pre-commit hook's one-`git-show`-per-file
  perf bug (1.93s → 0.45s from one batching fix), or Semgrep's silent 5-second rule/file timeout
  (found while chasing a performance regression, now surfaced as a warning instead of quietly dropped
  findings).
- The theme across all three: "The bug wasn't in the hard, interesting code. It was in the boring
  path nobody was watching. Evaluation and honest verification found more real bugs for me than
  clever architecture ever did."

## 7. Close (2 min)

- Apache-2.0, link to the repo, link to the evaluation docs specifically ("read the numbers, not just
  the pitch").
- One line on what's next if you want to invite follow-up questions: v3 is explicitly modeled on
  DefectDojo's ingest/engagement model, not a clone of it — portfolio hierarchy, SLAs, risk acceptance,
  a universal import endpoint.

## Q&A prep: likely questions

- **"Why not just use CodeQL / Snyk / [commercial tool]?"** — This is about correlation and
  prioritization across *open-source* tools specifically; licensing is also a real constraint (see
  ADR-006: Semgrep's community rules are self-host-only, which is why there's no hosted scanning
  service today — a hosted multi-tenant mode is a planned v3 item that would need to switch to
  Opengrep with project-authored rules instead).
- **"Does the LLM ever hallucinate a finding?"** — No: the model never originates findings, only
  explains/suggests fixes for or triages findings deterministic tools already produced. Detection stays
  delegated to the scanners.
- **"What stops the fix-verification loop from being gamed by a prompt injection in the scanned
  code?"** — This is exactly what `tests/redteam/` checks: 60 adversarial payload x contract
  combinations, all rejected regardless of what a (simulated) model returns, because severity/taxonomy
  mutation and patch-file-scope are enforced in code, not trusted from model output.
- **"What's the actual precision/recall of [feature]?"** — If it's one of the five LLM-gated rows, say
  so directly: "Not measured yet — needs a live model and a cost budget I haven't allocated. Here's
  what I'm confident about instead: [structural guarantee]." This is a stronger answer than a vague
  deflection.
