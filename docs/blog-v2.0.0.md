# Bulwark 2.0.0: from a scanner pipeline to a platform

v1.0.0 answered one question: given five scanners' worth of overlapping noise, what's the deduplicated,
risk-ranked list of things actually worth fixing? That shipped 26 weeks ago. v2.0.0 is another 26 weeks
on top of it, and it answers a different question: once you have that list, what actually closes it
out — and can the thing producing the list survive being used by more than one person, on more than
one machine, for more than a week? Here's what changed, what I measured, and what I'm still not
claiming.

## From findings to fixes

The single biggest gap in v1.0.0 was that it stopped at the list. v2.0.0's flagship feature is the
**verified-fix agent**: it proposes a patch, then actually checks its own work — reruns the rule that
triggered, reruns every scanner, runs the project's own test suite — and only then opens a real GitHub
PR for a human to approve. An LLM suggesting a diff is cheap and has been possible for a while; an LLM
suggesting a diff that's been mechanically proven not to break anything else is a different, much
smaller claim, and it's the one v2.0.0 actually makes.

Two more LLM-backed features sit next to it, both scoped narrower than they could be, on purpose: a
**triage assistant** that gives a "likely false positive" verdict a human can override, never a
silent suppression; and a **hypotheses lane** that finds exactly one pattern deterministic scanning
can't — a route missing the authorization check its siblings have — then asks a model to confirm it
against real code before showing it to anyone. Both are narrow because a false "this is fine" from a
security tool is worse than a missed finding, and I'd rather ship a feature that does one thing
honestly than five things that half-work.

## Correlation didn't stop being the point — it got deeper

v1.0.0's correlation merged duplicate *findings*. v2.0.0 adds a layer underneath that: **taint
analysis** that confirms whether a SAST finding is actually *reachable* from a real HTTP entrypoint,
not just present somewhere in the code. The distinction matters in practice, not just in theory — on a
real scan of OWASP Juice Shop, Semgrep's plain pattern rule flags any `eval()` call it sees; the taint
engine additionally confirms that in three specific cases, the argument demonstrably comes from the
request body. That's a materially stronger claim than "this function exists," and it's the kind of
signal the risk score now folds in alongside EPSS and CISA KEV.

**Ranking** is still a scoring question, and I still don't have a result I'm willing to oversell: the
risk score beats severity-only ordering at every top-K I've measured, but the confidence interval on
that difference includes zero. I'm reporting that plainly in [docs/evaluation-v2.md](evaluation-v2.md)
rather than quietly dropping the caveat because it's two years old now.

## The part that isn't about features at all

Multi-tenancy with Postgres Row-Level Security, a stable Issue/Occurrence data model (so "fixed" and
"returned" are real states instead of a guess from diffing two reports), a hash-chained audit log, mTLS
between every internal service, envelope-encrypted scan data with crypto-shredding on deletion, a gVisor
sandbox option, and authorized DAST (ownership verification before a URL can be scanned, a
scope-enforcing egress proxy *actually wired into* campaign execution, not just configured and left
unused — a gap I found and closed in the same week I found it). None of this is a "feature" a user
clicks on. All of it is the difference between a weekend project and something you'd trust with a
second organization's data.

## What I actually measured

Full method and every caveat: [docs/evaluation-v2.md](evaluation-v2.md).

| Measure | Result |
|---|---|
| Taint engine: hand-verified precision on a real spot-check (NodeGoat) | 3/3, zero false confirmations |
| Ranking: top-20 precision, risk score / severity-only / random | 63.3% / 52.4% / 48.2% (CI includes 0) |
| Scale: p95 latency (scan submission / results browsing) | 675ms / 1.84s |
| Platform security: ASVS 4.0.3 Level 2 self-audit | complete, 3 findings fixed |
| Red-team: structural-defense pass rate | 60/60 adversarial payload x contract combinations rejected |
| Incremental scanning: warm vs. cold PR scan (1 repo) | 3.6x faster |

The honest gaps, stated the same way v1.0.0's were:

- **No human-measured usability improvement.** The UX overhaul (new design system, new screens, a
  verdict-first project overview) is real and shipped. The before/after SUS study that would prove
  it's actually *better*, not just different, needs real participants and hasn't been run. I'm not
  fabricating that data to round out a launch post.
- **Five evaluation rows need a live model and aren't measured**: the verified-fix agent's acceptance
  rate and blind human review, the triage assistant's and hypotheses lane's precision/recall against
  labelled ground truth, Copilot's citation accuracy, and a real attack-success-rate for the red-team
  suite (its *structural*-defense pass rate is measured; a live model actually trying to be persuaded
  is a different, harder thing I haven't funded yet).
- **The taint-engine number above is a spot-check, N=3, one repository** — real and hand-verified, not
  a corpus-scale study.
- **Still one shared bearer token for most API auth.** Multi-user identity is explicitly a v3 item.

## Try it

```bash
git clone https://github.com/Rag2102/cyberimp
cd cyberimp && ./scripts/init-env.sh
docker compose --profile scanners build && docker compose up -d
# http://localhost:3000 -- the first screen is now a replay of a real scan of OWASP Juice Shop
```

Source, docs, and the full evaluation writeups: <https://github.com/Rag2102/cyberimp>. A technical
report on correlation, taint-based ranking, and verified fixes, written for people who want the method
rather than the pitch, is at [docs/technical-report-v2.md](technical-report-v2.md).
