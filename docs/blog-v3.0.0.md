# Bulwark 3.0: three things a security platform has to get right

> **Draft (Week 78, plan §59).** Written before `v3.0.0` is tagged; the tag waits for the third
> usability study (M16), which needs five real people. Every number links to the record of how it was
> measured. Nothing here is a claim the evaluation ([evaluation-v3.md](evaluation-v3.md)) does not
> back.

Version 2 found vulnerabilities and helped fix them. Version 3 manages them: imports from tools
Bulwark doesn't run, SLAs, risk acceptance with a second person, a rules engine, an SBOM inventory,
advisory matching, VEX, compliance, dashboards, reports, single sign-on, an MCP server and `/fix` on
pull requests. Most of that is plumbing every platform has. Three parts are where a platform can quietly
be wrong in a way that costs someone, so they get the space here.

## 1. Reimport must never close what it didn't look at

Importing a report is easy. Reimporting it -- the same tool, a week later -- is where platforms
hurt people: the Issues the new file no longer lists get closed. If the file was cut off, or came from
a different scope, or another tool still sees the problem, that closure is false, and a real
vulnerability leaves the queue looking fixed.

Bulwark treats reimport as the default (import is reimport with an empty history) and makes
closing the thing that has to earn its way in:

- **A file that can't be read completely closes nothing.** Every parser streams and reports whether
  it reached a real end. A Hypothesis property test cuts every vendored report at random points and
  requires each cut to be either refused or unable to close
  ([Week 54](v2-week54-verification.md)). That test kept finding things: in Week 76 a Nessus CSV cut
  right after a quoted field read as a whole row, and the follow-up found the same for a cut after an
  empty field. Since then every cut of every vendored Nessus and OpenVAS CSV has been checked -- 199,038
  of them -- and none can close an Issue; before, 29 dropped or garbled a finding and could still close
  it. A CSV whose last row has no line break is read but closes nothing, because a real Tenable export
  ending that way can't be told from a cut one.
- **Another source keeps an Issue open.** A finding no longer in this Test's file but still reported
  by a scan or another Test is *detached*, not closed, and the preview says how many.
- **You see the four numbers before anything is saved** -- new, unchanged, reopened, closed -- with
  the reopened ones listed by id. The same file twice is a no-op; the latest import can be undone.
- **Checked against ground truth, not examples.** Random import sequences into two Tests are compared,
  count by count, with an independent set-arithmetic oracle; every deliberate regression tried --
  ignoring other sources, ignoring "don't close", widening the close scope, swallowing truncation
  errors, letting an SBOM close Issues, removing the row lock, and six more -- makes the tests fail.

What this doesn't show: the sequences are generated, not a corpus of real reimport histories.

## 2. Advisory matching must not miss

"Which of our projects use this library at an affected version?" is only useful if the answer has no
false negatives. Version ranges are where that goes wrong: every ecosystem orders versions its own
way, and OSV records mix ranges with explicit version lists.

Bulwark matches with OSV's semantics, per ecosystem, and was checked against osv-scanner on the same
data: OSV's dumps for PyPI, npm, Go and Maven, and SBOMs built from the hardest versions to get right --
every range boundary for up to 1,000 packages per ecosystem
([evaluation-advisory-matching.md](evaluation-advisory-matching.md)).

**21,619 of 21,721 package versions agree (99.5%), and osv-scanner never reports an advisory Bulwark
misses.** In all 102 differences Bulwark reports more, and each is explained: 80 are Go modules with
capital letters, which osv-scanner lowercases and then cannot find. The check runs Bulwark twice --
the function, and the stored answer after a real inventory import -- so the database is checked, not
only the code.

What this doesn't show: boundary versions are adversarial on purpose, not a sample of real SBOMs.

## 3. "Not affected" needs evidence

A VEX statement that says `not_affected` tells customers they can ignore a CVE. If it's wrong, it's
worse than no statement. So Bulwark never writes one on its own:

- For Go, it proposes `vulnerable_code_not_in_execute_path` only when the advisory names the
  vulnerable functions and the project's code does not call them, and it attaches where it looked.
  For Python and JavaScript, the weaker claim: the package isn't imported by application code.
- **A person confirms each proposal** with their own token; confirming dismisses the matching Issue
  with the justification, and reopening withdraws it.
- The screen never says "unreachable": the call graph is unsound in known places, so it says "no call
  path found".
- Exports are OpenVEX v0.2.0 and CycloneDX 1.6, validated against their schemas; OpenVEX's own `vexctl`
  merged a Bulwark document and filtered a SARIF file with it, dropping the `not_affected` CVE and
  keeping the affected one ([Week 69](v2-week69-verification.md)).

What this doesn't show: the plan's measure -- a blind review of 100 proposals by someone who didn't
build it -- **has not been done.** The review kit is ready (`scripts/vex-review-kit.py`); until it's
used, the share of correct `not_affected` claims is unknown.

## What else was measured, and what wasn't

From [evaluation-v3.md](evaluation-v3.md), with the method next to every number:

- 10 parsers ported from DefectDojo agree with its own expected results on 156 sample files, except
  12 recorded differences and 2 deliberate refusals.
- Ingest: 2,400 Nessus findings a second end to end on a 95 MB file; SARIF 3,700 a second.
- Parser safety: 669,000 fuzzing runs, no crash or hang; XXE, entity expansion and depth bombs refused.
- Dashboards: every widget under 300 ms at p95 over a million Occurrences, on Postgres under RLS.
- SSO: 13 of 13 SAML attack cases refused, each for its own reason.
- Rules: one OPA evaluation at p95 15 ms -- but the plan's load test was not run.

**Not measured:** deduplication accuracy (it needs hand-labelled duplicate pairs), the VEX blind
review, and the third usability study's SUS and time on task (it needs five security leads or pen
testers). Each is "not measured" in the table, with the reason, rather than left out.

## Try it

```bash
git clone https://github.com/Rag2102/cyberimp
cd cyberimp && ./scripts/init-env.sh
docker compose --profile scanners build && docker compose up -d
# http://localhost:3000
```
