# Baseline usability study protocol (Week 31, plan §32)

**Status: ready to run, not yet run.** No sessions have happened; there is no participant data in
this document. This is the script — run it with five people who have never used Bulwark, a mix of
novice and experienced developers (plan §32), then fill in docs/ux-study-results-baseline.md (a
template, not written yet — create it from this session's real notes) with what actually happened.
The follow-up study (Week 35, same tasks, on the redesign) reuses this exact script so the
before/after comparison in `docs/ux-study.md` is apples to apples, per §32.

## Before each session

- Recruit: 5 participants, a mix of novice (per §26.1: doesn't know what CWE/CVSS/EPSS mean) and
  experienced (security engineer or team-lead persona) developers, none of whom have used Bulwark.
- Have ready: a running Bulwark instance with a real `BULWARK_API_TOKEN` (or the sample-scan mode,
  see Task 1's note below), a screen-recorder, and this document's task list printed or on a second
  screen for the moderator only — never shown to the participant.
- Tell the participant: "Think aloud as you go — say what you're looking at, what you expect to
  happen, and why you click what you click. There's no wrong way to do this; I'm testing the
  product, not you." Get consent to record.
- After each task: note **task success** (yes/no/partial), **time on task** (start when you finish
  reading the task aloud, stop when the participant says they're done or gives up), and ask the one
  extra question the plan specifies: *"How confident are you that this project is safe now?"*
  (1 = not at all confident, 5 = very confident).

## Tasks

Reframed from the plan's literal J1–J3 to what the current product can actually support — see
docs/ux-journey-maps.md for exactly why (no GitHub sign-in yet, no risk-acceptance UI yet). Running
the *literal* J1–J3 script against a product that doesn't have those flows would produce data about
a feature gap, not usability — noted here rather than glossed over.

**Task 1 — First scan (J1, token-path variant).** *"You've just found this tool. Get to a page that
shows you whether a project has security problems."* Success: participant reaches a completed
scan's report (the sample scan is a legitimate way to succeed here, since exploring it needs no
token — note which path they took). Target: under 2 minutes.

**Task 2 — Understand the top issue (J2, first half only).** *"Find the single most urgent thing to
fix, and explain in your own words what's wrong and why it matters."* Success: participant
correctly paraphrases the top finding's risk. Target: under 2 minutes (the plan's 5-minute J2 target
includes a verified-fix step that doesn't exist yet, so this task stops before it).

**Task 3 — Filter and triage (J3, filter-and-navigate half).** *"Show me only the HIGH and CRITICAL
findings that came from Trivy, then move through a few of them using only the keyboard."* Success:
correct filter state reached; participant discovers `j`/`k` (note whether they found it
unprompted, needed a hint after 60s, or never found it — this is the exact gap
docs/ux-heuristic-evaluation.md's finding #2 predicts). Target: no formal time target from the
plan (J3's 100-issues/30-minutes target assumes the full triage-decision feature); record time
anyway for comparison against the Week 35 follow-up.

**Task 4 — Free exploration (2 minutes).** *"Look around anywhere else you're curious about."*
Not scored for success/time; used to surface heuristic issues outside the scripted tasks.

## After all tasks: the System Usability Scale

Standard 10-item SUS (Brooke, 1986), read exactly as written, each on a 1 (Strongly disagree) to 5
(Strongly agree) scale:

1. I think that I would like to use this system frequently.
2. I found the system unnecessarily complex.
3. I thought the system was easy to use.
4. I think that I would need the support of a technical person to be able to use this system.
5. I found the various functions in this system were well integrated.
6. I thought there was too much inconsistency in this system.
7. I would imagine that most people would learn to use this system very quickly.
8. I found the system very cumbersome to use.
9. I felt very confident using the system.
10. I needed to learn a lot of things before I could get going with this system.

**Scoring:** for odd items (1,3,5,7,9), score = rating − 1. For even items (2,4,6,8,10), score = 5 −
rating. Sum all ten scores, multiply by 2.5 → a 0–100 SUS score. Average across all 5 participants
for the headline baseline number; report the spread too (SUS is noisy at n=5), not just the mean.

## Analysis and write-up

Per participant, record: task success (4/4, 3/4, ...), total time on task, the 5 confidence ratings,
the SUS score, and any direct quotes worth keeping (verbatim, attributed only as "P1"–"P5", never by
name). Across all 5: mean SUS, mean confidence, a simple heuristic-evaluation cross-check (did any
participant independently hit the issues docs/ux-heuristic-evaluation.md already predicts? That's a
useful validity check on the expert evaluation, not redundant with it).

Publish the real results in `docs/ux-study-results-baseline.md`, then the Week 35 follow-up
(identical script, redesigned product, 5 new participants) in `docs/ux-study.md` as the plan
specifies, with the two SUS numbers side by side. A redesign with a *measured* usability improvement
is the plan's own stated goal (§32) — a stronger claim than screenshots, but only if the baseline
above is real data, not filled in after the fact.
