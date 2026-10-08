# Third usability study protocol: journeys J6–J10 (Week 74, plan §58)

**Status: ready to run, not yet run.** No sessions have happened and there is no participant data
here. This is the moderator's script. Results go in [ux-study.md](ux-study.md), produced from the
session notes by `scripts/ux-study-score.py`, never typed in by hand.

The plan's study: five participants who work in **security leadership or penetration testing**,
journeys J6–J10 (plan §53.1), the System Usability Scale plus time on task. The earlier two studies
([ux-study-protocol.md](ux-study-protocol.md): baseline and follow-up on J1–J3) were also never run,
so this one has nothing to sit beside yet; ux-study.md says so.

## Recruiting

- Five people: at least two pen testers (J9 is theirs) and at least two security leads or managers
  (J7, J8, J10). Nobody who has used Bulwark or helped build it.
- 45 minutes each, remote with screen share or in person. Offer the same thank-you to everyone.
- Consent (read aloud, record the answer): *"We'll record the screen and your voice to see where the
  product is hard to use. Nothing you say is attributed to you by name -- you're P1 to P5 in the
  write-up. You can stop at any time."*

## Setting up an instance

Use the same data for every participant. From a clean checkout:

```
python scripts/e2e_server.py --port 8800 --web-origin http://localhost:3800   # throwaway API
(cd web && NEXT_PUBLIC_API_URL=http://localhost:8800 npm run dev -- --port 3800)  # the app
python scripts/ux-study-seed.py                                              # the scenario
```

Then open http://localhost:3800/app. (Not ports 8000 and 3000: a developer's own Bulwark usually has
those, and the scenario must never be seeded into real data.)

`e2e_server.py` is the real API on a throwaway SQLite database; it stands in only for scanner
containers, the parser sandbox, the advisory feeds and GitHub's Issues API (its docstring lists
them), none of which a participant sees. Restart all three before each participant, so nobody
starts from someone else's leftovers. `ux-study-seed.py` prints the token the participant signs in
with, the approver token for J8, and the path of the report file for J6. (Against a real deployment
instead, pass `--api` and set `BULWARK_TOKEN`; it seeds through the public API only.)

Have ready: the participant's token, the Nessus file from the seed output on the participant's
desktop, a timer, the observation sheet (`docs/ux-study-data/sessions.csv`), and this script on a
screen the participant cannot see.

## Running a session

Say: *"Think aloud as you go -- what you're looking at, what you expect, why you click. I'm testing
the product, not you. I can't help with the tasks, but I'll tell you if you're stuck for long."*

For each task, read the task text exactly, start the timer when you finish reading, stop it when the
participant says they're done or gives up. Record success as `yes`, `partial` or `no`. If someone is
stuck for 3 minutes, give the one hint listed and record `hint` in the notes; the task can then be
`partial` at best. Write down every quote worth keeping, verbatim.

| Task | Read aloud | Success | Hint after 3 min | Plan target |
|---|---|---|---|---|
| **J6** Import | *"Your team ran Nessus against the external hosts. Bring that report into the payments-api project and tell me what will change before you commit to it."* | Imported, and the participant could say how many issues were new before pressing Import | "The project page has an Import tab." | under 1 minute |
| **J7** New-CVE morning | *"A critical Log4j vulnerability, CVE-2021-44228, was announced this morning. Find out which of our projects use log4j-core, how exposed they are, and get it in front of the owners."* | Reached the advisory's impact view and created the Issues (and the ticket where configured) | "Try Components, or Advisories." | under 5 minutes |
| **J8** Risk acceptance | *"The AWS key finding in payments-api was rotated, but the team wants to accept the risk on the old key for 30 days. Request that. Then, as Priya, approve it."* (Hand over the approver sign-in for the second half.) | Requested with a justification and expiry; approved by the second person | "Open the issue itself." | under 3 minutes for each person |
| **J9** Pen test | *"You're starting an external pen test of storefront. Set it up, record these five findings from your notes, close it and get the report."* (Hand over the printed list of five findings from the seed output.) | Engagement created, five findings recorded, closed, report downloaded | "The project has an Engagements tab." | under 3 minutes per finding |
| **J10** Monthly report | *"Your CISO wants a summary of the security program on the 1st of every month, by email. Set that up."* | A report saved with a monthly schedule and a recipient | "Look under Reports." | under 5 minutes the first time |

After each task ask: *"On a scale of 1 to 5, how confident are you that you did that right?"*

## After all tasks: the System Usability Scale

The standard ten items (Brooke, 1986), read exactly, each from 1 (strongly disagree) to 5 (strongly
agree) -- the same wording as [ux-study-protocol.md](ux-study-protocol.md). Record the ten answers.

Then two open questions: *"What was the hardest moment?"* and *"What would make you use this
instead of what you use today?"*

## Recording

`docs/ux-study-data/sessions.csv`, one row per participant per task:
`participant,role,task,success,seconds,confidence,hint,notes`

`docs/ux-study-data/sus.csv`, one row per participant: `participant,q1,...,q10`

Then:

```
python scripts/ux-study-score.py
```

It checks the files, scores SUS (odd items: answer - 1; even items: 5 - answer; sum x 2.5), and
rewrites the results section of ux-study.md: SUS per participant with the mean, median and range
(five people is a small sample; the spread matters as much as the mean), success and median time per
task against the plan's targets, and the confidence ratings. Quotes and the problems found are
written into ux-study.md by hand, from the notes, attributed P1-P5 only.

## What already changed because of these journeys

Writing J6–J10 as Playwright tests (Week 74) found eight problems before any participant did; they
are fixed, and listed in [v2-week74-verification.md](v2-week74-verification.md). The study should
not count those as findings.
