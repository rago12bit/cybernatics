# Journey maps J1–J5 (Week 31, plan §26.2/§31)

Current-state walkthroughs of the plan's five acceptance-test journeys, against what's actually
built as of Week 30 — not the plan's aspirational v2 end state. Each entry says what happens today,
what target the plan sets (§26.2), and the concrete gap. These become Playwright end-to-end tests
once the redesign closes them (plan §31/§35), and are the task list for the baseline usability
study (docs/ux-study-protocol.md) — trimmed to what's actually walkable today.

## J1 — First scan

**Target:** land on the site, sign in with GitHub, install the GitHub App on one repository, scan
starts automatically, verdict appears. Under 2 minutes, no documentation needed.

**Today:** landing page → "Open app" → a screen asking to **paste an API token** from the server's
`.env` file (confirmed live: `/app` shows "SIGN IN / Connect to your Bulwark server / Paste the API
token..."), not GitHub sign-in. Once past that, submitting a scan (URL or archive upload) does work
and does produce a verdict-style report (severity summary, dedup rate, top-10-by-risk).

The GitHub App (Week 30) *does* now exist and *does* create an organization automatically the first
time it's installed — but it only scans on a `pull_request` event, not automatically on
installation. Installing it does not, by itself, produce a first verdict the way J1 describes.

**Gap:** no GitHub sign-in exists (the plan's identity work, §19.2, is explicitly deferred — see
ADR-0018's "what was actually built"). An install-triggered baseline scan doesn't exist either. J1
is walkable today only via the API-token path, which is a materially different first-run experience
than the one the target describes.

## J2 — Fix the first issue

**Target:** overview → top issue → explanation → review a *verified* fix → open a pull request.
Under 5 minutes.

**Today:** the overview/top-10-by-risk → finding detail → explanation chain all work (confirmed
live) and are genuinely fast. The explanation is static reference guidance from the CWE/OWASP
corpus (AI suggestions are available but off by default, per `docs/llm-remediation.md`). There is no
verified-fix step — no agent proposes, applies, or tests a patch — and nothing opens a pull request
on the user's behalf.

**Gap:** the last two steps of J2 (verified fix, auto-opened PR) are the plan's own Phase 9+
deliverable (the verified-fix agent, not yet built — see ADR-0015's scope). J2 today ends at "read
the explanation."

## J3 — Triage

**Target:** filter, move through issues with `j`/`k`, mark as not a risk with a reason or accept
risk with an expiry. 100 issues in 30 minutes.

**Today:** filtering (severity/category/scanner/path) and `j`/`k` navigation both work, confirmed
live on the real 38-finding sample scan — `j` correctly advanced from finding 5 of 38 to 6 of 38,
with the list's own highlight following it correctly (see docs/ux-heuristic-evaluation.md for the
one place this breaks: the Top 10 widget, not the main table). There is no "mark as not a risk" or
"accept risk" action anywhere in the UI.

**Gap:** risk-acceptance states don't exist as a feature yet (ADR-0012 defers them to Week 62,
matching the plan's own sequencing). J3's filter-and-navigate half is genuinely close to the target
today; its triage-*decision* half doesn't exist to test.

## J4 — Gate pull requests

**Target:** choose a policy template, test it against the last scan, enable it. Under 3 minutes.

**Today:** the GitHub Action supports one blunt severity gate (`fail-on: high`, a single CLI flag in
the workflow file) — no policy templates, no "test against the last scan" preview, no enable/disable
UI of any kind. This lives in a YAML file the repo owner edits directly, not a product screen.

**Gap:** essentially the entire journey. Policy-as-code (OPA/Rego, ADR-011 in the plan's own
numbering) is a later-phase deliverable this project hasn't reached.

## J5 — Report upward

**Target:** generate an executive summary, share a link that expires. Under 1 minute.

**Today:** per-scan export exists (JSON/SARIF/HTML/PDF), but that's a technical report for the
person who ran the scan, not an executive summary, and there is no link-sharing mechanism —
expiring or otherwise. Sharing today means sending the exported file itself.

**Gap:** the entire journey is unbuilt. Nothing to test yet.

## What this means for the baseline study

Only **J1** (partially, via the token path instead of GitHub sign-in) and **J3** (its
filter-and-navigate half) are realistically testable against today's product. §32 specifies the
baseline study covers J1–J3 — J3's testable portion should be reframed for participants as "find
and filter down to a specific finding" rather than the full target journey including risk
acceptance, and J1 as "get from the landing page to a scan result," not literally "sign in with
GitHub," since that flow doesn't exist. This is noted directly in docs/ux-study-protocol.md's task
list, not glossed over.
