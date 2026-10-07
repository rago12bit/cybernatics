# Week 77 verification: the public website (plan §57)

Done before Week 76 (the MCP server and `/fix`) at the owner's choice; nothing on the site needs
them, and the integrations catalogue is generated, so they appear on it when they exist. Week 74
(the third usability study, with five real participants) is still open, so M16 and `v2.5.0` are
not tagged.

The plan's Week 77 row: home with the recorded Juice Shop scan; how it works; security; community;
an integrations catalogue generated from parser and connector metadata; a compare page and
migration guides in both directions. §57's own text was not re-read for this week (a read of the
extracted plan was refused by the session's permission check); the work follows the plan's
week row.

## What was built

- **The recorded scan** (`scripts/record-juiceshop.py` -> `web/lib/juiceshop-demo-data.json`). One
  release, OWASP Juice Shop v17.3.0 (commit `1867b926c5f5`, image
  `bkimminich/juice-shop@sha256:123acb31ed8b...`), scanned twice by Bulwark's own code: the source by
  the default scanners (`core.scan.scan`), and the running container by a passive campaign's tools
  (ZAP baseline) behind the campaign's egress proxy (`BackgroundProxy`, allowed to reach only
  `localhost`). It replaces the Week 52 recording, which was of Juice Shop's main branch on another
  day and of the code only. The home page shows it right after the hero; `/sample` shows both
  halves with a switch.
- **Pages**: `/how-it-works`, `/integrations`, `/security`, `/compare`, `/migrate`, `/community`,
  sharing one frame and footer. Every claim about Bulwark names the file that does it; a test
  fails if a cited path does not exist.
- **The integrations catalogue** (`scripts/gen-integrations.py` -> `web/lib/integrations.json`):
  41 entries from `core.scan.ADAPTERS`, the DAST campaign's tools, `PARSERS` plus the universal
  mapper, `connectors.service.KINDS`, `tickets.config.PROVIDERS` and `notify.kinds`. The only
  hand-written words are labels for registries that carry names alone, and the test fails when
  one of those registries gains an entry without words.
- **Compare and migration**: Bulwark against DefectDojo, both ways. DefectDojo facts were checked
  against its repository on 2026-10-07 (its README, 369 directories under `dojo/tools` on master,
  BSD-3-Clause, release 3.4.0 of 2026-10-05) or against its parser code read while porting; two
  claims that could not be checked were rewritten as "not compared here". The guides' "what
  carries over / what does not" lists were read from `core/connectors/defectdojo.py` and
  `core/export/sarif.py` (one draft claim, that agreement does not travel, was wrong: SARIF carries
  `reported_by`, and it was removed).
- **Stale claims fixed**: the landing page's Roadmap still listed multi-user accounts and its
  scanner panel said "5 integrated"; the self-host page said "no user accounts yet" and "a small
  test project"; SECURITY.md said `1.x`.

## Bugs found by doing it for real

1. **A web finding's location read `:0`** in the scan report, the Issues list and the project
   overview: the label was `path:line`, and a DAST finding has neither (ADR-0041 places it by host
   and route). Seen on the recording's running-app half; fixed (`locationLabel`, `shortLocation`),
   tested.
2. **Duplicate React keys** in the findings table and "Fix these first": 79 console errors on
   `/sample`. A scanner reporting one rule twice in one place gives two findings one id. The Week
   52 recording had it too (271 "unique" findings, 241 ids). Keys now include the row's position;
   zero errors after a fresh load in the browser. The data is unchanged -- see "Not done".
3. **The running-app half claimed "raw output was not stored because secrets were found"**: the
   first version of the script marked every tool `withheld`. It now follows the product's rule
   (`core/pipeline.py`: withheld only when the scan found secrets); tested.
4. **The catalogue's search found nothing for "dast"**, the first thing typed into it in the
   browser: search did not look at categories. Fixed, tested.
5. **The header's eight links wrapped onto two lines** at 1024 px. They no longer wrap; checked at
   1024 and 980 px with no overflow, and below 960 px the menu takes over as before.
6. **The replay banner** used an inline `style` (dropped by the production CSP) and linked to
   itself as "a smaller sample".

Found and handed off, not fixed here (each is a separate task with its evidence):

- **Nuclei campaigns lose everything on a timeout.** Against the Juice Shop container Nuclei ran
  15 minutes and kept nothing: the image ships no templates, so each run downloads all of them,
  and `run_nuclei` discards the output already printed when it times out. The campaign's default
  timeout is 300 s. This is why the recording has no active tier.
- **ZAP baseline lists at most five URLs per alert, and which five changes between runs.** Three
  runs against the same container differed in about half their (alert, route) pairs, and a High
  alert (Vulnerable JS Library) appeared in two of three. Since each URL is its own Issue, the
  next campaign closes Issues that are still there.
- **A scan's "unique findings" is not its Issue count.** The recording's code half reports 139
  unique findings with 113 distinct fingerprints; the running-app half 49 with 39. The page says
  so.
- **Inline styles across app screens** (about a dozen, including the project overview chart's bar
  heights). The production CSP should drop them; not seen in a production browser here.

## Checked against real systems

- **Juice Shop, twice.** `bkimminich/juice-shop:v17.3.0` on 127.0.0.1:3000 and the same tag's
  source. Code: 154 raw -> 139 unique (bandit 0, semgrep 99 with 3 rule/file timeouts, gitleaks 47,
  trivy 8, osv-scanner skipped: no lockfile). The difference from Week 52's 104 Trivy findings is
  explained: 97 of those were Terraform challenge files on main that v17.3.0 does not have.
  Running app (final recording): 49 alerts (1 High, 10 Medium, 27 Low, 11 Info) in about 2
  minutes; the proxy refused 32 connections, to `cfu.zaproxy.org`, `tel.zaproxy.org` and
  `news.zaproxy.org` (ZAP's update checks).
- **A browser** (the app's dev server; the preview tool would not start a production build): every
  new page loaded with no console errors; the catalogue filtered by typing; `/sample` switched
  between halves and showed `http://localhost:3000/vendor.js`-style locations; at 375 px no page
  scrolls sideways and the compare table stacks; the header fits at 1024 and 980 px.
- **Playwright**: the four journeys pass on macOS; the three visual snapshots pass on Linux in
  `mcr.microsoft.com/playwright:v1.63.0-jammy` against the e2e API in `python:3.12`, on a copy of
  the repository.

## Tests

- Web: 444 tests (55 files), `tsc` clean, production build clean. New: `tests/site-pages.test.tsx`
  (no inline styles or scripts on any new page; axe on each; every cited file exists; every page
  reachable from the footer and all but the guides from the header; the catalogue lists every
  integration and filters; the recording's numbers, provenance, caveats and consistency; `/sample`
  switches halves and never prints `:0`).
- Backend: `tests/unit/test_integrations.py` (the committed catalogue is what the registries
  generate; every registry entry is listed; channel names are real modules). `ruff`, `black`,
  `mypy` (387 files) clean.
- **Mutation checks** (copy, mutate, run, restore, compare): a wrong cited path, the old
  `locationLabel`, an inline style in the banner, a hand-edited catalogue, a parser dropped from
  the generator, and the Security link removed from the header each fail a test. A cosmetic
  rewording of a caveat does not, by design.

## Not done, or not proven

- **No production build was shown in a browser**, so the CSP's effect on the site was not
  observed; the new pages emit no `style` attributes (tested), which is what matters for them.
- **Release signing is "not proven yet" on the Security page**: the release workflow's first run
  (the `v2.2.0`-`v2.4.0` tags were pushed on 2026-10-07) could not be observed from here.
- **The site is not deployed.** Nothing here publishes it; `web/fly.toml` and the demo-only build
  are unchanged.
- **The recording is one run.** ZAP's sample changes between runs; re-running the script changes
  the running-app numbers, and the page shows whatever the last run recorded.
- **The compare page's DefectDojo facts age.** They are dated, and the numbers live in one place in
  `web/app/compare/page.tsx`, but nothing re-checks them automatically.
- **Copy was not reviewed by anyone but its author.**
