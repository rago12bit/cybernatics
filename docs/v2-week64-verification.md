# Week 64 verification: assessments, retests and collaboration (plan §43.1, §43.3, §49, §55.2)

A factual record of what was built, run and measured. The decision is
[ADR-0048](adr/0048-engagements-retests-collaboration.md). This week ends Phase 15 (Governance);
milestone M14 is assessed at the end.

## What was built

- **Assessments.** Scope, lead and testers, dates, and a lifecycle (planned, in progress, reporting,
  closed). An optional OWASP checklist: WSTG 4.2 (114 tests) or ASVS 4.0.3 at L1, L2 or L3 (128, 259
  or 278 requirements), shipped from OWASP's tagged releases with credit.
- **The engagement screen (§55.2).** Every finding the engagement's uploads reported, with what else
  reports it and where its retest stands; its tests; "Add a finding" and "Import results" into it;
  "Close and write the report". There are also a project's engagement list and the checklist page.
- **The report.** A snapshot taken on closing, downloadable as Markdown or HTML.
- **Retests.** Mark ready, confirm fixed, reproduce (with a note), or cancel. The next scan or upload
  decides for scanner Issues. A targeted retest runs one rule against one file, or one DAST template
  against one URL.
- **Notes.** Threaded, plain text, with @mentions, a Mentions page and files on notes.
- **The attachments origin is enforced** when configured; the setting is now in Compose and Helm.
- **Tags** on portfolios, projects and Issues, inherited downward, with `?tag=` on the issues table.
  A project can belong to a portfolio.
- **Migration 0036.** Four new tables, all under forced RLS, and new columns on engagements, Issues,
  assets and attachments.

## Found and fixed along the way

1. **Found by the browser run:**
   - The issue page scrolled sideways whenever an issue had a long title (Opengrep's titles are full
     sentences). Two causes: the root grid's implicit column grew to its widest line, and the title
     had no `min-width: 0`. This predated the week.
   - The targeted-retest line's long rule id widened the sidebar.
   - The tests table on the engagement screen inherited the global table-header band.
   - The portfolio dropdown was four lines tall: a flex rule meant for a row was setting its height.
   - "Fix first" on the project overview still listed an Issue a targeted retest had just confirmed
     fixed. It now skips those, as the issues table does.
   - The report named its author as a token prefix, gave UTC dates without saying so, and
     over-escaped Markdown (`api\.acme\.example`). It now names the person, labels UTC, and escapes
     only what Markdown acts on.
   - "Also found by sarif" named a parser; it now names the other Test ("Also found by Nessus").
2. **Found by the tests:**
   - A token named "Arjun K." got the handle `arjunk.`, so `@arjunk` mentioned nobody.
   - Weight sliders never reported a field error to assistive technology (Week 63; fixed then, and
     the same wiring was used here).
   - An unexpected API response would crash the whole issue page through the tags panel. Every new
     panel now checks a response's shape.
3. **Undo.** Undoing an upload did not undo the retest outcome it had decided. The undo record now
   carries the retest state.

## Checked against real systems, not mocks

- **A real targeted retest.** A sample repository was scanned by the real `bulwark/opengrep` image
  (2 findings).
  - From the Issue page, "Run the targeted retest" re-ran only rule `bulwark-py-subprocess-shell-true`
    on only `app/report.py`, on a fresh copy of the repository. The result was "still fires on
    app/report.py:5": the retest failed and the Issue stayed open.
  - After the code was fixed, the same button gave "no longer fires": the retest passed and the Issue
    was marked fixed.
  - The Issue's history records both runs.
- **A pen test end to end, in a browser against the real API** (SQLite, Next dev server, two named
  test tokens):
  - Created "Q4 external pentest" through the form.
  - Recorded a CVSS 4.0 IDOR finding through "Add a finding", which went into the engagement.
  - Imported a two-result SARIF report into a "Burp Suite" test.
  - Recorded a pass and a fail, with a note, on the WSTG checklist ("2 of 114 done").
  - Priya marked the IDOR ready for retest, with a note.
  - Arjun, signed in separately, found Priya's @mention under Mentions. He reproduced the IDOR; the
    button stayed disabled until he wrote a note.
  - Built a portfolio "Payments" with tag `pci-dss`; the project then showed it as inherited.
  - Closed the engagement with a summary. The Markdown report has the scope, team, the failed
    checklist item with its note, the three findings with reproduction steps and CVSS vector, the
    tests, and OWASP credit.
- **The attachments origin, over real HTTP.** An HTML "capture" containing a script was attached to
  a note; the server sniffed it as active content.
  - Its signed link pointed at `attachments.localhost`, which returned the bytes as
    `application/octet-stream` with `attachment`, `nosniff` and a sandbox CSP.
  - The same link on the API's own host returned 404, and the attachments host returned 404 for an
    API route.
- **Real Postgres under forced RLS**, as the worker role: all 54 integration tests pass, one of them
  new.
  - Another org sees none of the new rows (checklist results, notes, targeted runs, tags, Issues,
    engagements), cannot open the engagement by id, and its tag filter matches nothing of the first
    org's.
  - With RLS turned off on `issue_notes`, the new test fails.
- **Migration 0036 on Postgres** with two orgs' engagements:
  - Standing ci and import engagements kept "active"; an active pen test became "in progress" and a
    completed audit became "closed"; lists were set to empty.
  - Downgrade restored "active" and "completed", and upgrading again worked.
  - Its data updates, run as the worker role, change 0 rows without the org scope and 2 with it.
- **Mutation checks.** Each of these, removed, fails a test: enforcing the attachments origin, the
  author-only rule on notes, scans deciding retests, and HTML escaping in the report.
- **Totals.**
  - Backend: 2,591 unit tests pass (55 new), coverage 92%. `ruff`, `black` and `mypy` are clean,
    except one older import-order warning in `tests/unit/test_dedup_strategies.py` that also fails
    on a clean `main`.
  - Web: 307 tests (9 new, with axe checks) and `tsc` are clean.

## What this does not prove

- **People are API tokens.** A lead, a tester and a mention are names, and one person with two tokens
  is two people. Real accounts arrive in Week 75.
- **The DAST targeted retest was not run against a live target.** Its plumbing (verification first,
  egress proxy, one Nuclei template via `-id`) is tested with the runner replaced.
- **The Celery path was not run with a live worker**, for targeted retests or anything else this
  week. The task wraps the same `targeted.run` the browser exercised.
- **Downloads were checked over HTTP, not by clicking.** The download buttons for attachments and
  reports were not clicked in the browser, to avoid saving files. They call the endpoints checked
  above.
- **The Import results page was not driven through its file picker.** The import used the same
  endpoint the page calls. The page's engagement wiring is covered by its code path and tests.
- **Mention and retest notifications are outbox events only.** Delivery to Slack, email and an inbox
  is Weeks 65–66.
- **Scale.** Mentions are found by reading an org's notes, and an engagement's findings by reading
  every upload into it. Neither was measured at size.
- CI results for this commit have not been observed (nothing pushed).

## Milestone M14: Governance

The plan's test: "A pen test runs end to end inside the platform. SLAs and risk acceptance are
enforced, and every decision is in the audit log."

- **End to end.** The browser run above covered scope, findings, import, checklist, retest, notes and
  the report.
- **Enforced.** The server enforces SLAs and risk acceptance, including four-eyes approval (Weeks
  61–62).
- **Audited.** Every decision a person makes is a hash-chained audit entry. That covers triage, risk
  acceptance, SLA and priority policies, engagement changes and checklist results, retest decisions,
  notes and tags. Outcomes decided by a scan or upload are outbox events, because they are results
  rather than decisions.

M14 is met, with the limits above.
