# ADR-0048: Assessments, retests and collaboration

Status: Accepted (2026-10-06), Week 64 (plan §43.1, §43.3, §49, §55.2, threat T24). Builds on
[ADR-0039](0039-portfolio-engagement-hierarchy.md) (engagements and tests),
[ADR-0040](0040-one-ingest-path.md) (imports), [ADR-0044](0044-manual-findings.md) (manual
findings and evidence) and [ADR-0046](0046-sla-and-risk-acceptance.md).

## Context

Milestone M14 asks that "a pen test runs end to end inside the platform". Until now an engagement
was only a container for tests, with a name, a type and dates. A tester could record findings and
import a tool's report into one, but had nowhere to keep the scope, the people or a checklist, and
had no retest, no notes and no report. Issues could not carry tags. Evidence downloads had a
configurable origin, but nothing stopped them being served from the API's own host.

## Decision

**An assessment is any engagement but the standing "ci" and "import" ones.** It gains a scope
(targets, routes, an out-of-scope note), a lead and testers, start and end dates, an optional OWASP
checklist, and a lifecycle: planned → in progress → reporting → closed. Reporting can go back to in
progress, and a closed one can be reopened. Older assessments map onto it (active → in progress,
completed → closed). People are names, or API token names, until user accounts exist in Week 75.
Every change is a hash-chained audit entry.

**Checklists are OWASP's own data, pinned.**
- WSTG 4.2 has 114 tests.
- ASVS 4.0.3 has 128 requirements at L1, 259 up to L2 and 278 up to L3.
- Both ship as JSON taken from the projects' tagged releases, with ids and text unchanged.
- Both are CC BY-SA 4.0, credited in the licence notices, on the checklist screen and in the report.
- Only entries someone touched get a row; "done" means passed, failed or not applicable.

**An engagement's findings are every Issue its uploads reported**, not only each test's latest
snapshot. Each manual finding is its own upload, so a snapshot holds just the last one. Findings
fixed during the test therefore stay in its report. Where another source reports the same Issue, the
engagement says so ("Also found by Opengrep taint", or another test's name), which is §55.2's
cross-source correlation where the tester works.

**Closing writes the report as a snapshot.** It is stored as JSON on the engagement and rendered on
download as Markdown or HTML. A later change to an Issue never rewrites a delivered report. Every
outside value is escaped for its format:
- HTML is fully escaped, and the page allows no script and no remote loads.
- Markdown is HTML-escaped, because viewers render embedded HTML. The characters Markdown acts on
  are backslash-escaped. With brackets escaped, no link or image can form.

This is a fixed engagement template. The report builder with editable templates is Week 72.

**Retest is a short workflow on the Issue.**
- *Requested.* A developer marks the Issue ready for retest.
- *Passed.* A tester confirms it fixed, and the Issue becomes fixed. It reopens as "reintroduced"
  if anything reports it again.
- *Failed.* A tester reproduces it and must write a note; the Issue stays open.

For a scanner's Issue, the next scan or upload is the retest. The shared Issue writer
(`repo.apply_reimport_plan`) decides any requested retest: "still reported by…" or "no longer
reported by…". These outcomes are outbox events in the same transaction, not audit entries, because
they are a scan's results rather than a person's decision. Undoing the upload undoes the outcome.

**A targeted retest re-runs one check at one location.**
- *A rule.* Check out the default branch afresh, copy only the Issue's file to an empty directory at
  the same path, and run only the tool that found it, in its usual sandbox with the whole
  repository's language context. The Issue is still present if a finding has its fingerprint, or if
  the same rule fires on the same file.
- *A DAST template.* Run only that Nuclei template, or ZAP's passive baseline keeping only that
  alert, against that one URL. This happens only if ownership verification still passes, and goes
  through the campaign egress proxy.

A run has its own row (`retest_runs`), never a scan, so it cannot become "the latest scan" or close
another Issue. It runs on the worker, or in the API process when there is no worker. It is not
offered for an Issue only a person or an imported report found.

**Notes are plain text, threaded one level deep.**
- @mentions resolve to the organisation's live personal tokens by handle (the name lowercased,
  punctuation trimmed). Each person mentioned gets an outbox event and finds the note under
  Mentions. An edit announces only people newly added.
- Only the author edits or deletes. Deleting keeps the row, so replies stay in context, but removes
  the body and the files.
- Files on notes use the evidence store: content-sniffed, encrypted with OpenBao, downloaded only
  through a short-lived signed link.

**The attachments origin is enforced.** With `BULWARK_ATTACHMENTS_ORIGIN` set, that host serves only
signed downloads, and only those: everything else there is a 404. The API's own host refuses those
downloads, and no response on the files host sets a cookie. Without the setting, downloads come from
the API host, which sets no cookies either; the separate origin is defence in depth for a file
someone opens anyway.

**Tags inherit downward.** A tag on a portfolio applies to its projects, and a project's tags apply
to its Issues; an Issue's own tags are added on top. A project now belongs to at most one portfolio,
through a new `assets.portfolio_id`. Inherited tags are shown with where they come from and are
changed there. The issues table filters by a tag wherever it was set, in SQL.

## Consequences

- "Another person" is another API token until Week 75: a lead, a tester and a mention are names.
- An Issue a person or a targeted retest confirmed fixed leaves the issues table and the
  fix-first queue, even though the last scan's rows still list it.
- Mentions are found by reading the organisation's notes. That is fine at this size but is not
  indexed.
- A targeted retest of a rule that depends on other files (cross-file analysis) sees only the one
  file. For the per-file rules Bulwark ships, that is the same answer as a full scan.
- Notifications for mentions and retests are outbox events only. Delivering them to Slack, email
  and an in-app inbox is Weeks 65–66.
