# Week 72 verification: the report builder (plan §48.3)

Design: [ADR-0055](adr/0055-report-builder.md). How to use it: [Reports](reports.md).

## What was built

- **Reports from blocks.**
  - Nine kinds of block: cover, executive summary, metric, issue table, one issue in detail, risk
    acceptances, compliance mapping, engagement scope, appendix.
  - Each block's settings are checked field by field.
  - Three templates: a weekly program summary, a penetration test report, a compliance summary.
  - The builder (`/app/reports/{id}`) reorders blocks with Up and Down buttons, and each move is
    announced to screen readers.
  - Migration 0044.
- **PDF with headless Chromium.**
  - The worker renders it in a container with no network, read-only, every capability dropped,
    non-root. The page's own CSP allows only its styles.
  - The image is the Playwright image the web tests pin, by digest.
  - The API queues the run and the worker renders it, because in Compose only the worker may start
    containers.
- **Signed with cosign** when the deployment's signing key is set, as for evidence packs. Every PDF
  is kept with its SHA-256.
- **Links that expire and can be revoked.**
  - A link lasts 1 to 90 days, is shown once, and only its hash is stored.
  - Opening it needs no sign-in, and each opening is counted and audit-logged.
- **Schedules.** Weekly or monthly, at an hour in UTC. Recipients are emailed a link, never the PDF.
- **AI-drafted executive summary.**
  - A new gateway task, `report`, within the organization's AI budget. The model sees numbers and a
    few scrubbed Issue titles, marked as untrusted.
  - The draft is labelled. Nothing is generated or sent until a person confirms it with a personal
    token, and the PDF names the reviewer.

## Checked against real systems

- **Real Chromium**, in its container, on a report built to be hostile: a `<script>` tag, an
  `<img>` pointing at the internet, an instruction to an AI, Japanese and accented text.
  - The PDF's extracted text shows all of it literally.
  - The page's CSP blocked the image (Chromium's log says so), and the container has no network.
  - The four-page report below rendered in about half a second.
  - The test is `tests/integration/test_report_pdf_docker.py`.
- **Signing and checking.** I generated a throwaway cosign key pair for the test.
  - A weekly summary was generated through the UI, fetched through its link with no sign-in, and
    checked with `cosign verify-blob`: **Verified OK**.
  - The link's `X-Report-SHA256` header, the hash shown in the UI and `shasum -a 256` of the file
    agree.
  - The same PDF with eight bytes appended fails: "invalid signature".
  - One earlier attempt reported "Verified OK" for the altered copy. That was a race: the file was
    changed while Docker Desktop's file sharing still served the old copy. Re-run, it fails as it
    should.
- **Reading the PDF.**
  - Cover page; the summary with "Drafted by AI (model) from this report's data; reviewed by Priya
    N. on 2026-10-07."; SLA adherence with its counts; open issues with bars; new versus fixed;
    past SLA ("104 issues past SLA", now marked "The 10 most overdue"); advisory impact; expiring
    acceptances; the appendix with every definition and the verification command.
  - Two layout fixes came from reading it: headings now stay with their tables across a page
    break, and a partial table says it is partial.
- **A scheduled send for real.**
  - Real Chromium, then SMTP to a local Mailpit.
  - One email arrived with the report's name and date, the link, its expiry (14 days), and the
    PDF's SHA-256, with no attachment. The next run moved to Monday 08:00 UTC.
- **Postgres.**
  - Migration 0044 up, down, up. `reports` and `report_runs` are under forced RLS; `report_links`
    has none, by design.
  - The new RLS test passes, and fails when either table's policy is removed.
  - A link resolves with no organization set, and the PDF is then readable only under the link's
    organization.
- **In the browser** (development, then the production build under its nonce-only CSP):
  - creating from a template, drafting with a (clearly fake, local) model;
  - Generate staying disabled until the draft is confirmed;
  - generating, then creating a link that is shown once;
  - no CSP violations and no console errors.
  - At 375 px the builder fits once the generated-PDF card was allowed to shrink (it had pushed
    the page to 477 px).
  - No text below WCAG AA in light or dark mode: 106 elements checked.

## Tests

- **Backend:** 9 report tests (every block rendered and escaped; the AI summary flow, including a
  browser trying to forge a review; links; schedules; a queued run; a failed render; validation;
  nothing of another organization), the RLS test, and the real-Chromium test.
- **Web:** 9 tests with axe on the list, the builder, the AI flow, a new link and the schedule.
  They also cover reordering by keyboard with its announcement, and a queued run polled until done.
- **End to end:**
  - J3 now exercises the Week 62 approval flow; all four journeys pass.
  - The Linux visual baselines were regenerated in the pinned Playwright image (installing the
    project's own pinned dependencies inside a throwaway container, as approved), then re-checked
    against fresh servers.
  - After this week's "Reports" link was added, they were checked again. The one-word change is
    within the 2% pixel tolerance, so the baselines pass unchanged.

## Not done, or not proven

- **The renderer image is large** (3.2 GB, the full Playwright image). A slim image with only the
  headless shell is future work; `BULWARK_PDF_IMAGE` allows one.
- **No saved Issue views in the issue-table block.** Saved views of the Issues table live in the
  browser, so the block takes the metric filters instead. Server-side saved views are Week 73.
- **A report shows data as of when it is rendered**, over a moving "last N days". It is not a
  frozen snapshot of the period's end.
- **No real model drafted a summary**; this machine has no model key. The flow was exercised with a
  local fake that says so, and the prompt's contents are checked in the unit tests (numbers,
  scrubbed and wrapped titles).
- **Links are bearer links.** Anyone holding one can open the PDF until it expires or is revoked.
  That is what the plan asks for, and the UI says so where the link is shown.
