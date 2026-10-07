# ADR-0055: Reports rendered by sandboxed Chromium in the worker, signed, shared by revocable links

Status: Accepted (2026-10-07), Week 72 (plan §48.3). Builds on [ADR-0054](0054-metrics-layer.md)
(metrics), [ADR-0053](0053-vex-compliance-evidence.md) (compliance mappings, cosign signing of
evidence packs) and [ADR-0013](0013-tenancy-row-level-security.md) (RLS).

## Context

Plan §48.3 asks for:

- reports built from blocks (cover, executive summary, metric widget, issue table, issue detail,
  risk acceptances, compliance mapping, engagement scope, appendix), with templates and schedules;
- PDFs rendered with headless Chromium, signed with cosign, and shared through links that expire
  and can be revoked;
- an executive summary the model can draft, "labelled as AI-written and edited before sending".

The existing PDFs (scan reports, evidence packs) use ReportLab, whose built-in fonts are Latin-1
only.

## Decision

**Chromium, in a container, in the worker.**
- A report is one self-contained HTML document. Every value is escaped, and the page's own CSP
  allows only its inline styles and `data:` images.
- Chromium's headless shell prints it to PDF in a container with:
  - no network;
  - a read-only root filesystem;
  - all capabilities dropped and no new privileges;
  - the image's non-root user;
  - limits of 1 GB memory and 256 processes.
- Chromium's own sandbox is off because it needs privileges the container withholds, so the
  container is the sandbox.
- Even if a scanned Issue title contained live HTML, it would print as text, and nothing could
  load or post anything.
- The image is `mcr.microsoft.com/playwright:v1.63.0-jammy`, pinned by digest: the version the web
  tests already pin, and already present wherever the Playwright tests run.
- Only the worker may start containers (in Compose the API has no Docker access, by design). So the
  API *queues* a run (`report_runs.status = queued`) and the worker renders it. A failure is
  recorded on the run, never retried in a loop. Schedules run in the worker anyway.

**Signed like evidence packs.**
- Each PDF is kept as generated, with its SHA-256.
- When `BULWARK_EVIDENCE_SIGNING_KEY` is set, cosign signs the PDF itself, offline with no
  transparency log, the same as evidence packs. The bundle is downloadable next to the PDF and
  next to any link.

**Links: a token, only its hash, no RLS on that one table.**
- A link is 256 random bits, shown once, with its SHA-256 stored in `report_links` along with its
  expiry (at most 90 days) and revocation.
- `report_links` carries no RLS, for the reason `api_tokens` carries none (migration 0007):
  following a link is what tells Bulwark the organization, so the lookup cannot need it first.
- The row holds no report content. Every other query filters by `org_id` in code, and the PDF is
  read from `report_runs`, under forced RLS, only after the link has set its organization.
- Opening a link is counted and audit-logged. Responses are `no-store`, `noindex` and
  `no-referrer`.

**The summary: drafted from numbers, reviewed by a named person.**
- The model is a new gateway task, `report`, routed and budgeted like the others. It sees each
  metric's value and counts, and at most five Issue titles per table, scrubbed of anything that
  looks like a secret and wrapped as untrusted data.
- The draft is stored as `source: ai` with the model's name. The server owns those fields; a save
  from the browser cannot claim a review.
- Generating, by hand or on a schedule, is refused until a person confirms the summary with a
  personal token.
- The PDF prints "Drafted by AI (model) from this report's data; reviewed by (name) on (date)."

**Schedules email a link, not a file.**
- Weekly or monthly, at an hour in UTC, to at most 20 recipients. The link lasts what the schedule
  says (default 14 days).
- The beat task runs every five minutes.
- Without SMTP or `BULWARK_API_PUBLIC_URL`, the report is still generated, and its run records why
  nothing was sent.

## Consequences

- PDFs render Unicode, and reports look like the screens (the same CSS shapes, inline SVG bars).
  Rendering a four-page report takes about half a second on a warm Docker daemon.
- A deployment needs the renderer image (3.2 GB, mostly the browsers Playwright ships), pulled
  once by the worker. A slimmer image holding only the headless shell would be smaller. That is
  future work, and `BULWARK_PDF_IMAGE` already allows it.
- The issue-table block takes the metric filters (portfolio, project, tag, period, priority).
  Saved views of the Issues table are kept in the browser (`web/lib/saved-views.ts`), so a report
  cannot use them yet. That needs server-side saved views (plan §56, Week 73).
- A report shows the data as of when it is rendered, not as of the end of its period: "the last N
  days" is a moving window. The appendix says what each number counts.
