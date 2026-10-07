# Reports

Build a report from blocks, generate a signed PDF, share it by a link that expires, or have it
sent on a schedule (plan §48.3, [ADR-0055](adr/0055-report-builder.md)).

## Blocks

| Block | What it shows |
|---|---|
| Cover | Title and subtitle; the organization, the period and when it was generated are added. |
| Executive summary | A person's text, or a model's draft that a person has reviewed (below). |
| Metric | Any [dashboard metric](metrics.md), with the same filters: portfolios, projects, a tag, the last N days. |
| Issue table | Open Issues, Issues past their SLA, or Issues first seen or fixed in the period; by priority; up to 200 rows. |
| One issue in detail | Its project, location, severity, priority, state, dates, CWE and description. |
| Risk acceptances | In force, awaiting a decision, or expiring within 30 days. |
| Compliance mapping | One framework's controls with the evidence Bulwark holds for each, as in [evidence packs](compliance.md). |
| Engagement scope | A pen test or audit's targets, routes, out-of-scope note, people and dates. |
| Appendix | The definition of every metric used, and how to check the PDF's signature. |

Three templates start you off: a weekly program summary for leads, a penetration test report, and
a compliance summary. Each report covers "the last N days" (1 to 366), so a schedule always reports
on the latest period.

## The executive summary

Write it yourself, or choose **Draft with AI** (when a model is set up for the `report` task: see
`BULWARK_LLM_ROUTE_REPORT` and [the model gateway](llm-remediation.md)). The model sees the report's
numbers and at most five Issue titles per table. Those come from scanned code, so they are scrubbed
of anything that looks like a secret and marked as untrusted data, never instructions. Drafting
counts against the organization's AI budget.

A draft is labelled as AI-written. **Nothing is generated or sent until a person confirms it**,
edited or not. The PDF then says, above the summary, "Drafted by AI (model) from this report's
data; reviewed by (name) on (date)." Drafting and confirming need a personal token, because the
reviewer's name is printed.

## Generating, signing and sharing

**Generate PDF** queues the report, and the worker renders it with headless Chromium. Chromium runs in
a container with no network, a read-only file system, every capability dropped and a non-root
user. The page itself allows nothing but its own styles, so nothing in an Issue's title can load
or run. The image is Microsoft's Playwright image, pinned by digest; set `BULWARK_PDF_IMAGE` to use
a mirror with the same layout.

Each PDF is kept as it was, with its SHA-256. When `BULWARK_EVIDENCE_SIGNING_KEY` is set (the same
cosign key as evidence packs), it is signed too. To check a copy:

```bash
cosign verify-blob --key cosign.pub --bundle report.pdf.sig --insecure-ignore-tlog report.pdf
```

**Create a link** makes a link that opens the PDF without signing in, for 1 to 90 days. It is shown
once; only its hash is stored. Every link can be revoked, each opening is counted and audit-logged,
and the signature is at the link plus `/signature`.

## Schedules

A report can be generated weekly (a weekday) or monthly (a day from 1 to 28), at an hour in UTC,
and each recipient (up to 20) is emailed a link to it, never the PDF itself. The worker checks every
five minutes. Scheduled emails need `BULWARK_SMTP_*` and `BULWARK_API_PUBLIC_URL`, the API's public
address; without them the report is still generated, and the run says why nothing was sent. A
report whose AI summary nobody has confirmed is not sent.

Every change, generation, link and send is in the audit log.
