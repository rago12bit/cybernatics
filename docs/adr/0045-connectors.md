# ADR-0045: Connectors pull through the ingest path, and never close on a pull they cannot trust

Status: Accepted (2026-10-05), Week 60 (plan §42.5, §55.7, threat T25). Builds on
[ADR-0040](0040-one-ingest-path.md), [ADR-0017](0017-github-app-integration.md) and
[ADR-0032](0032-envelope-encryption-and-crypto-shredding.md).

## Context

The plan asks for pull-based ingestion on a schedule -- GitHub code scanning and Dependabot alerts
through the GitHub App, GitLab vulnerability reports, DefectDojo in both directions -- with a health
state per connector that alerts "not only when it fails, but when it authenticates successfully and
sees no data, which is how silent misconfiguration shows up", and credentials "in OpenBao with the
narrowest scopes the source allows". Threat T25: a connector URL pointed at an internal service.

## Decision

**A pull is an import.** Each pull fetches the source's complete list of *open* items and applies it
with `apply_import` into the connector's own Test (`close_missing` on): an alert fixed or dismissed
at the source is no longer listed and is closed here. An unchanged pull has the same digest as the
last one and is a no-op. Findings are read by the same code an upload uses wherever one exists:
GitLab nodes are reshaped into security-report records and read by the GitLab report parser.

**Two pulls are never applied.**
- *A partial pull*: any failed page, a page cap exceeded (100 pages), or pagination pointing at
  another host fails the run; nothing is applied, because reimport would read the missing pages as
  "fixed".
- *An empty pull after a non-empty one* is held back: "everything was fixed at once" and "the token
  lost access" look the same from here. The run is recorded as `empty` and nothing is closed, unless
  the connector opts into `close_on_empty`.
GitLab supplied a third case on a live request: a viewer without access gets a valid page with no
vulnerabilities and `hasNextPage: true`. That is reported as a permissions error, not paged through.

**Health is a state, not a log line.** `never_run`, `ok`, `empty` (connected, fetched nothing -- worded
differently when it fetched items before), `failing` (with the reason, and an auth failure called
one), `disabled`. Failures back off exponentially (×2 up to ×16 the interval). Every run is kept
(`connector_runs`), and emits a `connector.run` outbox event for the rules and notifications to come.

**Credentials.** GitHub kinds store none: each pull mints a one-hour installation token from the App,
whose installation must belong to the connector's org; the App needs only "Code scanning alerts:
read" / "Dependabot alerts: read". GitLab and DefectDojo credentials go to OpenBao's KV store when it
is configured; otherwise into the row, and the API, the health warning and the screen all say "not
encrypted". A credential is write-only: no response contains it. Creating, changing, running and
deleting a connector is audit-logged and needs `ingest:write`.

**SSRF.** Base URLs are https, without embedded credentials, and must resolve only to public
addresses -- checked on save and again on every request, with redirects not followed. A private
instance needs `BULWARK_CONNECTOR_ALLOW_PRIVATE=1`, an explicit operator decision.

**DefectDojo out** posts the project's open Issues as SARIF (the report exporter) to `import-scan`,
then `reimport-scan` into the same DefectDojo Test with `close_old_findings`. Issues that came *from*
DefectDojo are excluded, so a pair of connectors cannot echo each other's findings.

**Scheduling.** Celery beat checks every five minutes, one organization at a time (scoped sessions,
as every cross-org job does); each due connector is its own task. "Run now" uses the same task.

## Consequences

- Dependabot does not report the installed version, only the vulnerable range; the range stands in
  for the version so a Dependabot Issue is stable, and it will not merge with an OSV-Scanner Issue
  for the same package at an exact version.
- A DefectDojo dynamic finding has its URLs in separate Endpoint objects that are not fetched; it is
  imported without a route.
- What was verified live, and what was not, is in the Weeks 59-60 verification record: the GitLab
  query against gitlab.com, and the DefectDojo round trip against a real instance (if run there);
  the GitHub endpoints only against GitHub's documented response shapes, since no App is registered.
