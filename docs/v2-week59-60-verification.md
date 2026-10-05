# Weeks 59-60 verification -- Universal mapper, manual findings, connectors (plan Phase 14, §42.4-§43.2)

Honest record of what was built, run and measured, done as four commits. Decisions:
[ADR-0043](adr/0043-universal-mapper.md) (a saved mapping is a deterministic, sandboxed parser),
[ADR-0044](adr/0044-manual-findings.md) (manual findings are an ingest source; evidence is encrypted
and only downloaded), [ADR-0045](adr/0045-connectors.md) (connectors pull through the ingest path and
never close on a pull they cannot trust).

**M13 is closed and `v2.2.0` is tagged** (2026-10-05). The round trip with a real DefectDojo, the
one item open after the first three commits, was run in a fourth -- and found two bugs that every
recorded-shape test had passed (below).

## What was built

| # | Commit | Result |
|---|---|---|
| 59.1 | Universal mapper | `MappingSpec` + a small path language; `UniversalParser` streams in the parser sandbox; sample analysis in the sandbox; drafts by the model (checked against the sample) or by name matching; versioned, tenant-isolated mappings (migration 0030); the **Map a format** screen; saved mappings offered on the import screen |
| 59.2 | Manual findings | CVSS 4.0 (`cvss` library); CWE picker; routes from code intelligence (`scans.entrypoints`, migration 0031); correlation to automation's taint path; evidence sniffed, encrypted with OpenBao, downloaded only through a signed link; the **Record a finding** form and a panel on the issue page |
| 60 | Connectors | GitHub code scanning and Dependabot (GitHub App), GitLab (GraphQL), DefectDojo in and out; SSRF-guarded client; health, backoff, run history (migration 0032); Celery beat; the **Connectors** screen |
| M13 | DefectDojo round trip | Run against DefectDojo 3.3.300; two connector bugs fixed; `tests/integration/test_defectdojo_live.py`; a recorded page of real findings as a unit-test fixture |

## The DefectDojo round trip (M13)

DefectDojo **3.3.300** (the latest release, 2026-09-28), from its own `docker-compose.yml` with the
images pinned to that tag, on `localhost:8180`; an API v2 key minted for its admin user inside the
container. `tests/integration/test_defectdojo_live.py` runs Bulwark's real API, connector service and
HTTP client (with its SSRF guard, private hosts allowed) against it; it makes fresh products each run.

| Direction | What happened |
|---|---|
| **In** | DefectDojo's own parsers imported a Bandit, an Anchore Grype and a ZAP report (DefectDojo's sample files) into a product: 13 active findings. The import connector pulled all 13 in 6 requests (the product, then five pages of 3 -- the test's page size; Bulwark asks for 100 -- by DefectDojo's own `next` links) and made 13 Issues -- code, package and web findings each read as such: file and line, package and CVE, severity. Pulled again: the same pull, not applied twice. A finding closed in DefectDojo (`active: false`) was closed in Bulwark on the next pull. |
| **Out** | A project's 3 open Issues (a real Semgrep SARIF) were exported: DefectDojo created the product, engagement and a "Bulwark Scan (SARIF)" Test, with the 3 findings on the same files and lines. Bulwark then closed one; the next export reimported into the same Test and DefectDojo closed it there: 2 active. |
| **Back** | That product pulled into a second project: 2 Issues on the files, lines and severities they left from, and none of them exported again (no echo). |
| **Screen** | The Connectors screen against the same instance: the export and import connectors Healthy (2 sent, 12 pulled, "12 new, 0 reopened, 0 closed"), and a connector for a product that does not exist Failing with "DefectDojo product 424242: not found (HTTP 404)". A wrong key: "the credential was refused (HTTP 403)". |

### Bugs the round trip found (every recorded-shape test had passed)

1. **The import connector pulled every product's findings.** DefectDojo's findings API ignores a
   filter it does not know, and `?product=<id>` -- what the connector sent, and what the documented
   example shapes could not reveal -- is not one: each of three products returned all 39 findings of
   the instance. A connector for one product would have imported every product its key can read. The
   filter is now `test__engagement__product`; the product is fetched first (a wrong id is a 404, not
   "fetched nothing"); and every finding is asked for with its `related_fields`, so one from another
   product refuses the whole pull. Checked live: with the old filter put back on the wire, the guard
   refuses ("finding 1 from outside product 7 ... nothing was imported").
2. **The export could not create its product**: HTTP 400, "Product ... does not exist and no
   product_type_name provided". It now sends a product type (default "Bulwark", settable on the
   screen), and a 4xx's reason now reaches the connector's health instead of a bare "HTTP 400".

Also from the real data: newer DefectDojo lists CWEs in `cwes` (`[{"cwe": "CWE-614"}]`, where ZAP's
is; the old `cwe` field was 0), now read; and `fix_version` becomes the remediation. One real page --
a Bandit, a Grype and a ZAP finding as DefectDojo 3.3.300 returns them -- is now a unit-test fixture
(`tests/golden/connectors/defectdojo-3.3.300-findings-page.json`), so CI checks the real shape.

After the fixes: 2,438 unit tests pass (4 skipped, coverage 92%), 274 web tests, the three live
round-trip tests; `ruff`, `black`, `mypy` (272 files) and `tsc` clean. Versions are 2.2.0 in
`pyproject.toml` and `web/package.json` (both had stayed at 2.0.0 through `v2.1.0`; the changelog's
2.1.0 section is now separated out too).

### Found, not fixed here

- On SQLite (the scratch and end-to-end servers) timestamps lose their time zone, so the screen read
  a run from seconds earlier as "6 hours ago" in IST. Postgres keeps the zone; this affects every
  screen on SQLite, not connectors, and is queued as its own task.

## M13, item by item

- **"At least 15 formats."** The plan's own list (§42.2, "Order of work") counts "generic JSON and
  CSV through the universal mapper" as one item, beside SARIF, CycloneDX, SPDX, OSV and the ported
  tool formats. Built: SARIF, CycloneDX (JSON and XML), SPDX, OSV, ZAP, Burp, Nuclei, Nessus,
  OpenVAS, Grype, Trivy, Snyk, GitLab security reports, Checkov (14 parsers), and generic JSON, CSV
  and XML through saved mappings: **15 by the plan's count.** (Without the mapper it is 14.)
- **"3 connectors."** Five kinds are built (GitHub code scanning, GitHub Dependabot, GitLab,
  DefectDojo in, DefectDojo out). Only DefectDojo has run against a live instance with data; see
  below for what that leaves unproven about the others.
- **"Deduplication can be changed per source with a dry run"** -- Week 58 (ADR-0042).
- **"A round trip with a real DefectDojo instance is recorded"** -- above.

## Bugs found and fixed along the way (Weeks 59-60)

1. **Correlation dropped a copied taint path.** `correlate()` rebuilds each finding without its
   `taint_path` (scans attach theirs later, in `finalize`), so the path a manual finding inherited from
   automation vanished. Found by its own test; now attached after preparation.
2. **The issue page could not open an Issue only an import or a person reported** -- "issue not found
   in the latest scan", for every imported Issue since Week 54. Found driving the manual finding flow in
   a browser. It now shows the Issue's most recent occurrence from any source; regression test added.
3. **GitLab hides what a viewer cannot read instead of refusing.** A live, anonymous request to gitlab.com
   returned a valid page with no vulnerabilities and `hasNextPage: true`. The connector would have paged
   through a hundred empty pages and then failed with a misleading message. It is now reported as a
   permissions error on the first page (the real response is a fixture).
4. Three tests that task 1 should have updated (the model gateway's task list, the fuzz matrix) were
   caught by the full suite and fixed in the next commit -- the task 1 commit ran only a subset.
5. Layout: the mapper's path inputs were unreadably narrow, and CVSS options wrapped into the label
   column; both found by looking at the screens, both fixed.

## Validated against real, live things -- not mocks

- **CVSS 4.0 against FIRST's own calculator.** Eight vectors (9.3, 7.1, 5.3, 1.0, 8.1 with `E:U`, 8.7,
  7.0, 6.3) scored on first.org/cvss/calculator/cvsscalc40; the library agrees on all eight and they are
  fixed in `tests/unit/test_manual_findings.py`.
- **GitLab against gitlab.com.** The exact connector query ran against gitlab.com without a schema error;
  every field it selects is checked against an extract of gitlab.com's published GraphQL schema
  (`tests/golden/connectors/gitlab-schema-extract.json`). A connector with a bad token, run against
  gitlab.com through the real client and SSRF guard, reported "the credential was refused (HTTP 401)".
- **The real parser sandbox (Docker).** A mapped report of 200 records parses to the same findings in
  the container as in-process; sample analysis is identical in both; a mapped XML report with an entity
  is refused inside the container (36 sandbox tests pass).
- **Real Postgres under Row-Level Security**, as the non-superuser worker role, migrated to 0032: 50
  integration tests pass, including new ones for mappings, manual findings and evidence, and connectors
  and their runs. Undoing the import that recorded a manual finding removes the finding and its evidence
  through the foreign-key cascade (which SQLite tests cannot exercise).
- **Fuzzing.** Atheris in a Linux container, 60 s each: `universal-json` 151,760 runs, `universal-csv`
  134,698, `universal-xml` 140,086, `analyze` 324,935; no crash or hang. The four targets joined the
  nightly matrix.
- **A real browser against the real API** (local API with the real Docker sandbox, Next dev server):
  a JSON sample was described in the sandbox, drafted, edited (rule, a custom severity), previewed live
  (1.2 s per preview), saved, suggested on the import screen ("Closest match: Acme scanner (95%)") and
  imported ("Imported: 4 new"). A manual IDOR finding was scored 7.1 by the calculator, placed on its
  route's handler, linked to the seeded opengrep finding and its taint path, and shown on the issue page;
  its disguised HTML evidence was listed as `text/html`, "can contain script", and its signed download
  carried `attachment`, `nosniff`, a sandbox CSP and `no-store`; a forged link got 404. The Connectors
  screen showed a failing GitLab connector (HTTP 401) and a GitHub one ("the GitHub App is not
  configured"), with the verdict naming both.
- **Mutation checks.** Removing the empty-pull hold-back, or the GitLab empty-page check, fails a test;
  the taint-path fix and the issue-page fix were each found by a failing test or screen first.
- Backend: `ruff`, `black`, `mypy` (272 files) clean; 2,432 unit tests pass (4 skipped), coverage 90%.
  Web: 273 tests, `tsc` clean.

## What this does NOT prove (read before relying on it)

- **One DefectDojo version.** The round trip ran against 3.3.300 only. Older versions name the same
  things differently (`cve` and `vulnerability_ids` are both read); a version without
  `related_fields` would now be refused rather than trusted. DefectDojo's Endpoints (a web
  finding's URLs) are still not fetched, so a DAST finding from DefectDojo has no route.
- **No GitHub App is registered here**, so the GitHub connectors were never run against GitHub. They are
  tested against response shapes taken from GitHub's documented examples. Dependabot does not report
  the installed version, so a Dependabot Issue uses the vulnerable range and will not merge with an
  OSV-Scanner Issue for the same package.
- **GitLab was reached, but never with a token that can read a vulnerability report** (that needs
  GitLab Ultimate). The mapping of real nodes is tested on nodes shaped from the schema.
- **The mapping assistant's prompt was not evaluated** (no local model here); its eval set exists
  (`core/llm/prompts/mapper/`). The draft's safety does not depend on its quality: every path is
  checked against the sample, a person saves the mapping, and imports never call a model.
- **Without OpenBao, connector credentials and evidence are stored unencrypted** (the API and the screen
  say so), the same posture as scan artifacts. Encrypted paths are tested with a fake OpenBao, not a
  live one in this run.
- **Download links are signed with a deployment-wide key** (`BULWARK_LINK_SECRET`, else derived from the
  API token), not a per-org key; serving them from a separate origin is configuration, not shown here.
- **"15 formats"**: there are 14 built-in parsers reading more than 20 file layouts, plus any number of
  saved mappings. Whether mappings count toward the milestone is a judgment call; they are not counted
  here.
- **CI results for these commits have not been observed** (nothing pushed), and the one web test run that
  showed 10 failures under load did not reproduce on three re-runs.
