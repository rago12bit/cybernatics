# Importing reports

Bulwark can take findings from tools it does not run: a SARIF file from CodeQL, a CycloneDX file with
a `vulnerabilities` section, a scan from another scanner. It is one endpoint, and **importing is
reimporting with an empty history**: the first upload into a *Test* creates everything; every later
one is compared with the previous one and tells you what changed.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -F project=$PROJECT_ID \
  -F file=@codeql.sarif \
  $BULWARK/v2/ingest
# 202 {"import_id": "...", "status": "queued", "parser": "sarif", "confidence": 0.99, ...}

curl -H "Authorization: Bearer $TOKEN" $BULWARK/v2/imports/$IMPORT_ID
# {"status": "applied", "counts": {"new": 38, "unchanged": 212, "reopened": 4, "closed": 17, ...}}
```

The call returns `202` at once; a worker reads the file and applies it. Poll `GET /v2/imports/{id}`
until `status` is `applied`, `previewed` or `failed`.

## Formats

| Parser | Reads | Produces findings from |
|---|---|---|
| `sarif` | SARIF 2.1.0 | `runs[].results[]` |
| `cyclonedx` | CycloneDX JSON or XML | `vulnerabilities[]`, each resolved to the component it `affects` |
| `osv` | OSV-Scanner JSON | `results[].packages[].vulnerabilities` |
| `spdx` | SPDX 2.x JSON | nothing: see below |
| `zap` | OWASP ZAP XML or JSON report | each `alertitem`, one finding per URL it was seen at |
| `nuclei` | Nuclei JSONL or JSON array | each result, one finding per matcher that fired |
| `burp` | Burp Suite XML issue export | each `<issue>` |
| `nessus` | Nessus `.nessus` XML; Nessus Pro and Tenable.io CSV | each plugin on each host and port |
| `openvas` | OpenVAS / Greenbone XML or CSV | each result (an NVT on a host and port) |
| `grype` | Grype JSON (`-o json`) | each match, read by the same function a Grype scan uses |
| `trivy` | Trivy JSON: image, filesystem, repository, Kubernetes (both layouts), the old bare list | vulnerabilities, misconfigurations and secrets; licences are counted, not imported |
| `snyk` | `snyk test --json` (Open Source and Container), one project or a list | each vulnerability, severity from its CVSS score |
| `gitlab` | GitLab security reports: SAST, dependency, container, secret detection, DAST, API fuzzing | each record, classified by where it is (file, package, URL) |
| `checkov` | Checkov JSON, one framework or a list | each failed check, read by the function a Checkov scan uses |

The format is detected from the file; if detection is not confident (below 90%) the call is refused
with the candidates and you pass `parser=` yourself. `GET /v2/parsers` lists what is available.

**A package list is not a clean bill of health.** An SBOM (any SPDX file, or a CycloneDX file with no
`vulnerabilities` section) lists what is *in* a project, not that it is free of vulnerabilities. So
such a file imports no findings and **can never close anything**, even with `close_missing=true`
(the import says so in its `warnings`).

### Ported parsers (DefectDojo)

`zap`, `nuclei`, `burp`, `nessus`, `openvas`, `grype`, `trivy`, `snyk`, `gitlab` and `checkov` are derived from [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)'s
parsers (BSD-3-Clause; the notice is in `THIRD_PARTY_LICENSES.md`) and are tested against DefectDojo's
own sample reports and the results its tests expect. Three things differ on purpose:

- **One finding per place.** DefectDojo folds a ZAP alert hit at fifty URLs into one finding with
  fifty endpoints. Here each URL is its own finding and its own Issue (ADR-0041), so fixing one place
  closes that place and not the others. Counts after an import are of Issues, so they are higher than
  DefectDojo's for the same file.
- **An unknown severity is Info**, and the import says how many findings it applied to. (DefectDojo's
  Nuclei parser makes it Low.)
- **An empty Nuclei file closes nothing.** Nuclei writes an empty file when it finds nothing, but an
  empty upload is also what a failed export looks like, so an empty file imports nothing and is
  refused the right to close (with a warning). Export JSON (`-json-export`), which writes `[]`, to
  record a clean run.

Request and response bodies in a ZAP or Burp report are not stored; the finding keeps the method,
parameter, attack, evidence and one line each of the request and response.

Three more differences in the vulnerability scanners: **Trivy licence findings are not imported**
(DefectDojo makes a finding of each); **Snyk Code is SARIF**, so upload it with `sarif`; and
**one vulnerability in one package at two paths is one Issue** (its Issue is package, version and
vulnerability; each path keeps its own finding). A Trivy report is also shown the CVSS score of the
source that decided its severity, not always NVD's.

**GitLab:** one parser for GitLab's five report types. A record is classified by its location (a
dependency is a package, a hostname a web target, a commit a secret, a file with lines code), because
v15 reports leave `category` out; GitLab's own `id` is not an identity (it is recomputed); an
Unknown or Undefined severity is Info and the title says so; coverage-fuzzing crashes, which have no
place in code or on the web, are skipped and counted. **A DAST finding's place is host and route, not
HTTP method**: `GET` and `DELETE` of one URL with the same check are one Issue (ADR-0041).

**When a scanner report may close Issues.** A report is evidence of what was fixed only if the scan
finished and reached something, so these close nothing (the import says so in its `warnings`):
an OpenVAS scan whose `scan_run_status` is not `Done`, an OpenVAS or Nessus report that scanned no
hosts, and a CSV with a header and no rows. An OpenVAS export made with a severity filter
(`levels=hm`) is imported with a warning, because what the filter hides will read as fixed.
A CSV cut exactly between two rows cannot be told from a shorter CSV; any other cut is an error.

**A report that covers fewer hosts than the last one will list the missing hosts' Issues as closed.**
Closing is scoped to the Test, not to the hosts a report covers, and the preview shows the count
before anything is saved -- so read "closed" before you confirm, or import each scan range into
its own Test.

Burp reports start with an internal `<!DOCTYPE issues [<!ELEMENT ...>]>`; the `burp` parser admits
that and nothing more (an entity declaration or an external DTD is still refused).

## Where it goes

A **Test** is the thing a later upload is compared with. By default an upload goes into the project's
standing `import` engagement, in a Test named for the format. Name it yourself to keep tools apart:

```bash
curl ... -F project=$PROJECT_ID -F test="Nessus external" -F file=@scan.sarif $BULWARK/v2/ingest
curl ... -F project=$PROJECT_ID -F engagement_type=assessment -F engagement_name="Q3 pentest" ...
curl ... -F test_id=$TEST_ID ...            # into an existing Test
```

`engagement` takes an engagement id within the project. Other organisations' ids read as not found.

## What the four counts mean

| Count | Meaning |
|---|---|
| `new` | matches no Issue yet: a new Issue is created |
| `unchanged` | matches a live Issue |
| `reopened` | matches a fixed Issue: it is back (state `reintroduced`) |
| `closed` | the previous upload had it, this one does not, `close_missing` is on, and **no other source still reports it**: the Issue becomes `fixed` |

`detached` is a fifth number: Issues this file stopped listing that stay open because another source
(a scan, another Test) still reports them. They are not fixed, so they are not "closed".

`close_missing` (default true) closes what this Test's previous upload had and this one lacks.
`scope=test` (default) considers only this Test, so one tool's report cannot close another tool's
findings; `scope=engagement` considers every Test in the engagement.

## Preview before you commit

`-F preview=true` parses and counts but saves nothing and keeps the file; the import ends in
`previewed` with the counts and the reopened and closed Issue ids. Then
`POST /v2/imports/{id}/confirm` applies it, or `POST /v2/imports/{id}/cancel` discards it. A
preview nobody confirms is cancelled, and its file deleted, after 24 hours. The
preview and the import are the same computation, so the counts do not differ.

## Safety

- **The same file twice is a no-op.** Uploading a file identical to the Test's latest import returns
  `200` with the original's id and `duplicate: true`.
- **A file that cannot be read completely is refused, never applied.** Closing what a file no longer
  lists means a truncated file would look like "everything was fixed", so a truncated, malformed or
  over-limit file ends in `failed` with the reason and changes nothing.
- **Parsing happens in the scanner sandbox**: no network, read-only filesystem, no capabilities, a
  throwaway container. XML with a DTD or entities is refused outright.
- **Secrets are never stored.** A secret finding's snippet and any quoted value in its text are
  replaced before the finding is saved.
- **The most recent import into a Test can be reverted** (`POST /v2/imports/{id}/revert`). Issues are
  restored only if nothing has changed them since; anything newer is left alone and reported as
  `skipped`.
- Limits: `BULWARK_MAX_UPLOAD_BYTES` (default 100 MB), 64 levels of nesting, 60 s of parsing,
  500 000 findings per file. `BULWARK_INGEST_SANDBOX=0` parses in the worker instead of a container;
  that is for tests and local development only.

## Permissions

Importing needs the `ingest:write` scope and reading needs `ingest:read`. They are separate from
`scans:write` on purpose: an import can close Issues, which starting a scan cannot.
