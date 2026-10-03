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

The format is detected from the file; if detection is not confident (below 90%) the call is refused
with the candidates and you pass `parser=` yourself. `GET /v2/parsers` lists what is available.

**A package list is not a clean bill of health.** An SBOM (any SPDX file, or a CycloneDX file with no
`vulnerabilities` section) lists what is *in* a project, not that it is free of vulnerabilities. So
such a file imports no findings and **can never close anything**, even with `close_missing=true`
(the import says so in its `warnings`).

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
`POST /v2/imports/{id}/confirm` applies it, or `POST /v2/imports/{id}/cancel` discards it. The
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
