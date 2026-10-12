# GitHub Action

Runs Bulwark on every push and pull request. It uploads SARIF to **Code Scanning**, comments the findings a pull
request **introduces**, and fails the check at a severity you choose.

```yaml
name: Bulwark
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # upload SARIF to Code Scanning
  pull-requests: write    # the PR comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rago12bit/cybernatics@main   # pin a release tag or commit SHA once one is published
        with:
          fail-on: high
```

## Inputs

| Input | Default | |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `tools` | all five | Comma-separated scanners. |
| `fail-on` | `high` | `none`, `low`, `medium`, `high` or `critical`. On a pull request only **new** findings count. |
| `upload-sarif` | `true` | Needs `security-events: write`. |
| `comment` | `true` | Needs `pull-requests: write`. |
| `sbom` | `false` | Also write a CycloneDX 1.6 SBOM (output `sbom-file`); upload it with `actions/upload-artifact` if you want to keep it. |
| `compare-base` | `true` | On pull requests, also scan the base commit so only new findings are reported and gated. |
| `github-token` | `github.token` | Used only for the comment. |
| `python-version` | `3.12` | |

Outputs: `new-findings`, `total-findings`, `sarif-file`, `sbom-file` (empty unless `sbom` is `true`).

## How "new" is decided

The action scans the pull request and the base commit (a second checkout of the base SHA) and compares the two by
Bulwark's **fingerprint**, the stable defect identity from correlation. A finding that only moved lines or was
reported by a different set of scanners is not new. The comment also says how many findings already existed and how
many the change fixed.

If the base cannot be scanned, or a scanner failed on the base (which would make its findings look new), Bulwark
does not guess: it lists and gates on **all** findings and says so in the comment.

On a push there is no baseline; the threshold applies to every finding.

## What happens on failure

Upload and comment run **before** the check fails, so a red run still shows the findings. The upload step is allowed
to fail (forks, missing permissions) without hiding the gate result; the comment is skipped with a warning when
the token cannot write. The run summary always contains the same table.

## Ignoring paths: `.bulwarkignore`

Put a `.bulwarkignore` at the scan root (see this repository's own for an example): one glob per line, `#` for
comments. `tests/fixtures/` (anchored at the root), `fixtures/` (any directory of that name), `*.lock`, `docs/**/*.md`.
Ignored findings are dropped from the report **but counted**, and the count appears in the comment and JSON
(`stats.ignored_findings`), so ignoring is never silent.

**A change cannot hide its own findings.** On pull requests the action reads the ignore file from the **base**
commit and passes it to both scans; a `.bulwarkignore` added or edited by the pull request has no effect until it is
merged (checked by running the action's scan step against a real repository whose head tried to ignore its own new
file). If the base commit cannot be fetched, nothing is ignored. On pushes the file in the checkout applies.

## Security notes

- Use the `pull_request` trigger. **Do not use `pull_request_target` with a checkout of the PR head**: that runs
  untrusted code with a write token.
- **Fork pull requests** get a read-only token: the scan and the gate work, the comment and SARIF upload are
  skipped.
- Inputs reach shell steps only through `env:`, never interpolated into the script, so a branch name or input
  value cannot become code (checked by a test). Third-party actions are pinned to commit SHAs.
- Only the one comment authored by `github-actions[bot]` that carries the Bulwark marker is ever updated; a user
  quoting the marker cannot redirect the update. Every scan-derived string in the comment is escaped: no links,
  images, HTML or `@mentions`.
- The scanners run in sandboxed containers (see the threat model). The action builds their images on the runner
  (about 2 to 4 minutes on a cold runner) and pulls Gitleaks from Docker Hub.
- It uses `actions/cache` v6 and `github/codeql-action` v4, which run on Node 24: a self-hosted runner needs
  version 2.327.1 or later. GitHub-hosted runners already are.

## Not yet

- It has **not been run on GitHub**. Its logic was checked by running the exact step scripts locally against a
  real git repository with a base and a head commit (the base worktree was scanned, only the new finding was
  reported, the gate failed), by unit tests, and by static checks of `action.yml`. Expect first-run surprises around
  runner permissions and Docker.
- No image caching, so every run rebuilds the scanner images.
- Marketplace listing is a manual step: see [releasing.md](releasing.md).
