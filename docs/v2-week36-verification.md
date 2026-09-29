# Week 36 verification — incremental scanning (plan §20.1, §36, §28.6)

Honest record of what was built, run, and measured — for Week 36: the content-addressed result
cache, pull-request-mode issue classification, the scan comparison screen, and a real measurement
of PR scan time against a full scan.

## Content-addressed result cache (§20.1)

`core/cache.py`'s `ResultCache` is disk-backed, keyed on `(tool, tool_version, ruleset_hash,
content_hash)`. File-local tools (Bandit, Semgrep, Gitleaks) are cached **per file** — a cache-miss
subset directory is built by copying (not symlinking: the sandbox mounts a directory the real
scanned tree isn't inside, so a symlink back out to it would dangle inside the container) only the
changed files, and the real tool runs against just that subset. Repo-wide tools (Trivy,
OSV-Scanner) are cached as a whole, keyed on the files that actually drive their output — Trivy's
key correctly includes Dockerfile/IaC files alongside lockfiles, since its `applies_to()` covers all
three; keying it on lockfiles alone would have served a stale result after an unrelated Dockerfile
edit.

Opt-in via `bulwark scan --cache-dir PATH`; unset, every existing test and CLI invocation behaves
exactly as before (verified: the full 894-test backend suite passed both before and after this
change with no cache-dir set anywhere in it). Tier-2 tools (Grype, Checkov, gosec, Dockle) are not
cached this week — a documented cut, not an oversight: they're opt-in, not part of any default
scan, and not on the pull-request-speed critical path this week measures.

**Wired into the GitHub Action** (`action.yml`): `actions/cache` restores/saves
`~/.bulwark-result-cache` across runs (keyed by run id, with an OS-scoped `restore-keys` prefix so
any prior run's cache is found), and both the head and the base-commit scans pass `--cache-dir`.
This is what turns `compare-base`'s extra base-commit scan — previously a second full scan on
*every single run* — into something that's usually almost entirely cache hits after the first run
on a repository.

**Not done**: wiring the cache into the hosted (DB-backed) worker pipeline
(`core/pipeline.py`/Celery). The plan's speed target is specifically about the standalone
CLI/Action path; the hosted product's own speed characteristics weren't part of this week's
deliverables, and extending caching there is real, separable future work.

## Pull-request mode and "new in this PR" (§36)

`core/issues.py`'s `classify_for_pr()` is a **read-only** counterpart to `sync()` for PR-triggered
scans: it matches a scan's findings against the asset's currently-live issues without deciding
anything is fixed. This matters because `sync()`'s `fixed_issue_ids` logic is wrong for a PR diff —
a pull request necessarily touches only some of a repository's files, so every issue elsewhere would
look "fixed" simply for not appearing in a scan that never looked at it. A fixed issue reappearing
in a PR classifies as **new**, not "open" — the base branch has no such problem, so a PR bringing it
back must still trip the gate, even though the same event is called "reintroduced" on the real
branch.

**A real bug this surfaced and fixed**: a PR-triggered scan's `Asset` was keyed on its own
`"owner/repo#42"` display label, not the repository's URL, so it never actually shared the
repository's real Issue history — every PR silently got its own throwaway asset, and "new in this
PR" would have compared against nothing every time. `core/persistence/repo.py`'s `create_scan()`
now takes an explicit `asset_label` distinct from the scan's own display label; the GitHub webhook
handler passes the clone URL, the same identity an ordinary scan of that repository already uses.
Verified end to end (`tests/unit/test_github_webhook.py`): two different PRs of the same repository,
and an ordinary scan of it, now all resolve to one `Asset` row.

**Where it shows up**:
- **API**: `ScanView.issue_counts` and each finding's `issue.state` needed no code changes to pick
  this up — they already read from `FindingRow.issue_state`, which `classify_for_pr`'s output now
  populates for PR scans the same way `sync()` already did for ordinary ones.
- **Action**: already existed (`bulwark ci compare --base`, `new-findings` output, the PR comment) —
  verified still working, now made fast by the cache above.
- **VS Code extension**: new "Bulwark: Scan (new since base branch)" command
  (`extensions/vscode/src/git.ts`, `diff.ts`). Resolves the merge-base with the real system `git`,
  scans a throwaway worktree of it alongside the workspace, and tags (not hides — every finding is
  still shown) the ones that don't match by fingerprint, the same comparison `core/ci/compare.py`
  runs in CI.

## Scan comparison screen (§28.6)

`GET /scans/{id}/compare?against={id}` (`core/persistence/repo.py`'s `compare_scans()`) categorizes
an asset's issues between any two of its own scans as new/fixed/reintroduced/unchanged, ordered by
`created_at` rather than trusting which id the caller passed first. Web UI at
`/app/projects/[id]/compare`, picking from the project overview's existing recent-scans data (no new
listing endpoint needed).

**Reduced scope, stated honestly**: the plan describes this screen "with the commit range between
them." `core/persistence/repo.py`'s `Scan` doesn't capture a resolved commit SHA today — only a git
*ref* for PR scans (`refs/pull/<n>/head`), never a specific commit. Capturing one would mean
threading a new return value through `core/gitfetch.py::clone_repo` and `core/source.py::materialize`
into every one of their ten call sites (the CLI, the worker pipeline, and eight benchmark/test call
sites) — real, bounded work, but a wider, more invasive change than this specific display detail
justified this week. The screen instead shows each scan's source label, finish time, and PR number
when there is one, which is genuinely what's available; the gap is noted in
`web/components/ScanComparison.tsx`'s own docstring rather than faked with placeholder data.

## Measured: PR scan time against a full scan (§20.1's target, §34's methodology)

`benchmarks/incremental/run.py`, real Docker, real clone, no mocking:

| Repository | Tools | Cold full scan | Warm PR scan (median of 3, 3 files changed) | Speedup |
|---|---|---:|---:|---:|
| NodeGoat | bandit, semgrep, gitleaks, trivy, osv-scanner | 71.2s | **19.6s** | **3.6x** |

Target met (under 60s) on this repository. Full numbers, methodology, and an honest explanation of
*why* the speedup is 3.6x and not closer to instant (the warm run's remaining ~17-20s is almost
entirely `core.correlation.correlate()` — cross-tool dedup over every finding, unrelated to this
week's cache and not sped up by it) are in `benchmarks/README.md`'s "Incremental scanning" section.
This is one repository with a 3-file simulated diff, not the plan §34 evaluation methodology
("replay the last 20 merged PRs of each repository in the 30-repository corpus") — that is a
separate, larger evaluation task for a later phase.

## Verified

- 904 backend tests passing before the scan-comparison work, 910 after, plus the VS Code
  extension's 91 and the web app's 150 — all passing; ruff/black/mypy clean throughout.
- The cache's per-file and repo-wide behavior verified directly (cache hit/miss counts, which files
  actually got rescanned) via `tests/unit/test_cache.py` and `test_cache_scan.py`, not just "the
  scan still produces the same findings."
- `classify_for_pr`'s non-mutation guarantee verified directly (`existing == snapshot` after
  calling it), not just its output.
- `action.yml`'s existing static checks (SHA-pinning, no shell-injection via unescaped `${{ }}`)
  needed no changes to keep passing with the new steps; two new checks added for the cache wiring
  specifically. The `actions/cache/restore`/`save` SHA was verified against the real tag on
  github.com/actions/cache, not guessed.
- The web comparison screen's populated view was **not** exercised in a live browser against a real
  backend (would need a seeded Postgres + multiple real scans) — covered instead by mocked unit and
  axe accessibility tests; the route itself was confirmed to render (sign-in gate, then the
  API-unreachable state) via `next build` and a real browser.
