# Dogfooding: Bulwark scanning Bulwark

The **Bulwark self-scan** workflow (`.github/workflows/bulwark.yml`) runs the action on this repository. On pull
requests it fails on **new** findings of severity HIGH or critical; findings already on `main` do not count. On pushes it
reports and uploads SARIF only. It has not yet run on GitHub; everything below is from running the same CLI locally.

## First scan of this repository (2026 Week 19, all five scanners completed)

| | Findings |
|---|---|
| First scan, no ignore file | 1,191 unique (4 critical, 81 high, 52 medium, 1,054 low) |
| After `.bulwarkignore` (183 hidden, counted) | 1,010 (0 critical, 31 high, 27 medium, 952 low) |

The 183 hidden findings are the deliberately vulnerable scanner test fixtures, saved raw scanner outputs, one
old lockfile kept to seed the OSV database, the OWASP/CWE corpus text, and three test files that need realistic-looking
fake secrets. Each entry in `.bulwarkignore` says why.

## What it found and what was done

- **Real bug in Bulwark itself:** scanning an ordinary working directory that contains `node_modules` or a
  virtualenv failed with "target exceeds max total size". The workspace copy now skips installed dependencies,
  tool caches and virtualenvs (lockfiles are still scanned). This affected the VS Code extension too.
- **Real dependency advisories:** the extension's dev tooling (vitest 2.1.9 with vite 5.4 and esbuild 0.21) carried
  1 critical, 1 high and 5 medium advisories. Upgrading to vitest 4 leaves the extension's lockfile with none.
- **Literal bidirectional-control characters in source** (`core/ci/report.py`, `core/llm/contract.py`, two tests):
  the sanitising regexes contained the raw characters, which Bandit flags as a Trojan Source pattern. They are now
  written as `\uXXXX` escapes, so the source is clean and behaviour is unchanged.
- **SHA-1 used for a sampling id** (`core/llm/evaluation.py`): not a security use; marked `usedforsecurity=False`.
- **Missing feature:** there was no way to say "these paths are test inputs", which the self-scan needed, so
  `.bulwarkignore` was added (with the rule that pull requests cannot ignore their own findings).

## What remains (31 HIGH), and why it is not "fixed"

Most of what is left is scanner noise, which is exactly what a triage layer should be for:

- 23 findings only Semgrep reports: for example "function defined inside a function but never used" on
  FastAPI route handlers registered by decorators, `time.sleep` in retry code, `innerHTML` in web tests, and "use
  defusedxml" on XML written by our own PDF code.
- 4 that Bandit and Semgrep both report: `subprocess` calls with argument lists (no shell) and SQL text assembled
  from fixed fragments with bound parameters. Bandit alone rates none of them HIGH; the merged finding takes the
  higher severity.
- 3 Gitleaks findings on a local, git-ignored `.env` (not present in a CI checkout).
- 1 Trivy finding: the Postgres image's build stage runs as root (the final image is the upstream one).

None was judged a vulnerability, but that is a manual judgment with no ground truth. They stay visible and will
not block anyone: the gate only counts findings a pull request adds. **A reviewer should still look at the SQL
built with `text()` in `core/rag/store.py` and the migration string concatenation**: both use only fixed fragments
and bound parameters today, which is why they were not changed, but a scanner cannot tell that.

## Limits of this exercise

- One repository, one run, no comparison with what a human reviewer would flag.
- Counting findings measures noise as much as risk. The number that matters is whether a pull request introducing a
  real HIGH issue would be caught; that was shown on a small synthetic repository, not on this one.
