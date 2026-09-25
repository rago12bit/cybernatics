# Bulwark for VS Code (early scaffold)

Runs the `bulwark` CLI over a workspace folder and shows the results as VS Code diagnostics: they appear in the
**Problems** panel, grouped by file, with the CWE (or rule id) as the code and the reporting scanners and risk
score in the message.

## Use

1. Install Bulwark so `bulwark` is on your PATH (from the repo root: `pip install -e .`) and have Docker running:
   the scanners run in sandboxed containers.
2. Build and load the extension (not published to the Marketplace yet):
   ```bash
   cd extensions/vscode && npm install && npm run build
   ```
   then in VS Code run **Developer: Install Extension from Location...** and pick this folder, or press F5 with
   this folder open to start an Extension Development Host.
3. Command Palette: **Bulwark: Scan Workspace**. A scan takes from seconds to several minutes; cancel it from
   the progress notification. **Bulwark: Clear Findings** removes the diagnostics.

## Settings

| Setting | Default | Notes |
|---|---|---|
| `bulwark.cliPath` | `bulwark` | Machine scope: a workspace's `.vscode/settings.json` cannot change which program runs. |
| `bulwark.tools` | all five | List of scanners to run (empty means all); validated before use. |
| `bulwark.minimumSeverity` | `INFO` | Findings below it are hidden, and the scan summary says how many. |
| `bulwark.timeoutSeconds` | 1800 | A longer scan is stopped. |

## Hover and Quick Fix

- **Hover** a squiggle for severity, risk score and why, description, CWE/OWASP, fix summary, references and which
  scanners reported it. The text comes from scanned files and rule metadata, so it is escaped and shown as untrusted
  markdown (no HTML, no command links).
- **Quick Fix** (lightbulb or Cmd/Ctrl + .): **apply scanner-suggested fix** and **open CWE reference**.
  Suggested fixes today come from Semgrep rules that define an autofix (for example `shell=True` to `shell=False`);
  many findings have none. A patch is offered only when its context and removed lines match the editor's current
  text exactly, so editing the file after a scan can remove the option but never corrupts it. Always review the
  change: a rule's fix can be wrong for your code (a command that genuinely needs a shell, for instance).

## Safety choices

- The CLI is started without a shell; the folder and tool list are separate arguments, never interpolated.
- Not supported in **untrusted workspaces** (VS Code's Workspace Trust): opening a hostile repo must not run tools.
- Paths in the results come from scanned files, so absolute or `..` paths are refused instead of opened.
- Output is read from a temp file and validated field by field; malformed findings are counted and skipped.

## What is verified

- `npm test` (80 tests): output parsing, path safety, severity mapping and threshold, the patch matcher, hover
  escaping, CLI runner against fake executables (success, missing, failure, bad JSON, timeout, cancel), and the
  command, hover and Quick Fix flow against an in-memory stand-in for the `vscode` API. Deliberately breaking six
  safety checks (patch matching, ambiguity, markdown escaping, untrusted markdown, link allow-list, https-only
  references) each made a test fail.
- The built runner was run against the real `bulwark` CLI on a sample Python file: findings came back at the right
  lines, and Semgrep's real autofix for `shell=True` reached the extension as a patch that planned the correct
  one-line edit against the real file.
- **Not verified:** the extension has not been loaded into a real VS Code window (no `code` binary here and no
  automated Extension Host test yet), so the actual squiggles, Problems panel and status bar are untested by
  eye. The stand-in API can hide differences from the real one.

## Not yet

Scanning on save, scanning only changed files and Marketplace packaging (Weeks 18 to 19).
Findings are full-line ranges (the scanners report lines, not columns), diagnostics do not move as you edit and are
only refreshed by a new scan, and a scan replaces all earlier results. AI-generated patches are not produced by
the CLI yet; the extension already handles them if a finding carries one.
