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
| `bulwark.tools` | all five | Comma-separated list; validated before use. |
| `bulwark.timeoutSeconds` | 1800 | A longer scan is stopped. |

## Safety choices

- The CLI is started without a shell; the folder and tool list are separate arguments, never interpolated.
- Not supported in **untrusted workspaces** (VS Code's Workspace Trust): opening a hostile repo must not run tools.
- Paths in the results come from scanned files, so absolute or `..` paths are refused instead of opened.
- Output is read from a temp file and validated field by field; malformed findings are counted and skipped.

## What is verified

- `npm test` (44 tests): output parsing, path safety, severity mapping, CLI runner against fake executables
  (success, missing, failure, bad JSON, timeout, cancel), and the command flow against an in-memory stand-in for
  the `vscode` API.
- The built runner was run against the real `bulwark` CLI on a sample Python file: two Bandit findings came back
  at the right lines.
- **Not verified:** the extension has not been loaded into a real VS Code window (no `code` binary here and no
  automated Extension Host test yet), so the actual squiggles, Problems panel and status bar are untested by
  eye. The stand-in API can hide differences from the real one.

## Not yet

Hover detail, quick fixes, scanning on save, scanning only changed files and Marketplace packaging (Weeks 17 to 19).
Findings are full-line ranges for now, and a scan replaces all earlier results.
