import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { runScan } from "./cli";
import { newSince } from "./diff";
import { checkoutWorktree, mergeBase } from "./git";
import { atLeast, groupByFile, toSpecs } from "./mapping";
import { BulwarkHover, BulwarkQuickFix, SELECTOR } from "./providers";
import { FindingStore } from "./store";
import type { ScanOutput } from "./types";

// Not VS Code's own extension-storage API: that needs a real `vscode.ExtensionContext` at
// `activate()` time, which the lightweight test stub doesn't model. A fixed, well-known temp
// subdirectory persists across scans (and editor restarts) on the same machine just as well for
// what this cache is for -- speeding up repeated local scans, not per-workspace isolation.
const CACHE_DIR = path.join(os.tmpdir(), "bulwark-vscode-cache");

let collection: vscode.DiagnosticCollection | undefined;
let output: vscode.OutputChannel | undefined;
let status: vscode.StatusBarItem | undefined;
let running: AbortController | undefined;
const store = new FindingStore();
const REFERENCE_URL = /^https:\/\/cwe\.mitre\.org\/data\/definitions\/\d{1,6}\.html$/;

function setStatus(text: string, tooltip: string): void {
  if (!status) return;
  status.text = text;
  status.tooltip = tooltip;
  status.show();
}

async function pickRoot(): Promise<string | undefined> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) {
    void vscode.window.showWarningMessage("Open a folder first: Bulwark scans a workspace folder.");
    return undefined;
  }
  if (folders.length === 1) return folders[0]?.uri.fsPath;
  const chosen = await vscode.window.showWorkspaceFolderPick({ placeHolder: "Folder to scan" });
  return chosen?.uri.fsPath;
}

export function toolList(v: string[] | string | undefined): string {
  const all = "bandit,semgrep,gitleaks,trivy,osv-scanner";
  if (Array.isArray(v)) return v.length ? v.join(",") : all;
  return typeof v === "string" && v ? v : all;
}

/** Turns one scan result into diagnostics and the status/notification summary. `newIds`, when
 * given (plan §36's "new since the base branch"), prefixes only those findings' messages -- every
 * finding is still shown, since hiding pre-existing issues from the Problems panel would make this
 * command a worse version of an ordinary scan rather than an additional view on the same results. */
function render(root: string, result: ScanOutput, cfg: vscode.WorkspaceConfiguration, newIds: Set<string> | null): number {
  const shown = atLeast(result.findings, cfg.get<string>("minimumSeverity", "INFO"));
  const below = result.findings.length - shown.length;
  const { specs, refused } = toSpecs(root, shown);
  collection?.clear();
  const grouped = groupByFile(specs);
  store.replace(grouped);
  for (const [file, list] of grouped) {
    const uri = vscode.Uri.file(file);
    collection?.set(
      uri,
      list.map((s) => {
        const isNew = newIds?.has(s.finding.id) ?? false;
        const d = new vscode.Diagnostic(
          new vscode.Range(s.startLine, 0, s.endLine, Number.MAX_SAFE_INTEGER),
          isNew ? `[new] ${s.message}` : s.message,
          s.level as vscode.DiagnosticSeverity,
        );
        d.source = "Bulwark";
        d.code = s.code || undefined;
        return d;
      }),
    );
  }
  const newCount = newIds ? specs.filter((s) => newIds.has(s.finding.id)).length : null;
  const failed = Object.entries(result.toolStatus).filter(([, s]) => s !== "ok" && s !== "skipped");
  const notes = [
    failed.length ? `${failed.map(([t]) => t).join(", ")} did not complete` : "",
    result.skipped ? `${result.skipped} unreadable finding(s) ignored` : "",
    refused ? `${refused} finding(s) outside the folder ignored` : "",
    below ? `${below} below the severity threshold hidden` : "",
  ].filter(Boolean);
  const countLabel = newCount === null ? `${specs.length} finding(s)` : `${specs.length} finding(s), ${newCount} new`;
  output?.appendLine(`Bulwark: ${countLabel} shown${notes.length ? "; " + notes.join("; ") : ""}.`);
  setStatus(`$(shield) Bulwark: ${specs.length}`, notes.join("; ") || "Scan complete");
  void vscode.window.showInformationMessage(`Bulwark: ${countLabel}${notes.length ? ` (${notes.join("; ")})` : ""}. See the Problems panel.`);
  return specs.length;
}

async function withRun(body: (ctrl: AbortController) => Thenable<void>): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("Bulwark does not run in an untrusted workspace.");
    return;
  }
  if (running) {
    void vscode.window.showInformationMessage("A Bulwark scan is already running.");
    return;
  }
  const ctrl = new AbortController();
  running = ctrl;
  setStatus("$(sync~spin) Bulwark", "Scanning…");
  try {
    await body(ctrl);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    output?.appendLine(`Error: ${msg}`);
    setStatus("$(shield) Bulwark: error", msg);
    void vscode.window.showErrorMessage(msg);
  } finally {
    running = undefined;
  }
}

export async function scanWorkspace(): Promise<void> {
  const root = await pickRoot();
  if (!root) return;
  const cfg = vscode.workspace.getConfiguration("bulwark");
  await withRun((ctrl) =>
    vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "Bulwark: scanning", cancellable: true },
      async (_progress, token) => {
        token.onCancellationRequested(() => ctrl.abort());
        const result = await runScan({
          cliPath: cfg.get<string>("cliPath", "bulwark"),
          root,
          tools: toolList(cfg.get<string[] | string>("tools")),
          timeoutMs: cfg.get<number>("timeoutSeconds", 1800) * 1000,
          cacheDir: cfg.get<boolean>("cache", true) ? CACHE_DIR : undefined,
          signal: ctrl.signal,
          log: (line) => output?.appendLine(line),
        });
        render(root, result, cfg, null);
      },
    ),
  );
}

export async function scanChangedSinceBase(): Promise<void> {
  const root = await pickRoot();
  if (!root) return;
  const cfg = vscode.workspace.getConfiguration("bulwark");
  const base = cfg.get<string>("baseBranch", "main");
  await withRun((ctrl) =>
    vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `Bulwark: scanning (new since ${base})`, cancellable: true },
      async (_progress, token) => {
        token.onCancellationRequested(() => ctrl.abort());
        const runOpts = {
          cliPath: cfg.get<string>("cliPath", "bulwark"),
          tools: toolList(cfg.get<string[] | string>("tools")),
          timeoutMs: cfg.get<number>("timeoutSeconds", 1800) * 1000,
          cacheDir: cfg.get<boolean>("cache", true) ? CACHE_DIR : undefined,
          signal: ctrl.signal,
          log: (line: string) => output?.appendLine(line),
        };
        const commit = await mergeBase(root, base);
        const worktree = await checkoutWorktree(root, commit);
        let baseResult: ScanOutput;
        try {
          baseResult = await runScan({ ...runOpts, root: worktree.path });
        } finally {
          await worktree.dispose();
        }
        const headResult = await runScan({ ...runOpts, root });
        const newIds = newSince(headResult.findings, baseResult.findings);
        render(root, headResult, cfg, newIds);
      },
    ),
  );
}

export function activate(context: vscode.ExtensionContext): void {
  collection = vscode.languages.createDiagnosticCollection("bulwark");
  output = vscode.window.createOutputChannel("Bulwark");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = "bulwark.scanWorkspace";
  context.subscriptions.push(
    collection,
    output,
    status,
    vscode.commands.registerCommand("bulwark.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("bulwark.scanChangedSinceBase", scanChangedSinceBase),
    vscode.languages.registerHoverProvider(SELECTOR, new BulwarkHover(store)),
    vscode.languages.registerCodeActionsProvider(SELECTOR, new BulwarkQuickFix(store), {
      providedCodeActionKinds: BulwarkQuickFix.kinds,
    }),
    vscode.commands.registerCommand("bulwark.openReference", (url: unknown) => {
      // Only fixed-shape CWE links are ever opened, whatever a caller passes.
      if (typeof url === "string" && REFERENCE_URL.test(url)) void vscode.env.openExternal(vscode.Uri.parse(url));
    }),
    vscode.commands.registerCommand("bulwark.clearFindings", () => {
      collection?.clear();
      store.clear();
      setStatus("$(shield) Bulwark", "Findings cleared");
    }),
    vscode.commands.registerCommand("bulwark.showOutput", () => output?.show()),
  );
}

export function deactivate(): void {
  running?.abort();
}
