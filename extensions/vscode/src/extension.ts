import * as vscode from "vscode";
import { runScan } from "./cli";
import { groupByFile, toSpecs } from "./mapping";

let collection: vscode.DiagnosticCollection | undefined;
let output: vscode.OutputChannel | undefined;
let status: vscode.StatusBarItem | undefined;
let running: AbortController | undefined;

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

export async function scanWorkspace(): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("Bulwark does not run in an untrusted workspace.");
    return;
  }
  if (running) {
    void vscode.window.showInformationMessage("A Bulwark scan is already running.");
    return;
  }
  const root = await pickRoot();
  if (!root) return;
  const cfg = vscode.workspace.getConfiguration("bulwark");
  const ctrl = new AbortController();
  running = ctrl;
  setStatus("$(sync~spin) Bulwark", "Scanning…");
  try {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "Bulwark: scanning", cancellable: true },
      async (_progress, token) => {
        token.onCancellationRequested(() => ctrl.abort());
        const result = await runScan({
          cliPath: cfg.get<string>("cliPath", "bulwark"),
          root,
          tools: cfg.get<string>("tools", "bandit,semgrep,gitleaks,trivy,osv-scanner"),
          timeoutMs: cfg.get<number>("timeoutSeconds", 1800) * 1000,
          signal: ctrl.signal,
          log: (line) => output?.appendLine(line),
        });
        const { specs, refused } = toSpecs(root, result.findings);
        collection?.clear();
        for (const [file, list] of groupByFile(specs)) {
          const uri = vscode.Uri.file(file);
          collection?.set(
            uri,
            list.map((s) => {
              const d = new vscode.Diagnostic(
                new vscode.Range(s.startLine, 0, s.endLine, Number.MAX_SAFE_INTEGER),
                s.message,
                s.level as vscode.DiagnosticSeverity,
              );
              d.source = "Bulwark";
              d.code = s.code || undefined;
              return d;
            }),
          );
        }
        const failed = Object.entries(result.toolStatus).filter(([, s]) => s !== "ok" && s !== "skipped");
        const notes = [
          failed.length ? `${failed.map(([t]) => t).join(", ")} did not complete` : "",
          result.skipped ? `${result.skipped} unreadable finding(s) ignored` : "",
          refused ? `${refused} finding(s) outside the folder ignored` : "",
        ].filter(Boolean);
        output?.appendLine(`Bulwark: ${specs.length} finding(s) shown${notes.length ? "; " + notes.join("; ") : ""}.`);
        setStatus(`$(shield) Bulwark: ${specs.length}`, notes.join("; ") || "Scan complete");
        void vscode.window.showInformationMessage(
          `Bulwark: ${specs.length} finding(s)${notes.length ? ` (${notes.join("; ")})` : ""}. See the Problems panel.`,
        );
      },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    output?.appendLine(`Error: ${msg}`);
    setStatus("$(shield) Bulwark: error", msg);
    void vscode.window.showErrorMessage(msg);
  } finally {
    running = undefined;
  }
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
    vscode.commands.registerCommand("bulwark.clearFindings", () => {
      collection?.clear();
      setStatus("$(shield) Bulwark", "Findings cleared");
    }),
    vscode.commands.registerCommand("bulwark.showOutput", () => output?.show()),
  );
}

export function deactivate(): void {
  running?.abort();
}
