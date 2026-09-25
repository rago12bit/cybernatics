/** Minimal in-memory stand-in for the parts of the `vscode` API the extension uses. */
export const state = {
  commands: new Map<string, (...a: unknown[]) => unknown>(),
  diagnostics: new Map<string, Diagnostic[]>(),
  messages: [] as { kind: string; text: string }[],
  folders: [] as { uri: { fsPath: string } }[],
  trusted: true,
  config: {} as Record<string, unknown>,
  cancelOnStart: false,
};

export class Range {
  constructor(public sl: number, public sc: number, public el: number, public ec: number) {}
}
export enum DiagnosticSeverity { Error = 0, Warning = 1, Information = 2, Hint = 3 }
export class Diagnostic {
  source?: string;
  code?: string | number;
  constructor(public range: Range, public message: string, public severity: DiagnosticSeverity) {}
}
export const Uri = { file: (p: string) => ({ fsPath: p, toString: () => `file://${p}` }) };
export enum ProgressLocation { Notification = 15 }
export enum StatusBarAlignment { Left = 1 }

export const workspace = {
  get workspaceFolders() { return state.folders; },
  get isTrusted() { return state.trusted; },
  getConfiguration: () => ({ get: <T>(k: string, d: T): T => (k in state.config ? (state.config[k] as T) : d) }),
};
const msg = (kind: string) => async (text: string) => { state.messages.push({ kind, text }); return undefined; };
export const window = {
  showWarningMessage: msg("warn"),
  showInformationMessage: msg("info"),
  showErrorMessage: msg("error"),
  showWorkspaceFolderPick: async () => state.folders[0],
  createOutputChannel: () => ({ appendLine: () => undefined, show: () => undefined, dispose: () => undefined }),
  createStatusBarItem: () => ({ text: "", tooltip: "", command: "", show: () => undefined, dispose: () => undefined }),
  withProgress: async (_o: unknown, task: (p: unknown, t: { onCancellationRequested: (cb: () => void) => void }) => Promise<void>) =>
    task({}, { onCancellationRequested: (cb) => { if (state.cancelOnStart) cb(); } }),
};
export const commands = {
  registerCommand: (id: string, fn: (...a: unknown[]) => unknown) => { state.commands.set(id, fn); return { dispose: () => undefined }; },
};
export const languages = {
  createDiagnosticCollection: () => ({
    clear: () => state.diagnostics.clear(),
    set: (uri: { fsPath: string }, d: Diagnostic[]) => { state.diagnostics.set(uri.fsPath, d); },
    dispose: () => undefined,
  }),
};
