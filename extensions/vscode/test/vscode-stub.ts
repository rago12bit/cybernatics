/** Minimal in-memory stand-in for the parts of the `vscode` API the extension uses. */
export const state = {
  commands: new Map<string, (...a: unknown[]) => unknown>(),
  diagnostics: new Map<string, Diagnostic[]>(),
  messages: [] as { kind: string; text: string }[],
  folders: [] as { uri: { fsPath: string } }[],
  trusted: true,
  config: {} as Record<string, unknown>,
  cancelOnStart: false,
  opened: [] as string[],
  hover: undefined as unknown,
  actions: undefined as unknown,
};

export class Range {
  constructor(public sl: number, public sc: number, public el: number, public ec: number) {}
  get start() { return { line: this.sl, character: this.sc }; }
  get end() { return { line: this.el, character: this.ec }; }
}
export enum DiagnosticSeverity { Error = 0, Warning = 1, Information = 2, Hint = 3 }
export class Diagnostic {
  source?: string;
  code?: string | number;
  constructor(public range: Range, public message: string, public severity: DiagnosticSeverity) {}
}
export const Uri = {
  file: (p: string) => ({ fsPath: p, toString: () => `file://${p}` }),
  parse: (u: string) => ({ fsPath: u, toString: () => u }),
};
export enum EndOfLine { LF = 1, CRLF = 2 }
export class MarkdownString { isTrusted: boolean | undefined; supportHtml: boolean | undefined; constructor(public value: string) {} }
export class Hover { constructor(public contents: MarkdownString) {} }
export const CodeActionKind = { QuickFix: "quickfix" };
export class CodeAction {
  edit?: WorkspaceEdit; command?: { command: string; title: string; arguments?: unknown[] }; diagnostics?: Diagnostic[];
  constructor(public title: string, public kind: string) {}
}
export class WorkspaceEdit {
  edits: { uri: unknown; range: Range; text: string }[] = [];
  replace(uri: unknown, range: Range, text: string) { this.edits.push({ uri, range, text }); }
}
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
export const env = { openExternal: async (u: { toString(): string }) => { state.opened.push(u.toString()); return true; } };
export const languages = {
  registerHoverProvider: (_s: unknown, p: unknown) => { state.hover = p; return { dispose: () => undefined }; },
  registerCodeActionsProvider: (_s: unknown, p: unknown) => { state.actions = p; return { dispose: () => undefined }; },
  createDiagnosticCollection: () => ({
    clear: () => state.diagnostics.clear(),
    set: (uri: { fsPath: string }, d: Diagnostic[]) => { state.diagnostics.set(uri.fsPath, d); },
    dispose: () => undefined,
  }),
};
