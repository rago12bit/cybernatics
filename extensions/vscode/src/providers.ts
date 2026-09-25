import * as vscode from "vscode";
import { cweUrl, hoverMarkdown } from "./hover";
import { planEdits } from "./patch";
import type { FindingStore } from "./store";
import type { BulwarkFinding } from "./types";

const SELECTOR: vscode.DocumentSelector = { scheme: "file" };

export class BulwarkHover implements vscode.HoverProvider {
  constructor(private store: FindingStore) {}

  provideHover(doc: vscode.TextDocument, pos: vscode.Position): vscode.Hover | undefined {
    const found = this.store.at(doc.uri.fsPath, pos.line);
    if (found.length === 0) return undefined;
    const md = found.map(hoverMarkdown).join("\n\n---\n\n");
    const text = new vscode.MarkdownString(md);
    text.isTrusted = false; // no command links from scanned content
    text.supportHtml = false;
    return new vscode.Hover(text);
  }
}

/** The patch as edits, only if it matches the text in the editor right now. */
export function patchEdit(doc: vscode.TextDocument, f: BulwarkFinding): vscode.WorkspaceEdit | null {
  if (!f.suggestedPatch) return null;
  const lines = doc.getText().split(/\r?\n/);
  const edits = planEdits(lines, f.suggestedPatch, f.path);
  if (!edits) return null;
  const we = new vscode.WorkspaceEdit();
  const eol = doc.eol === vscode.EndOfLine.CRLF ? "\r\n" : "\n";
  for (const e of edits) {
    const last = e.startLine + e.oldCount - 1;
    we.replace(doc.uri, new vscode.Range(e.startLine, 0, last, doc.lineAt(last).text.length), e.newLines.join(eol));
  }
  return we;
}

export class BulwarkQuickFix implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];
  constructor(private store: FindingStore) {}

  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const d of ctx.diagnostics) {
      if (d.source !== "Bulwark") continue;
      const f = this.store.match(doc.uri.fsPath, d.range.start.line, d.message);
      if (!f) continue;
      const edit = patchEdit(doc, f);
      if (edit) {
        const who = f.patchSource === "llm" ? "AI-suggested" : "scanner-suggested";
        const a = new vscode.CodeAction(`Bulwark: apply ${who} fix (review first)`, vscode.CodeActionKind.QuickFix);
        a.edit = edit;
        a.diagnostics = [d];
        actions.push(a);
      }
      const url = f.cwe[0] ? cweUrl(f.cwe[0]) : null;
      if (url) {
        const a = new vscode.CodeAction(`Bulwark: open ${f.cwe[0]} reference`, vscode.CodeActionKind.QuickFix);
        a.command = { command: "bulwark.openReference", title: "Open reference", arguments: [url] };
        a.diagnostics = [d];
        actions.push(a);
      }
    }
    return actions;
  }
}

export { SELECTOR };
