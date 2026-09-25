import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { activate, toolList } from "../src/extension";
import { state } from "./vscode-stub";

const PATCH = "--- a/app.py\\n+++ b/app.py\\n@@ -3,1 +3,1 @@\\n-    subprocess.call(cmd, shell=True)\\n+    subprocess.call(cmd, shell=False)\\n";
const finding = (sev = "HIGH", extra = "") =>
  `{"title":"Shell true","description":"d","location":{"path":"app.py","start_line":3,"end_line":3},"taxonomy":{"category":"sast","cwe":["CWE-78"]},"scoring":{"normalized_severity":"${sev}","risk_score":75},"evidence":{"reported_by":["semgrep"]},"remediation":{"summary":"Use shell=False","references":["https://x.test/r"]${extra}}}`;

function cli(json: string): string {
  const p = path.join(mkdtempSync(path.join(tmpdir(), "provcli-")), "bulwark");
  writeFileSync(p, `#!/bin/sh\nfor a; do out="$a"; done\nprintf '%s' '${json}' > "$out"\n`);
  chmodSync(p, 0o755);
  return p;
}
const DOC = ["import subprocess", "def run(cmd):", "    subprocess.call(cmd, shell=True)", "    return 1"];
const fakeDoc = (lines: string[], fsPath = "/proj/app.py", eol = 1) => ({
  uri: { fsPath }, eol, getText: () => lines.join(eol === 2 ? "\r\n" : "\n"), lineAt: (n: number) => ({ text: lines[n]! }),
});
const P = (h: unknown) => h as { provideHover(d: unknown, p: unknown): { contents: { value: string; isTrusted: boolean; supportHtml: boolean } } | undefined; provideCodeActions(d: unknown, r: unknown, c: unknown): { title: string; edit?: { edits: { range: { sl: number; el: number; ec: number }; text: string }[] }; command?: { command: string; arguments: string[] } }[] };

async function scan(json: string, cfg: Record<string, unknown> = {}): Promise<void> {
  state.config = { cliPath: cli(json), ...cfg };
  await state.commands.get("bulwark.scanWorkspace")!();
}
const diag = () => state.diagnostics.get("/proj/app.py")![0]!;

beforeEach(() => {
  state.commands.clear(); state.diagnostics.clear(); state.messages.length = 0; state.opened.length = 0;
  state.folders = [{ uri: { fsPath: "/proj" } }]; state.trusted = true; state.config = {};
  activate({ subscriptions: [] } as never);
});

describe("hover", () => {
  it("shows detail on the finding's lines only, as untrusted markdown", async () => {
    await scan(`{"findings":[${finding()}]}`);
    const h = P(state.hover);
    const shown = h.provideHover(fakeDoc(DOC), { line: 2 });
    expect(shown?.contents.value).toContain("Shell true");
    expect(shown?.contents.isTrusted).toBe(false);
    expect(shown?.contents.supportHtml).toBe(false);
    expect(h.provideHover(fakeDoc(DOC), { line: 0 })).toBeUndefined();
    expect(h.provideHover(fakeDoc(DOC, "/proj/other.py"), { line: 2 })).toBeUndefined();
  });
});

describe("quick fix", () => {
  const ctx = () => ({ diagnostics: [{ ...diag(), source: "Bulwark" }] });
  it("offers the patch and a CWE link, and the edit replaces exactly the matched line", async () => {
    await scan(`{"findings":[${finding("HIGH", `,"suggested_patch":"${PATCH}","generated_by":"static"`)}]}`);
    const acts = P(state.actions).provideCodeActions(fakeDoc(DOC), {}, ctx());
    expect(acts.map((a) => a.title)).toEqual(["Bulwark: apply scanner-suggested fix (review first)", "Bulwark: open CWE-78 reference"]);
    const e = acts[0]!.edit!.edits[0]!;
    expect(e.range).toMatchObject({ sl: 2, el: 2, ec: DOC[2]!.length });
    expect(e.text).toBe("    subprocess.call(cmd, shell=False)");
    expect(acts[1]!.command).toMatchObject({ command: "bulwark.openReference", arguments: ["https://cwe.mitre.org/data/definitions/78.html"] });
  });
  it("does not offer the patch once the line has changed", async () => {
    await scan(`{"findings":[${finding("HIGH", `,"suggested_patch":"${PATCH}"`)}]}`);
    const changed = [...DOC]; changed[2] = "    subprocess.run(cmd)";
    const acts = P(state.actions).provideCodeActions(fakeDoc(changed), {}, ctx());
    expect(acts.map((a) => a.title)).toEqual(["Bulwark: open CWE-78 reference"]);
  });
  it("uses the document's line endings", async () => {
    await scan(`{"findings":[${finding("HIGH", `,"suggested_patch":"${PATCH}"`)}]}`);
    const acts = P(state.actions).provideCodeActions(fakeDoc(DOC, "/proj/app.py", 2), {}, ctx());
    expect(acts[0]!.edit).toBeDefined();
  });
  it("ignores diagnostics that are not Bulwark's", async () => {
    await scan(`{"findings":[${finding()}]}`);
    expect(P(state.actions).provideCodeActions(fakeDoc(DOC), {}, { diagnostics: [{ ...diag(), source: "eslint" }] })).toEqual([]);
  });
  it("opens only CWE links, whatever the command is given", async () => {
    await state.commands.get("bulwark.openReference")!("https://evil.test/x");
    await state.commands.get("bulwark.openReference")!("file:///etc/passwd");
    await state.commands.get("bulwark.openReference")!(42);
    expect(state.opened).toEqual([]);
    await state.commands.get("bulwark.openReference")!("https://cwe.mitre.org/data/definitions/79.html");
    expect(state.opened).toEqual(["https://cwe.mitre.org/data/definitions/79.html"]);
  });
  it("forgets findings when cleared", async () => {
    await scan(`{"findings":[${finding()}]}`);
    const before = diag();
    await state.commands.get("bulwark.clearFindings")!();
    expect(P(state.hover).provideHover(fakeDoc(DOC), { line: 2 })).toBeUndefined();
    expect(P(state.actions).provideCodeActions(fakeDoc(DOC), {}, { diagnostics: [{ ...before, source: "Bulwark" }] })).toEqual([]);
  });
});

describe("settings", () => {
  it("hides findings below the severity threshold and says so", async () => {
    await scan(`{"findings":[${finding("LOW")},${finding("HIGH")}]}`, { minimumSeverity: "HIGH" });
    expect(state.diagnostics.get("/proj/app.py")).toHaveLength(1);
    expect(state.messages.at(-1)!.text).toMatch(/1 below the severity threshold hidden/);
  });
  it("accepts the tool list as an array or a legacy string, defaulting to all", () => {
    expect(toolList(["bandit", "trivy"])).toBe("bandit,trivy");
    expect(toolList("gitleaks")).toBe("gitleaks");
    for (const v of [[], "", undefined]) expect(toolList(v as never)).toBe("bandit,semgrep,gitleaks,trivy,osv-scanner");
  });
});
