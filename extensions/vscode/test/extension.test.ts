import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { activate } from "../src/extension";
import { state } from "./vscode-stub";

const ctx = { subscriptions: [] as unknown[] };

function cli(json: string): string {
  const p = path.join(mkdtempSync(path.join(tmpdir(), "extcli-")), "bulwark");
  writeFileSync(p, `#!/bin/sh\nfor a; do out="$a"; done\nprintf '%s' '${json}' > "$out"\n`);
  chmodSync(p, 0o755);
  return p;
}
const finding = (p: string, sev: string, line = 3) =>
  `{"title":"Bad thing","location":{"path":"${p}","start_line":${line},"end_line":${line + 1}},"taxonomy":{"category":"sast","cwe":["CWE-89"]},"scoring":{"normalized_severity":"${sev}","risk_score":80},"evidence":{"reported_by":["semgrep"]}}`;

beforeEach(() => {
  state.commands.clear(); state.diagnostics.clear(); state.messages.length = 0;
  state.folders = [{ uri: { fsPath: "/proj" } }]; state.trusted = true; state.config = {};
  activate(ctx as never);
});

describe("extension", () => {
  it("registers its commands", () => {
    expect([...state.commands.keys()].sort()).toEqual(["bulwark.clearFindings", "bulwark.openReference", "bulwark.scanWorkspace", "bulwark.showOutput"]);
  });

  it("turns findings into diagnostics with source, code, severity and range", async () => {
    state.config = { cliPath: cli(`{"findings":[${finding("app/db.py", "HIGH")},${finding("../../etc/x", "LOW")}],"tool_status":{"semgrep":{"status":"ok"}}}`) };
    await state.commands.get("bulwark.scanWorkspace")!();
    const d = state.diagnostics.get("/proj/app/db.py")!;
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ message: "Bad thing (risk 80) [semgrep]", severity: 0, source: "Bulwark", code: "CWE-89" });
    expect(d[0]!.range).toMatchObject({ sl: 2, el: 3 });
    expect(state.diagnostics.size).toBe(1); // the path-escaping finding was not opened
    expect(state.messages.at(-1)!.text).toMatch(/1 finding.*outside the folder/);
  });

  it("replaces previous results on a rescan and clears on request", async () => {
    state.config = { cliPath: cli(`{"findings":[${finding("a.py", "MEDIUM")}]}`) };
    await state.commands.get("bulwark.scanWorkspace")!();
    state.config = { cliPath: cli(`{"findings":[${finding("b.py", "MEDIUM")}]}`) };
    await state.commands.get("bulwark.scanWorkspace")!();
    expect([...state.diagnostics.keys()]).toEqual(["/proj/b.py"]);
    await state.commands.get("bulwark.clearFindings")!();
    expect(state.diagnostics.size).toBe(0);
  });

  it("refuses to run in an untrusted workspace or without a folder", async () => {
    state.trusted = false;
    await state.commands.get("bulwark.scanWorkspace")!();
    expect(state.messages.at(-1)!.text).toMatch(/untrusted/);
    state.trusted = true; state.folders = [];
    await state.commands.get("bulwark.scanWorkspace")!();
    expect(state.messages.at(-1)!.text).toMatch(/Open a folder/);
  });

  it("shows a readable error when the CLI is missing and keeps old results", async () => {
    state.config = { cliPath: cli(`{"findings":[${finding("a.py", "LOW")}]}`) };
    await state.commands.get("bulwark.scanWorkspace")!();
    state.config = { cliPath: "/nonexistent/bulwark" };
    await state.commands.get("bulwark.scanWorkspace")!();
    expect(state.messages.at(-1)).toMatchObject({ kind: "error" });
    expect(state.diagnostics.size).toBe(1);
  });
});
