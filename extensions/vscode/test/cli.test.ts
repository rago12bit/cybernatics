import { chmodSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { buildArgs, runScan } from "../src/cli";

function fakeCli(body: string): string {
  const p = path.join(mkdtempSync(path.join(tmpdir(), "fakecli-")), "bulwark");
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return p;
}
const base = { root: "/tmp", tools: "bandit,semgrep", timeoutMs: 10_000 };
// The fake honours the real contract: the last argument is the --output file.
const writeJson = (json: string) => `for a; do out="$a"; done\nprintf '%s' '${json}' > "$out"`;

describe("buildArgs", () => {
  it("builds a fixed argument vector", () => {
    expect(buildArgs("/w", "bandit,trivy", "/o.json")).toEqual(["scan", "/w", "--tools", "bandit,trivy", "--format", "json", "--output", "/o.json"]);
  });
  it.each(["bandit; rm -rf /", "", "a b", "--format", "bandit,,x", "$(x)"])("rejects tool list %j", (t) => {
    expect(() => buildArgs("/w", t, "/o")).toThrow(/Invalid scanner list/);
  });
});

describe("runScan", () => {
  it("runs the CLI and parses its output file", async () => {
    const cli = fakeCli(writeJson('{"findings":[{"location":{"path":"a.py","start_line":1},"scoring":{"normalized_severity":"LOW"}}],"tool_status":{"bandit":{"status":"ok"}}}'));
    const out = await runScan({ ...base, cliPath: cli });
    expect(out.findings).toHaveLength(1);
    expect(out.toolStatus.bandit).toBe("ok");
  });
  it("passes the folder as one argument even with spaces and shell characters", async () => {
    const cli = fakeCli(`echo "$2" > /dev/stderr\n${writeJson('{"findings":[]}')}`);
    const lines: string[] = [];
    await runScan({ ...base, cliPath: cli, root: "/tmp/a b; touch /tmp/pwned$(id)", log: (l) => lines.push(l) });
    expect(lines.join("\n")).toContain("/tmp/a b; touch /tmp/pwned$(id)");
    expect(existsSync("/tmp/pwned")).toBe(false);
  });
  it("explains a missing CLI", async () => {
    await expect(runScan({ ...base, cliPath: "/nonexistent/bulwark" })).rejects.toThrow(/set bulwark.cliPath/);
  });
  it("reports the exit code and stderr on failure", async () => {
    await expect(runScan({ ...base, cliPath: fakeCli("echo boom >&2; exit 2") })).rejects.toThrow(/could not read the source: boom/);
    await expect(runScan({ ...base, cliPath: fakeCli("exit 1") })).rejects.toThrow(/code 1/);
  });
  it("rejects invalid JSON output", async () => {
    await expect(runScan({ ...base, cliPath: fakeCli(writeJson("not json")) })).rejects.toThrow(/valid JSON/);
  });
  it("times out", async () => {
    await expect(runScan({ ...base, cliPath: fakeCli("sleep 5"), timeoutMs: 300 })).rejects.toThrow(/timed out/);
  });
  it("can be cancelled", async () => {
    const ctrl = new AbortController();
    const p = runScan({ ...base, cliPath: fakeCli("sleep 5"), signal: ctrl.signal });
    setTimeout(() => ctrl.abort(), 100);
    await expect(p).rejects.toThrow(/cancelled/);
  });
});
