import { execFile } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";
import { activate } from "../src/extension";
import { state } from "./vscode-stub";

const run = promisify(execFile);
const ctx = { subscriptions: [] as unknown[] };

async function git(cwd: string, ...args: string[]): Promise<void> {
  await run("git", args, { cwd });
}

/** A real repo (see test/git.test.ts's docstring for why): main has one finding, a feature branch
 * adds a second, unrelated one. "Scan (new since base branch)" should report only the addition. */
async function makeRepo(): Promise<string> {
  const dir = mkdtempSync(path.join(tmpdir(), "bulwark-pr-repo-"));
  await git(dir, "init", "--quiet", "--initial-branch=main");
  await git(dir, "config", "user.email", "t@example.com");
  await git(dir, "config", "user.name", "Test");
  writeFileSync(path.join(dir, "a.py"), "1\n");
  await git(dir, "add", "a.py");
  await git(dir, "commit", "--quiet", "-m", "base");
  await git(dir, "checkout", "--quiet", "-b", "feature");
  return dir;
}

/** A fake `bulwark` that reports one finding always present, plus a second one only when scanning
 * `dir` itself (HEAD) rather than a worktree checkout (the base branch) -- worktree paths always
 * contain "/wt", which this repo layout's own workspace path never does. */
function cliDistinguishingHeadFromBase(dir: string): string {
  const p = path.join(mkdtempSync(path.join(tmpdir(), "extcli-pr-")), "bulwark");
  const always = `{"id":"f:always","fingerprint":"fp-always","title":"Always present","location":{"path":"a.py","start_line":1,"end_line":1},"taxonomy":{"category":"sast"},"scoring":{"normalized_severity":"MEDIUM"},"evidence":{"reported_by":["bandit"]}}`;
  const onlyOnHead = `{"id":"f:new","fingerprint":"fp-new","title":"Introduced by this branch","location":{"path":"a.py","start_line":2,"end_line":2},"taxonomy":{"category":"sast"},"scoring":{"normalized_severity":"HIGH"},"evidence":{"reported_by":["bandit"]}}`;
  writeFileSync(
    p,
    [
      "#!/bin/sh",
      'root="$2"',
      'for a; do out="$a"; done',
      `case "$root" in`,
      `  */wt) printf '{"findings":[${always}],"tool_status":{"bandit":{"status":"ok"}}}' > "$out" ;;`,
      `  *) printf '{"findings":[${always},${onlyOnHead}],"tool_status":{"bandit":{"status":"ok"}}}' > "$out" ;;`,
      "esac",
    ].join("\n"),
  );
  chmodSync(p, 0o755);
  return p;
}

beforeEach(() => {
  state.commands.clear();
  state.diagnostics.clear();
  state.messages.length = 0;
  state.trusted = true;
  state.config = {};
  activate(ctx as never);
});

describe("bulwark.scanChangedSinceBase", () => {
  it("marks only the finding introduced since the base branch as new, keeping the rest visible", async () => {
    const repo = await makeRepo();
    state.folders = [{ uri: { fsPath: repo } }];
    state.config = { cliPath: cliDistinguishingHeadFromBase(repo), baseBranch: "main" };
    await state.commands.get("bulwark.scanChangedSinceBase")!();
    const diags = state.diagnostics.get(path.join(repo, "a.py"))!;
    expect(diags).toHaveLength(2);
    const byMessage = Object.fromEntries(diags.map((d) => [d.message, d]));
    expect(Object.keys(byMessage).some((m) => m.startsWith("[new] Introduced by this branch"))).toBe(true);
    expect(Object.keys(byMessage).some((m) => m.startsWith("Always present"))).toBe(true);
    expect(state.messages.at(-1)!.text).toMatch(/2 finding\(s\), 1 new/);
  });

  it("reports an unknown base branch as a readable error", async () => {
    const repo = await makeRepo();
    state.folders = [{ uri: { fsPath: repo } }];
    state.config = { cliPath: cliDistinguishingHeadFromBase(repo), baseBranch: "no-such-branch" };
    await state.commands.get("bulwark.scanChangedSinceBase")!();
    expect(state.messages.at(-1)).toMatchObject({ kind: "error" });
    expect(state.messages.at(-1)!.text).toMatch(/no-such-branch/);
  });
});
