import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { checkoutWorktree, mergeBase } from "../src/git";

const run = promisify(execFile);

async function git(cwd: string, ...args: string[]): Promise<string> {
  const { stdout } = await run("git", args, { cwd });
  return stdout.trim();
}

/** A tiny real repo: main has one commit, a feature branch forks off it with a second commit that
 * main never sees. Real git, not a fake -- `merge-base` and `worktree` have enough real subtlety
 * (detached HEADs, `.git/worktrees` bookkeeping) that faking them risks testing the fake. */
async function makeRepo(): Promise<string> {
  const dir = mkdtempSync(path.join(tmpdir(), "bulwark-gittest-"));
  await git(dir, "init", "--quiet", "--initial-branch=main");
  await git(dir, "config", "user.email", "t@example.com");
  await git(dir, "config", "user.name", "Test");
  writeFileSync(path.join(dir, "a.txt"), "1\n");
  await git(dir, "add", "a.txt");
  await git(dir, "commit", "--quiet", "-m", "base");
  await git(dir, "checkout", "--quiet", "-b", "feature");
  writeFileSync(path.join(dir, "a.txt"), "2\n");
  await git(dir, "commit", "--quiet", "-am", "feature work");
  return dir;
}

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

describe("mergeBase", () => {
  it("finds the commit main and the feature branch last shared", async () => {
    const repo = await makeRepo();
    const expected = await git(repo, "rev-parse", "main");
    expect(await mergeBase(repo, "main")).toBe(expected);
  });

  it("explains an unknown base branch instead of a raw git error", async () => {
    const repo = await makeRepo();
    await expect(mergeBase(repo, "does-not-exist")).rejects.toThrow(/does-not-exist/);
  });
});

describe("checkoutWorktree", () => {
  it("checks out the given commit's tree, not the current HEAD's", async () => {
    const repo = await makeRepo();
    const base = await git(repo, "rev-parse", "main");
    const wt = await checkoutWorktree(repo, base);
    cleanups.push(wt.dispose);
    expect(readFileSync(path.join(wt.path, "a.txt"), "utf8")).toBe("1\n"); // main's, not feature's
  });

  it("dispose removes the worktree directory and its git bookkeeping", async () => {
    const repo = await makeRepo();
    const base = await git(repo, "rev-parse", "main");
    const wt = await checkoutWorktree(repo, base);
    await wt.dispose();
    expect(existsSync(wt.path)).toBe(false);
    expect((await git(repo, "worktree", "list")).split("\n")).toHaveLength(1); // only the main one
  });
});
