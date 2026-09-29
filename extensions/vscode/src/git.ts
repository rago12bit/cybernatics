import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

function git(args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("git", args, { cwd, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr.trim() || err.message));
      resolve(stdout.trim());
    });
  });
}

/** The commit `base` and the current `HEAD` last shared -- what "new since the base branch" (plan
 * §36) compares against, not `base`'s current tip: a base branch that's moved on since this
 * change forked must not make every one of *its* new commits look like part of this diff. */
export async function mergeBase(root: string, base: string): Promise<string> {
  try {
    return await git(["merge-base", "HEAD", base], root);
  } catch {
    throw new Error(`Could not find a common ancestor with "${base}". Is it a real branch, fetched locally?`);
  }
}

/** A throwaway checkout of `commit`, for a second `bulwark scan` to compare HEAD against. Always
 * clean up with the returned `dispose()`, even on failure -- `git worktree` otherwise leaves the
 * repository's `.git/worktrees` bookkeeping behind. */
export async function checkoutWorktree(
  root: string,
  commit: string,
): Promise<{ path: string; dispose: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(tmpdir(), "bulwark-base-"));
  const wt = path.join(dir, "wt");
  try {
    await git(["worktree", "add", "--quiet", "--detach", wt, commit], root);
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw err;
  }
  return {
    path: wt,
    dispose: async () => {
      await git(["worktree", "remove", "--force", wt], root).catch(() => undefined);
      await rm(dir, { recursive: true, force: true });
    },
  };
}
