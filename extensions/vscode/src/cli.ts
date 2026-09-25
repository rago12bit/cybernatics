import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { parseScanOutput } from "./parse";
import type { ScanOutput } from "./types";

export interface RunOptions {
  cliPath: string;
  root: string;
  tools: string;
  timeoutMs: number;
  signal?: AbortSignal;
  log?: (line: string) => void;
}

const TOOL_LIST = /^[a-z][a-z0-9-]*(,[a-z][a-z0-9-]*)*$/;

export function buildArgs(root: string, tools: string, outFile: string): string[] {
  if (!TOOL_LIST.test(tools)) throw new Error(`Invalid scanner list: ${JSON.stringify(tools.slice(0, 80))}`);
  return ["scan", root, "--tools", tools, "--format", "json", "--output", outFile];
}

/** Runs `bulwark scan` without a shell (arguments are never interpreted) and returns parsed findings. */
export async function runScan(opts: RunOptions): Promise<ScanOutput> {
  const dir = await mkdtemp(path.join(tmpdir(), "bulwark-vscode-"));
  const outFile = path.join(dir, "scan.json");
  try {
    const args = buildArgs(opts.root, opts.tools, outFile);
    opts.log?.(`$ ${opts.cliPath} ${args.join(" ")}`);
    await new Promise<void>((resolve, reject) => {
      const child = execFile(
        opts.cliPath,
        args,
        { timeout: opts.timeoutMs, signal: opts.signal, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
        (err, _stdout, stderr) => {
          if (stderr) opts.log?.(stderr.trim());
          if (!err) return resolve();
          const e = err as Error & { killed?: boolean; code?: string | number };
          if (e.name === "AbortError") return reject(new Error("Scan cancelled."));
          if (e.code === "ENOENT")
            return reject(new Error(`Could not run "${opts.cliPath}". Install Bulwark or set bulwark.cliPath.`));
          if (e.killed) return reject(new Error(`Scan timed out after ${Math.round(opts.timeoutMs / 1000)} s.`));
          if (e.code === 2) return reject(new Error(`Bulwark could not read the source: ${stderr.trim() || "see output"}`));
          reject(new Error(`Bulwark exited with code ${String(e.code)}. See the Bulwark output for details.`));
        },
      );
      child.on("error", () => undefined); // reported through the callback
    });
    return parseScanOutput(await readFile(outFile, "utf8"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
