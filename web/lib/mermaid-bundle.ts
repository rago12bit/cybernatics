// Mermaid's self-contained browser build (it sets globalThis.mermaid), served to the threat-model
// diagram frame (app/diagram-frame). Read from node_modules, so it is always the version
// package-lock.json installed; next.config.mjs keeps the file in the standalone build.
import { readFileSync } from "node:fs";
import path from "node:path";

const DIR = path.join(process.cwd(), "node_modules", "mermaid");

export const MERMAID_VERSION: string = JSON.parse(readFileSync(path.join(DIR, "package.json"), "utf8")).version;

let bundle: Buffer | null = null;
export function mermaidBundle(): Buffer {
  bundle ??= readFileSync(path.join(DIR, "dist", "mermaid.min.js"));
  return bundle;
}
