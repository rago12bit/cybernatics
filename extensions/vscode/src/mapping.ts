import * as path from "node:path";
import type { BulwarkFinding, Severity } from "./types";

/** Plain numbers matching vscode.DiagnosticSeverity, so this file needs no `vscode` import. */
export const SEVERITY_LEVEL: Record<Severity, 0 | 1 | 2 | 3> = {
  CRITICAL: 0, // Error
  HIGH: 0,
  MEDIUM: 1, // Warning
  LOW: 2, // Information
  INFO: 3, // Hint
};

const ORDER: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Findings at or above `min`. An unknown threshold keeps everything rather than hiding results. */
export function atLeast(findings: BulwarkFinding[], min: string): BulwarkFinding[] {
  const floor = ORDER.indexOf(min as Severity);
  return floor <= 0 ? findings : findings.filter((f) => ORDER.indexOf(f.severity) >= floor);
}

export interface DiagnosticSpec {
  file: string; // absolute path
  startLine: number; // 0-based
  endLine: number; // 0-based
  message: string;
  level: 0 | 1 | 2 | 3;
  code: string;
  finding: BulwarkFinding;
}

/**
 * Resolve a scanner-reported path under the scanned root. Paths come from scanned (untrusted) content,
 * so anything absolute or escaping the root is refused rather than opened.
 */
export function resolveInside(root: string, rel: string): string | null {
  if (!rel || rel.includes("\0") || path.isAbsolute(rel) || /^[a-zA-Z]:/.test(rel)) return null;
  const abs = path.resolve(root, rel);
  const back = path.relative(root, abs);
  return back && !back.startsWith("..") && !path.isAbsolute(back) ? abs : null;
}

export function message(f: BulwarkFinding): string {
  const tag = f.riskScore === null ? "" : ` (risk ${f.riskScore})`;
  const by = f.tools.length ? ` [${f.tools.join(", ")}]` : "";
  return `${f.title}${tag}${by}`;
}

export function toSpecs(root: string, findings: BulwarkFinding[]): { specs: DiagnosticSpec[]; refused: number } {
  const specs: DiagnosticSpec[] = [];
  let refused = 0;
  for (const f of findings) {
    const file = resolveInside(root, f.path);
    if (!file) {
      refused++;
      continue;
    }
    specs.push({
      file,
      startLine: f.startLine - 1,
      endLine: f.endLine - 1,
      message: message(f),
      level: SEVERITY_LEVEL[f.severity],
      code: f.cwe[0] ?? f.rule,
      finding: f,
    });
  }
  return { specs, refused };
}

export function groupByFile(specs: DiagnosticSpec[]): Map<string, DiagnosticSpec[]> {
  const out = new Map<string, DiagnosticSpec[]>();
  for (const s of specs) out.set(s.file, [...(out.get(s.file) ?? []), s]);
  return out;
}
