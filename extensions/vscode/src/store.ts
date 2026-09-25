import type { BulwarkFinding } from "./types";
import type { DiagnosticSpec } from "./mapping";

/** The findings currently shown, indexed by file so hovers and quick fixes can find them. */
export class FindingStore {
  private byFile = new Map<string, DiagnosticSpec[]>();

  replace(grouped: Map<string, DiagnosticSpec[]>): void {
    this.byFile = new Map(grouped);
  }

  clear(): void {
    this.byFile.clear();
  }

  /** Findings in `file` whose line range (0-based, inclusive) covers `line`. */
  at(file: string, line: number): BulwarkFinding[] {
    return (this.byFile.get(file) ?? []).filter((s) => line >= s.startLine && line <= s.endLine).map((s) => s.finding);
  }

  /** The finding behind a diagnostic VS Code hands back (a copy, so match on range and message). */
  match(file: string, startLine: number, message: string): BulwarkFinding | undefined {
    return (this.byFile.get(file) ?? []).find((s) => s.startLine === startLine && s.message === message)?.finding;
  }
}
