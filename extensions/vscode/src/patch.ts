/**
 * Apply a one-file unified diff to text that is open in the editor, but only if it really matches.
 *
 * A suggested patch comes from a scanner or a model and the file may have been edited since the scan, so
 * nothing is applied unless every hunk's context and removed lines equal the current lines exactly. A hunk
 * whose stated line is off is searched for within a small window, and refused if the match is ambiguous.
 */
export interface LineEdit {
  startLine: number; // 0-based first line replaced
  oldCount: number;
  newLines: string[];
}

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;
const WINDOW = 10;

interface Hunk {
  oldStart: number;
  oldLines: string[];
  newLines: string[];
}

export function parseHunks(patch: string, expectedPath: string): Hunk[] | null {
  const lines = patch.replace(/\r\n/g, "\n").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  const a = lines[0]?.match(/^--- (?:a\/)?(.+)$/)?.[1];
  const b = lines[1]?.match(/^\+\+\+ (?:b\/)?(.+)$/)?.[1];
  if (!a || !b || a !== expectedPath || b !== expectedPath) return null; // one file, and the finding's own
  const hunks: Hunk[] = [];
  let cur: Hunk | null = null;
  for (const ln of lines.slice(2)) {
    const m = HUNK.exec(ln);
    if (m) {
      cur = { oldStart: Number(m[1]), oldLines: [], newLines: [] };
      hunks.push(cur);
    } else if (!cur || ln.startsWith("\\")) {
      if (!cur) return null;
    } else if (ln.startsWith(" ")) {
      cur.oldLines.push(ln.slice(1));
      cur.newLines.push(ln.slice(1));
    } else if (ln.startsWith("-")) cur.oldLines.push(ln.slice(1));
    else if (ln.startsWith("+")) cur.newLines.push(ln.slice(1));
    else if (ln === "") {
      cur.oldLines.push("");
      cur.newLines.push("");
    } else return null;
  }
  return hunks.length > 0 && hunks.length <= 20 ? hunks : null;
}

function matchesAt(doc: string[], at: number, block: string[]): boolean {
  if (at < 0 || at + block.length > doc.length) return false;
  return block.every((l, i) => doc[at + i] === l);
}

/** Edits that apply `patch` to `docLines`, or null if it does not match the current text. */
export function planEdits(docLines: string[], patch: string, expectedPath: string): LineEdit[] | null {
  const hunks = parseHunks(patch, expectedPath);
  if (!hunks) return null;
  const edits: LineEdit[] = [];
  let lastEnd = -1;
  for (const h of hunks) {
    if (h.oldLines.length === 0 || h.oldLines.join("\n") === h.newLines.join("\n")) return null;
    const stated = Math.max(h.oldStart - 1, 0);
    let at = matchesAt(docLines, stated, h.oldLines) ? stated : -1;
    if (at < 0) {
      const found: number[] = [];
      for (let d = -WINDOW; d <= WINDOW; d++) if (matchesAt(docLines, stated + d, h.oldLines)) found.push(stated + d);
      if (found.length !== 1) return null; // not there, or ambiguous
      at = found[0]!;
    }
    if (at < lastEnd) return null; // overlapping hunks
    edits.push({ startLine: at, oldCount: h.oldLines.length, newLines: h.newLines });
    lastEnd = at + h.oldLines.length;
  }
  return edits;
}
