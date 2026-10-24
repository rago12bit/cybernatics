import { globSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { formatDate, formatDateTime } from "../lib/format";

describe("one date format across the app", () => {
  const iso = "2026-10-11T18:52:21Z";

  it("writes the month as a word and never shows seconds", () => {
    const d = new Date(iso);
    expect(formatDate(iso)).toBe(d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }));
    expect(formatDateTime(iso)).toBe(d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit" }));
    expect(formatDateTime(iso)).not.toContain(":21"); // the seconds
    expect(formatDate(iso)).not.toMatch(/^\d+\/\d+\/\d+$/); // not 10/11/2026, which reads two ways
  });

  it("shows a dash, not 'Invalid Date', for a broken timestamp", () => {
    expect(formatDate("not a date")).toBe("—");
    expect(formatDateTime("")).toBe("—");
  });

  it("is the only way screens format a timestamp", () => {
    // A UI audit found about 56 ad-hoc toLocaleString()/toLocaleDateString() calls in 33 files, each
    // free to drift; calendar grids pass their own options and are allowed.
    const root = join(__dirname, "..");
    const offenders = globSync("components/**/*.tsx", { cwd: root })
      .filter((f) => /new Date\([^()]*\)\.toLocale(Date)?String\(\)/.test(readFileSync(join(root, f), "utf8")));
    expect(offenders).toEqual([]);
  });
});
