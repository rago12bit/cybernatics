import { describe, expect, it } from "vitest";
import { groupByFile, resolveInside, SEVERITY_LEVEL, toSpecs } from "../src/mapping";
import type { BulwarkFinding } from "../src/types";

const f = (over: Partial<BulwarkFinding> = {}): BulwarkFinding => ({
  id: "1", title: "T", path: "src/a.py", startLine: 3, endLine: 4, severity: "HIGH", category: "sast",
  riskScore: 70, rule: "B1", cwe: [], tools: ["bandit"], ...over,
});

describe("severity", () => {
  it("maps to VS Code levels: critical/high error, medium warning, low info, info hint", () => {
    expect(SEVERITY_LEVEL).toEqual({ CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 });
  });
});

describe("resolveInside", () => {
  it("accepts paths within the root", () => {
    expect(resolveInside("/w", "src/a.py")).toBe("/w/src/a.py");
    expect(resolveInside("/w", "./a.py")).toBe("/w/a.py");
  });
  it.each(["../etc/passwd", "a/../../x", "/etc/passwd", "C:\\x", "C:/x", "", "a\0b", "."])("refuses %j", (p) => {
    expect(resolveInside("/w", p)).toBeNull();
  });
});

describe("toSpecs", () => {
  it("converts to 0-based lines, prefers the CWE as code, and includes risk and tools", () => {
    const { specs } = toSpecs("/w", [f({ cwe: ["CWE-78"] })]);
    expect(specs[0]).toEqual({ file: "/w/src/a.py", startLine: 2, endLine: 3, message: "T (risk 70) [bandit]", level: 0, code: "CWE-78" });
  });
  it("falls back to the rule id and omits missing risk", () => {
    const { specs } = toSpecs("/w", [f({ riskScore: null, tools: [] })]);
    expect(specs[0]?.code).toBe("B1");
    expect(specs[0]?.message).toBe("T");
  });
  it("refuses findings that point outside the folder and counts them", () => {
    const r = toSpecs("/w", [f({ path: "../../etc/shadow" }), f()]);
    expect(r.refused).toBe(1);
    expect(r.specs).toHaveLength(1);
  });
  it("groups by file", () => {
    const g = groupByFile(toSpecs("/w", [f(), f({ startLine: 9, endLine: 9 }), f({ path: "b.py" })]).specs);
    expect(g.get("/w/src/a.py")).toHaveLength(2);
    expect(g.size).toBe(2);
  });
});
