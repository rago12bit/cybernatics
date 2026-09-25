import { describe, expect, it } from "vitest";
import { parseFinding, parseScanOutput } from "../src/parse";

const good = {
  id: "bandit:B602:a.py:3",
  title: "subprocess with shell=True",
  location: { path: "a.py", start_line: 3, end_line: 5 },
  taxonomy: { category: "sast", cwe: ["CWE-78"] },
  scoring: { normalized_severity: "HIGH", risk_score: 71 },
  evidence: { reported_by: ["bandit", "semgrep"], rule_ids: { bandit: ["B602"] } },
};

describe("parseFinding", () => {
  it("reads the fields the extension needs", () => {
    expect(parseFinding(good)).toEqual({
      id: "bandit:B602:a.py:3", title: "subprocess with shell=True", path: "a.py", startLine: 3, endLine: 5,
      severity: "HIGH", category: "sast", riskScore: 71, rule: "B602", cwe: ["CWE-78"], tools: ["bandit", "semgrep"],
    });
  });
  it.each([
    ["not an object", 5],
    ["null", null],
    ["no path", { ...good, location: { start_line: 1 } }],
    ["line 0", { ...good, location: { path: "a", start_line: 0 } }],
    ["bad severity", { ...good, scoring: { normalized_severity: "SEVERE" } }],
    ["string line", { ...good, location: { path: "a", start_line: "3" } }],
  ])("drops %s", (_n, raw) => expect(parseFinding(raw)).toBeNull());
  it("never lets end precede start", () => {
    expect(parseFinding({ ...good, location: { path: "a", start_line: 9, end_line: 2 } })?.endLine).toBe(9);
  });
  it("caps hostile string lengths and list sizes", () => {
    const f = parseFinding({ ...good, title: "x".repeat(10_000), taxonomy: { category: "sast", cwe: Array(100).fill("CWE-1") } });
    expect(f?.title.length).toBe(500);
    expect(f?.cwe.length).toBe(20);
  });
});

describe("parseScanOutput", () => {
  it("counts unreadable findings instead of failing", () => {
    const out = parseScanOutput(JSON.stringify({ findings: [good, { nope: 1 }], tool_status: { bandit: { status: "ok" } } }));
    expect(out.findings).toHaveLength(1);
    expect(out.skipped).toBe(1);
    expect(out.toolStatus).toEqual({ bandit: "ok" });
  });
  it("rejects non-JSON and shapes without findings", () => {
    expect(() => parseScanOutput("Traceback...")).toThrow(/valid JSON/);
    expect(() => parseScanOutput("{}")).toThrow(/no findings/);
  });
});
