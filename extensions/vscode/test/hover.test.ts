import { describe, expect, it } from "vitest";
import { cweUrl, escapeMd, hoverMarkdown } from "../src/hover";
import { atLeast } from "../src/mapping";
import type { BulwarkFinding } from "../src/types";

const f = (o: Partial<BulwarkFinding> = {}): BulwarkFinding => ({
  id: "1", title: "SQL injection", path: "a.py", startLine: 1, endLine: 1, severity: "HIGH", category: "sast", riskScore: 80,
  rule: "r", cwe: ["CWE-89"], owasp: ["A03:2021"], tools: ["semgrep", "bandit"], description: "User input reaches a query.",
  riskFactors: ["High severity", "Flagged by 2 scanners"], references: ["https://example.com/x"], remediationSummary: "Use parameters.",
  suggestedPatch: null, patchSource: "static", reachable: null, ...o,
});

describe("hoverMarkdown", () => {
  it("shows severity, risk, why, ids, fix, references and tools", () => {
    const md = hoverMarkdown(f());
    for (const s of ["SQL injection", "HIGH · risk 80/100", "High severity; Flagged by 2 scanners", "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)", "A03:2021", "Use parameters", "[reference 1](https://example.com/x)", "Reported by semgrep, bandit"])
      expect(md).toContain(s);
  });
  it("mentions a suggested fix and who made it", () => {
    expect(hoverMarkdown(f({ suggestedPatch: "p" }))).toContain("Scanner-suggested fix available");
    expect(hoverMarkdown(f({ suggestedPatch: "p", patchSource: "llm" }))).toContain("AI-suggested fix available");
    expect(hoverMarkdown(f())).not.toContain("fix available");
  });
  it("says when a package is not imported", () => {
    expect(hoverMarkdown(f({ reachable: false }))).toContain("Not imported by application code");
  });
  it("neutralises markdown and HTML from untrusted text", () => {
    const md = hoverMarkdown(f({ title: "[click](command:evil) <img src=x onerror=1> **b**", description: "`x` <script>", remediationSummary: "![p](https://t/x.png)" }));
    expect(md).not.toMatch(/(?<!\\)\[click\]\(/);
    expect(md).not.toMatch(/(?<!\\)</);
    expect(md).not.toMatch(/(?<!\\)!\[/);
    expect(md).not.toMatch(/(?<!\\)\*\*b/);
  });
  it("keeps a reference URL from breaking out of its link", () => {
    const md = hoverMarkdown(f({ references: ["https://e.com/a)[x](command:evil"] }));
    expect(md).not.toContain("(command:evil");
  });
  it("drops unparsable reference URLs", () => {
    expect(hoverMarkdown(f({ references: ["https://"] }))).not.toContain("reference 1");
  });
});

describe("helpers", () => {
  it("escapeMd escapes markdown syntax and keeps line breaks", () => {
    expect(escapeMd("a_b*c\nd")).toBe("a\\_b\\*c  \nd");
  });
  it("cweUrl only builds links from a strict CWE id", () => {
    expect(cweUrl("CWE-79")).toBe("https://cwe.mitre.org/data/definitions/79.html");
    for (const bad of ["CWE-", "CWE-1/../x", "cwe-79", "CWE-79?x", "javascript:1", "CWE-1234567"]) expect(cweUrl(bad)).toBeNull();
  });
});

describe("atLeast", () => {
  const all = (["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map((s) => f({ severity: s }));
  it("filters by threshold", () => {
    expect(atLeast(all, "MEDIUM").map((x) => x.severity)).toEqual(["MEDIUM", "HIGH", "CRITICAL"]);
    expect(atLeast(all, "CRITICAL")).toHaveLength(1);
  });
  it("keeps everything for INFO or an unknown value", () => {
    expect(atLeast(all, "INFO")).toHaveLength(5);
    expect(atLeast(all, "bogus")).toHaveLength(5);
  });
});
