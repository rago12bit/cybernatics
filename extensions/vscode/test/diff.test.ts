import { describe, expect, it } from "vitest";
import { newSince } from "../src/diff";
import type { BulwarkFinding } from "../src/types";

function f(id: string, fingerprint = ""): BulwarkFinding {
  return {
    id,
    fingerprint,
    title: "t",
    path: "a.py",
    startLine: 1,
    endLine: 1,
    severity: "HIGH",
    category: "sast",
    riskScore: null,
    rule: "",
    cwe: [],
    owasp: [],
    tools: [],
    description: "",
    riskFactors: [],
    references: [],
    remediationSummary: "",
    suggestedPatch: null,
    patchSource: "static",
    reachable: null,
  };
}

describe("newSince", () => {
  it("is empty when every head finding matches a base one by fingerprint", () => {
    const head = [f("a:1", "fp1"), f("a:2", "fp2")];
    const base = [f("b:9", "fp2"), f("b:8", "fp1")]; // different ids, same fingerprints
    expect(newSince(head, base)).toEqual(new Set());
  });

  it("reports a head finding whose fingerprint matches nothing in base", () => {
    const head = [f("a:1", "fp1"), f("a:2", "fp-new")];
    const base = [f("b:9", "fp1")];
    expect(newSince(head, base)).toEqual(new Set(["a:2"]));
  });

  it("falls back to id when a finding has no fingerprint", () => {
    const head = [f("same-id", ""), f("only-in-head", "")];
    const base = [f("same-id", "")];
    expect(newSince(head, base)).toEqual(new Set(["only-in-head"]));
  });

  it("an empty base makes every head finding new", () => {
    const head = [f("a:1", "fp1"), f("a:2", "fp2")];
    expect(newSince(head, [])).toEqual(new Set(["a:1", "a:2"]));
  });

  it("an empty head is empty, whatever base has", () => {
    expect(newSince([], [f("b:1", "fp1")])).toEqual(new Set());
  });
});
