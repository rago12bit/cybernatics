import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { caretContext, formatQuery, parse, QueryError, toDict, withClause } from "../lib/issue-query";

// The same cases core/search/language.py must pass (tests/unit/test_issue_search.py): the browser's
// parser and the API's read every query identically, errors at the same characters.
type Case = { q: string; filters?: Record<string, unknown>; query?: string; error?: { start: number; end: number; contains: string } };
const { cases } = JSON.parse(readFileSync(new URL("../../tests/fixtures/issue_query_cases.json", import.meta.url), "utf8")) as { cases: Case[] };

describe("the shared query cases", () => {
  it.each(cases.map((c) => [c.q || "(empty)", c] as const))("%s", (_name, c) => {
    if (c.error) {
      let caught: unknown;
      try {
        parse(c.q);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(QueryError);
      const err = caught as QueryError;
      expect([err.start, err.end]).toEqual([c.error.start, c.error.end]);
      expect(err.message).toContain(c.error.contains);
      return;
    }
    const q = parse(c.q);
    expect(toDict(q)).toEqual(c.filters);
    expect(formatQuery(q)).toBe(c.query);
    expect(toDict(parse(formatQuery(q)))).toEqual(toDict(q));
  });
});

describe("what the panel and the query bar need", () => {
  it("replacing one key's values leaves the rest of the query as it was", () => {
    const q = parse('severity:high "sql injection" -status:accepted');
    const next = withClause(q, "severity", { include: ["critical", "high"] });
    expect(formatQuery(next)).toBe('-status:accepted severity:critical,high "sql injection"');
    expect(formatQuery(withClause(next, "severity", { include: [] }))).toBe('-status:accepted "sql injection"');
    expect(formatQuery(q)).toBe('-status:accepted severity:high "sql injection"'); // not mutated
  });

  it("knows whether the caret is in a key or a value, and which", () => {
    expect(caretContext("prio", 4)).toEqual({ kind: "key", prefix: "prio", start: 0 });
    expect(caretContext("severity:high -sta", 18)).toEqual({ kind: "key", prefix: "sta", start: 15 });
    expect(caretContext("sev:crit", 8)).toEqual({ kind: "value", key: "severity", prefix: "crit", start: 4 });
    expect(caretContext("project:acme/a,pay", 18)).toEqual({ kind: "value", key: "project", prefix: "pay", start: 15 });
    expect(caretContext('tag:"q4', 7)).toEqual({ kind: "value", key: "tag", prefix: "q4", start: 4 });
  });
});
