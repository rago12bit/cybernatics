import { describe, expect, it } from "vitest";
import { agreementLabel, dedupSummary, defaultQuery, findingsQueryString, formatDuration, issueSummary, locationLabel, pageCount } from "../lib/format";
import { readFileSync } from "node:fs";
import { OWASP_2021, owaspLabel } from "../lib/owasp";
import { cveUrl, cweUrl, owaspUrl, safeHttpsUrl } from "../lib/safe";
import type { Finding, ScanView } from "../lib/types";

const scan = (over: Partial<ScanView> = {}): ScanView => ({
  id: "1", status: "completed", source_type: "git", source_label: "x", tools: [],
  created_at: "", started_at: null, finished_at: null, error: null,
  tool_status: {
    bandit: { status: "ok", findings: 1, exit_code: 1, duration_seconds: 1, error: null, raw_artifact: null },
    semgrep: { status: "ok", findings: 1, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
    trivy: { status: "skipped", findings: 0, exit_code: null, duration_seconds: null, error: null, raw_artifact: null },
  },
  severity_counts: {}, raw_findings: 10, unique_findings: 6, dedup_rate: 0.4, ...over,
});

const finding = (agreement: number): Finding => ({
  id: "f", fingerprint: "fp", title: "t", description: "d",
  location: { path: "a.py", start_line: 3, end_line: 5, snippet: "" },
  taxonomy: { category: "sast", cwe: [], owasp_top_10_2021: [], cve: [], aliases: [] },
  scoring: { native_severity: { bandit: "MEDIUM", semgrep: "ERROR" }, normalized_severity: "HIGH", cvss_v3_1: null, risk_score: null, confidence: 0.5 },
  evidence: { reported_by: [], agreement_count: agreement, rule_ids: {} },
  remediation: { summary: "", references: [], generated_by: "static" }, package: null, taint_path: [],
});

describe("safe links (untrusted scanner data must never become a dangerous href)", () => {
  it("only allows plain https URLs", () => {
    expect(safeHttpsUrl("https://example.com/a")).toBe("https://example.com/a");
    for (const bad of ["javascript:alert(1)", "http://example.com", "data:text/html,<script>", "//evil.com", "https://user:pw@evil.com", "ftp://x", "", "not a url"]) {
      expect(safeHttpsUrl(bad)).toBeNull();
    }
  });
  it("builds CWE/CVE/OWASP links only from well-formed ids", () => {
    expect(cweUrl("CWE-89")).toBe("https://cwe.mitre.org/data/definitions/89.html");
    expect(cveUrl("cve-2021-23337")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-23337");
    expect(owaspUrl("A03:2021")).toBe("https://top10.owasp.org/A03_2021-Injection/");
    for (const bad of ["CWE-89/../x", "CWE-", "javascript:CWE-1", "CWE-999999"]) expect(cweUrl(bad)).toBeNull();
    for (const bad of ["CVE-2021-1", "GHSA-xxxx", 'CVE-2021-23337"><script>']) expect(cveUrl(bad)).toBeNull();
    for (const bad of ["A11:2021", "A03:2017", "A03"]) expect(owaspUrl(bad)).toBeNull();
  });
});

describe("findings query", () => {
  it("omits empty filters and encodes values", () => {
    expect(findingsQueryString(defaultQuery())).toBe("sort=severity&limit=50&offset=0");
    const q = { ...defaultQuery(), severity: ["HIGH", "CRITICAL"] as Finding["scoring"]["normalized_severity"][], category: "sca", path: " src/a b&c ", page: 2, sort: "path" as const };
    const s = new URLSearchParams(findingsQueryString(q));
    expect(s.getAll("severity")).toEqual(["HIGH", "CRITICAL"]);
    expect(s.get("path")).toBe("src/a b&c");
    expect(s.get("offset")).toBe("100");
    expect(s.get("sort")).toBe("path");
  });
  it("pageCount never drops below 1", () => {
    expect([0, 1, 50, 51, 120].map(pageCount)).toEqual([1, 1, 1, 2, 3]);
  });
});

describe("labels", () => {
  it("agreement denominator counts only scanners that ran AND cover the finding's category", () => {
    const sc = scan({
      tool_status: {
        bandit: { status: "ok", findings: 1, exit_code: 1, duration_seconds: 1, error: null, raw_artifact: null },
        semgrep: { status: "ok", findings: 1, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
        trivy: { status: "ok", findings: 0, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
        gitleaks: { status: "ok", findings: 0, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
      },
    });
    // Trivy and Gitleaks ran but cannot find a SQL injection, so they are not counted against it.
    expect(agreementLabel(finding(2), sc)).toBe("Flagged by 2 of 2 code scanners");
    expect(agreementLabel(finding(1), sc)).toBe("Flagged by 1 of 2 code scanners");
    expect(agreementLabel(finding(1), null)).toBe("Flagged by 1 scanner");
    expect(agreementLabel(finding(3), sc)).toBe("Flagged by 3 scanners"); // never "3 of 2"
    const semgrepDown = scan({ tool_status: { ...sc.tool_status, semgrep: { ...sc.tool_status.semgrep!, status: "timeout" } } });
    expect(agreementLabel(finding(1), semgrepDown)).toBe("Flagged by 1 of 1 code scanners"); // a dead scanner is not a miss
  });
  it("dedup summary", () => {
    expect(dedupSummary(scan())).toContain("10 raw findings became 6");
    expect(dedupSummary(scan({ raw_findings: 0, unique_findings: 0, dedup_rate: 0 }))).toContain("No findings");
    expect(dedupSummary(scan({ raw_findings: 4, unique_findings: 4, dedup_rate: 0 }))).toContain("no duplicates");
  });
  it("issue summary is quiet unless something is new or came back (ADR-0012)", () => {
    expect(issueSummary(undefined)).toBeNull();
    expect(issueSummary({})).toBeNull();
    expect(issueSummary({ open: 40 })).toBeNull(); // steady state alone says nothing
    expect(issueSummary({ new: 3 })).toBe("3 new since the last scan of this project.");
    expect(issueSummary({ reintroduced: 1 })).toBe("1 reintroduced since the last scan of this project.");
    expect(issueSummary({ new: 3, reintroduced: 1, open: 40 })).toBe(
      "3 new, 1 reintroduced since the last scan of this project.",
    );
  });
  it("durations and locations", () => {
    expect([0.2, 5.4, 75, null].map(formatDuration)).toEqual(["<1s", "5s", "1m 15s", ""]);
    expect(locationLabel(finding(1))).toBe("a.py:3-5");
  });
});

import { isDefaultQuery, queryToSearch, rangeLabel, relativeTime, searchToQuery } from "../lib/format";
import { collectAll, exportFilename, exportPayload } from "../lib/export";

describe("filter state <-> URL", () => {
  it("round-trips a non-default query and omits defaults", () => {
    const q = { ...defaultQuery(), severity: ["HIGH", "CRITICAL"] as never, category: "sca", tool: "trivy", path: "src/a b", sort: "path" as const, page: 2 };
    const s = queryToSearch(q);
    expect(s).toBe("?sev=HIGH%2CCRITICAL&cat=sca&tool=trivy&q=src%2Fa+b&sort=path&p=3");
    expect(searchToQuery(s)).toEqual(q);
    expect(queryToSearch(defaultQuery())).toBe("");
    expect(isDefaultQuery(defaultQuery())).toBe(true);
    expect(isDefaultQuery({ ...defaultQuery(), tool: "trivy" })).toBe(false);
    expect(isDefaultQuery({ ...defaultQuery(), page: 3 })).toBe(true); // paging alone is not a "filter"
  });
  it("treats the URL as untrusted: unknown values are dropped", () => {
    const q = searchToQuery("?sev=HIGH,DROP%20TABLE,HIGH&cat=evil&tool=<script>&sort=hax&p=-5&q=" + "x".repeat(500));
    expect(q.severity).toEqual(["HIGH"]);
    expect(q.category).toBe("");
    expect(q.tool).toBe("");
    expect(q.sort).toBe("severity");
    expect(q.page).toBe(0);
    expect(q.path.length).toBe(200);
    expect(searchToQuery("?p=abc").page).toBe(0);
    expect(searchToQuery("?p=999999999").page).toBe(10_000);
  });
});

describe("labels", () => {
  it("range label", () => {
    expect(rangeLabel(291, 0, 50)).toBe("Showing 1-50 of 291");
    expect(rangeLabel(291, 5, 41)).toBe("Showing 251-291 of 291");
    expect(rangeLabel(0, 0, 0)).toBe("No results");
  });
  it("relative time", () => {
    const now = Date.parse("2026-09-25T12:00:00Z");
    const at = (s: number) => new Date(now - s * 1000).toISOString();
    expect([10, 120, 7200, 3 * 86400].map((s) => relativeTime(at(s), now))).toEqual(["just now", "2 min ago", "2 h ago", "3 d ago"]);
    expect(relativeTime("garbage", now)).toBe("");
    expect(relativeTime(at(-30), now)).toBe("just now"); // clock skew never shows the future
  });
});

describe("export", () => {
  const scan = { id: "s1", source_label: "https://github.com/OWASP/NodeGoat", status: "completed", raw_findings: 5, unique_findings: 3, dedup_rate: 0.4, tool_status: { trivy: { status: "ok" } } } as unknown as ScanView;
  it("pages through every result and stops at the total", async () => {
    const calls: number[] = [];
    const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ id: String(i) }) as never);
    const got = await collectAll(async (q, limit) => {
      calls.push(q.page);
      return { total: 1100, limit, offset: q.page * limit, items: mk(q.page < 2 ? 500 : 100) };
    }, defaultQuery());
    expect(got.length).toBe(1100);
    expect(calls).toEqual([0, 1, 2]);
  });
  it("is bounded and survives an empty page", async () => {
    expect((await collectAll(async (q, l) => ({ total: 99999, limit: l, offset: 0, items: [{ id: "x" } as never] }), defaultQuery(), 3)).length).toBe(3);
    expect(await collectAll(async (_q, l) => ({ total: 10, limit: l, offset: 0, items: [] }), defaultQuery())).toEqual([]);
  });
  it("payload is self-describing; filename is filesystem-safe", () => {
    const p = exportPayload(scan, [], { ...defaultQuery(), tool: "trivy" });
    expect(p.generated_by).toBe("Bulwark");
    expect(p.filters.tool).toBe("trivy");
    expect(p.scan.dedup_rate).toBe(0.4);
    expect(exportFilename(scan)).toBe("bulwark-github.com-OWASP-NodeGoat-findings.json");
    expect(exportFilename({ ...scan, source_label: "../../etc/passwd" })).not.toContain("/");
    expect(exportFilename({ ...scan, source_label: "???" })).toBe("bulwark-scan-findings.json");
  });
});

describe("owasp table", () => {
  it("names and ids match the backend table (single source of truth is core/taxonomy)", () => {
    const backend = JSON.parse(readFileSync(new URL("../../core/taxonomy/owasp_top10_2021.json", import.meta.url), "utf8")).categories;
    expect(Object.keys(OWASP_2021)).toEqual(Object.keys(backend));
    for (const [id, e] of Object.entries(OWASP_2021)) expect(e.name).toBe(backend[id].name);
  });
  it("labels known ids with their name and passes unknown ones through as text", () => {
    expect(owaspLabel("A03:2021")).toBe("OWASP A03 Injection");
    expect(owaspLabel("__proto__")).toBe("OWASP __proto__");
    expect(owaspUrl("__proto__")).toBeNull();
  });
});
